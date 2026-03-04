/*
MIT License

Copyright (c) 2024 Tobias Staack

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define MBEDTLS_STATUS( x ) \
    set_last_status( x )

#define CHUNK_SIZE 8192

#include <websocket/core/byte_stream.h>
#include <websocket/core/handshake.h>
#include <websocket/core/websocket.h>

#include <cstring>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>

#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/timing.h>
#include <mbedtls/x509.h>
#ifdef MBEDTLS_SSL_CACHE_C
#include <mbedtls/ssl_cache.h>
#endif

static FORCE_INLINE int
gen_rnd_int()
{
    constexpr auto pers = "a6aa177d5f45d14c7cbbca646160ff79537620b1503e681fd08f88589b26fee1";

    unsigned char block[ 4 ];

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast< const unsigned char * >( pers ), strlen( pers ) ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );

        // fallback
        std::random_device rd;
        std::mt19937 mt( rd() );
        std::uniform_int_distribution<> dist( std::numeric_limits< int >::min(), std::numeric_limits< int >::max() );
        return dist( mt );
    }

    if ( mbedtls_ctr_drbg_random( &ctr_drbg, block, 4 ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );

        // fallback
        std::random_device rd;
        std::mt19937 mt( rd() );
        std::uniform_int_distribution<> dist( std::numeric_limits< int >::min(), std::numeric_limits< int >::max() );
        return dist( mt );
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return block[ 0 ] << 24 | block[ 1 ] << 16 | block[ 2 ] << 8 | block[ 3 ];
}

struct ssl_t
{
    mbedtls_ssl_config context{}; /**< ssl settings context. */
    mbedtls_entropy_context entropy{}; /**< entropy context for random number generation. */
    mbedtls_x509_crt cert{}; /**< certificate context. */
    mbedtls_pk_context private_key{}; /**< private key context. */
    mbedtls_ssl_cache_context cache{}; /**< ssl cache context. */
    mbedtls_ctr_drbg_context drbg{}; /**< drbg context for random number generation. */

    ssl_t();

    ~
    ssl_t();
};

struct addr_t
{
    unsigned char bytes[ 18 ]{}; /**< address in byte format. */
    size_t len; /**< length of the address. */
    bool is_raw; /**< flag indicating if the address is in raw format. */
    std::string raw; /**< address in string format. */

    addr_t();

    addr_t( const unsigned char *in_bytes, size_t in_len );

    explicit
    addr_t( const char *in_raw );

    explicit
    addr_t( const std::string &in_raw );

    void
    from_string( const std::string &in_string );

    std::string
    to_string() const;
};

struct network_stream_t
{
    c_byte_stream input;
    c_byte_stream output;

    void
    close() const;

    network_stream_t() = default;

    ~
    network_stream_t()
    {
        close();
    }
};

enum class e_file_descriptor_type : unsigned char
{
    any = 0x0, /**< any type of file descriptor (non-binding). */
    bind = 0x1, /**< binding file descriptor (used to accept further connections). */
};

enum class e_file_descriptor_state : unsigned char
{
    handshake, /**< file descriptor is performing ssl/tls handshake. */
    open, /**< file descriptor is open. */
    close /**< file descriptor is closed. */
};

enum class e_ws_con_state : unsigned char
{
    opening, /**< connection is performing opening handshake. */
    open, /**< connection is established. */
    closing, /**< connection is performing closure handshake. */
    closed /**< connection is closed. */
};

struct file_descriptor_context
{
    mbedtls_net_context net{}; /**< network context for the file descriptor. */
    mbedtls_ssl_context ssl{}; /**< ssl context for the file descriptor. */

    addr_t addr; /**< address associated with the file descriptor. */

    e_file_descriptor_type type; /**< type of the file descriptor. */
    e_file_descriptor_state state; /**< state of the file descriptor. */

    e_ws_con_state ws_con_state; /**< ws connection state. */

    network_stream_t stream;

    std::string sec_websocket_accept;

    c_ws_frame frame;

    ws_extensions_t extensions{};

    mbedtls_timing_delay_context timer_ping_ctx{};
    mbedtls_timing_delay_context timer_ping_pong_ctx{};

    e_ws_closure_status closure_status; /**< closure reason for file descriptor. */

    file_descriptor_context();

    ~
    file_descriptor_context();

    void
    timer_ping( unsigned int ms );

    void
    timer_pong( unsigned int ms );

    void
    reset_timer_pong();
};

struct c_websocket::impl_t
{
    c_websocket *instance;

    e_ws_mode mode; /**< operation mode */

    unsigned int read_timeout; /**< read timeout in milliseconds. */
    unsigned int poll_timeout; /**< poll timeout in milliseconds. */

    size_t fd_limit; /**< maximum number of file descriptors to manage. */

    mutable std::recursive_mutex mutex; /**< mutex for thread-safe operations. */

    int last_status; /**< last status code returned by an operation. */
    std::string last_error; /**< last error message. */

    ssl_t ssl;

    std::map< int, file_descriptor_context > fd_map;

    e_ws_endpoint_type endpoint;

    ws_extensions_t extensions{};

    std::string host;
    std::string allowed_origin;

    unsigned int ping_interval;
    unsigned int ping_timeout;

    size_t message_limit;

    bool auto_mask_frame;

    bool
    try_lock() const;

    void
    wait_lock() const;

    void
    unlock() const;

    int
    set_last_status( int status );

    void
    set_last_error( const std::string &message );

    e_ws_status
    setup( const ws_settings_t *settings );

    int
    poll( file_descriptor_context *ctx ) const;

    void
    accept( file_descriptor_context *ctx );

    void
    communicate( file_descriptor_context *ctx );

    e_ws_status
    bind( const char *bind_ip, const char *bind_port, int *out_fd );

    e_ws_status
    open( const char *host_name, const char *host_port, int *out_fd );

    static void
    close( file_descriptor_context *ctx, e_ws_closure_status closure_status );

    int
    operate();

    void
    async_ws_frame( const int &fd, const c_ws_frame &frame ) const;

    impl_t();

    ~
    impl_t();
};

c_websocket::impl_t::
impl_t()
{
    instance = nullptr;

    mode = mode_unsecured;

    read_timeout = 0;
    poll_timeout = 0;

    fd_limit = 0;

    last_status = 0;
    last_error = "";

    ssl = {};

    endpoint = endpoint_server;

    host = "";
    allowed_origin = "";

    ping_interval = 60 * 1000;
    ping_timeout = 30 * 1000;

    message_limit = 4 * 1024 * 1024; // 4 mb in bytes

    auto_mask_frame = true;

    extensions.permessage_deflate.enabled = false;
    extensions.permessage_deflate.window_bits = 15;
}

c_websocket::impl_t::~
impl_t()
{
    fd_map.clear();
}

ssl_t::
ssl_t()
{
    mbedtls_ssl_config_init( &context );

    mbedtls_entropy_init( &entropy );
    mbedtls_x509_crt_init( &cert );
    mbedtls_pk_init( &private_key );

#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_init( &cache );
#endif

    mbedtls_ctr_drbg_init( &drbg );
}

ssl_t::~
ssl_t()
{
    mbedtls_ssl_config_free( &context );

    mbedtls_entropy_free( &entropy );
    mbedtls_x509_crt_free( &cert );
    mbedtls_pk_free( &private_key );

#ifdef MBEDTLS_SSL_CACHE_C
    mbedtls_ssl_cache_free( &cache );
#endif

    mbedtls_ctr_drbg_free( &drbg );
}

addr_t::
addr_t()
{
    std::memset( bytes, 0, sizeof( bytes ) );
    len = 0;

    is_raw = false;
    raw = {};
}

addr_t::
addr_t( const unsigned char *in_bytes, const size_t in_len )
{
    std::memcpy( bytes, in_bytes, sizeof( bytes ) );
    len = in_len;

    is_raw = false;
    raw = {};
}

addr_t::
addr_t( const char *in_raw ) :
    addr_t()
{
    is_raw = true;
    raw = in_raw;
}

addr_t::
addr_t( const std::string &in_raw ) :
    addr_t()
{
    is_raw = true;
    raw = in_raw;
}

void
addr_t::from_string( const std::string &in_string )
{
    std::memset( bytes, 0, sizeof( bytes ) );
    len = 0;

    if ( in_string.find( '.' ) != std::string::npos )
    {
        // IPv4
        len = 4;
        std::istringstream iss( in_string );
        std::string part;
        size_t i = 0;
        while ( std::getline( iss, part, '.' ) && i < len )
        {
            int byte = std::stoi( part );
            bytes[ i++ ] = static_cast< unsigned char >( byte );
        }
        if ( i != 4 )
        {
            len = 0;
            std::memset( bytes, 0, sizeof( bytes ) );
        }
    }
    else if ( in_string.find( ':' ) != std::string::npos )
    {
        // IPv6
        len = 16;
        std::istringstream iss( in_string );
        std::string part;
        size_t i = 0;
        while ( std::getline( iss, part, ':' ) && i < len )
        {
            int byte = std::stoi( part, nullptr, 16 );
            bytes[ i++ ] = static_cast< unsigned char >( byte );
        }
        if ( i != 16 )
        {
            len = 0;
            std::memset( bytes, 0, sizeof( bytes ) );
        }
    }
}

std::string
addr_t::to_string() const
{
    if ( is_raw )
    {
        return raw;
    }

    std::ostringstream oss;

    if ( len == 4 )
    {
        for ( size_t i = 0; i < len; ++i )
        {
            if ( i != 0 )
            {
                oss << '.';
            }
            oss << static_cast< int >( bytes[ i ] );
        }
    }
    else if ( len == 16 )
    {
        for ( size_t i = 0; i < len; ++i )
        {
            if ( i != 0 )
            {
                oss << ':';
            }
            oss << std::hex << static_cast< int >( bytes[ i ] );
        }
    }
    else
    {
        for ( size_t i = 0; i < len; ++i )
        {
            oss << static_cast< int >( bytes[ i ] );
        }
    }

    return oss.str();
}

void
network_stream_t::close() const
{
    input.close();
    output.close();
}

file_descriptor_context::
file_descriptor_context()
{
    net = {};
    ssl = {};

    addr = {};

    type = e_file_descriptor_type::any;
    state = e_file_descriptor_state::handshake;

    ws_con_state = e_ws_con_state::opening;

    mbedtls_timing_set_delay( &timer_ping_ctx, 0, 0 );
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, 0 );

    closure_status = closure_no_status_received;

    extensions.permessage_deflate.enabled = false;
    extensions.permessage_deflate.window_bits = 15;
}

file_descriptor_context::~
file_descriptor_context()
{
    stream.close();
}

void
file_descriptor_context::timer_ping( const unsigned int ms )
{
    mbedtls_timing_set_delay( &timer_ping_ctx, 0, ms );
}

void
file_descriptor_context::timer_pong( const unsigned int ms )
{
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, ms );
}

void
file_descriptor_context::reset_timer_pong()
{
    mbedtls_timing_set_delay( &timer_ping_pong_ctx, 0, 0 );
}

bool
c_websocket::impl_t::try_lock() const
{
    return mutex.try_lock();
}

void
c_websocket::impl_t::wait_lock() const
{
    mutex.lock();
}

void
c_websocket::impl_t::unlock() const
{
    mutex.unlock();
}

int
c_websocket::impl_t::set_last_status( const int status )
{
    last_status = status;

    if ( status < 0 )
    {
        char buffer[ 512 ];
        mbedtls_strerror( status, buffer, sizeof( buffer ) - 1 );
        set_last_error( buffer );
    }

    return status;
}

void
c_websocket::impl_t::set_last_error( const std::string &message )
{
    last_error = message;

    instance->on_error( last_error.c_str() );
}

e_ws_status
c_websocket::impl_t::setup( const ws_settings_t *settings )
{
    if ( settings == nullptr )
    {
        return status_error;
    }

    endpoint = settings->endpoint;

    read_timeout = settings->read_timeout;
    poll_timeout = settings->poll_timeout;

    fd_limit = settings->fd_limit;

    if ( mode == mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_entropy_add_source( &ssl.entropy, mbedtls_platform_entropy_poll, nullptr, 32, MBEDTLS_ENTROPY_SOURCE_STRONG ) ) != 0 )
        {
            return status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_ctr_drbg_seed( &ssl.drbg, mbedtls_entropy_func, &ssl.entropy, reinterpret_cast< const unsigned char * >( settings->ssl_seed ? settings->ssl_seed : "" ), settings->ssl_seed ? std::strlen( settings->ssl_seed ) : 0 ) ) != 0 )
        {
            return status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_ca_cert ? settings->ssl_ca_cert : "" ), settings->ssl_ca_cert ? std::strlen( settings->ssl_ca_cert ) : 0 ) ) != 0 )
        {
            return status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_x509_crt_parse( &ssl.cert, reinterpret_cast< const unsigned char * >( settings->ssl_own_cert ? settings->ssl_own_cert : "" ), settings->ssl_own_cert ? std::strlen( settings->ssl_own_cert ) : 0 ) ) != 0 )
        {
            return status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_pk_parse_key( &ssl.private_key, reinterpret_cast< const unsigned char * >( settings->ssl_private_key ? settings->ssl_private_key : "" ), settings->ssl_private_key ? std::strlen( settings->ssl_private_key ) : 0, nullptr, 0, mbedtls_ctr_drbg_random, &ssl.drbg ) ) != 0 )
        {
            return status_error;
        }

        if ( MBEDTLS_STATUS( mbedtls_ssl_config_defaults( &ssl.context, endpoint, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
        {
            return status_error;
        }

        mbedtls_ssl_conf_ca_chain( &ssl.context, &ssl.cert, nullptr );

        if ( MBEDTLS_STATUS( mbedtls_ssl_conf_own_cert( &ssl.context, ssl.cert.next, &ssl.private_key ) ) != 0 )
        {
            return status_error;
        }

        mbedtls_ssl_conf_rng( &ssl.context, mbedtls_ctr_drbg_random, &ssl.drbg );

#ifdef MBEDTLS_SSL_CACHE_C
        mbedtls_ssl_conf_session_cache( &ssl.context, &ssl.cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
#endif

        mbedtls_ssl_conf_authmode( &ssl.context, MBEDTLS_SSL_VERIFY_REQUIRED );

        mbedtls_ssl_conf_read_timeout( &ssl.context, read_timeout );
    }

    host = settings->host ? settings->host : "";
    allowed_origin = settings->allowed_origin ? settings->allowed_origin : "";

    ping_interval = settings->ping_interval;
    ping_timeout = settings->ping_timeout;

    message_limit = settings->message_limit;

    auto_mask_frame = settings->auto_mask_frame;

    extensions = settings->extensions;

    return status_ok;
}

int
c_websocket::impl_t::poll( file_descriptor_context *ctx ) const
{
    return mbedtls_net_poll( &ctx->net, MBEDTLS_NET_POLL_READ | MBEDTLS_NET_POLL_WRITE, poll_timeout );
}

void
c_websocket::impl_t::accept( file_descriptor_context *ctx )
{
    const int state = poll( ctx );

    if ( !( state & MBEDTLS_NET_POLL_READ ) )
    {
        return;
    }

    unsigned char client_addr[ 18 ];
    size_t client_addr_len = 0;
    std::memset( client_addr, 0, sizeof( client_addr ) );

    mbedtls_net_context net;
    mbedtls_net_init( &net );

    const int status = MBEDTLS_STATUS( mbedtls_net_accept( &ctx->net, &net, &client_addr, sizeof( client_addr ), &client_addr_len ) );

    if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
    {
        mbedtls_net_free( &net );
        return;
    }

    if ( MBEDTLS_STATUS( status ) != 0 )
    {
        mbedtls_net_free( &net );
        return;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init( &ssl );

    if ( mode == mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_ssl_setup( &ssl, &this->ssl.context ) ) != 0 )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return;
        }

        mbedtls_ssl_set_bio( &ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = { client_addr, client_addr_len };
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::handshake;
    new_fd.ws_con_state = e_ws_con_state::opening;
    fd_map.emplace( net.fd, new_fd );
}

void
c_websocket::impl_t::communicate( file_descriptor_context *ctx )
{
    const int state = poll( ctx );

    if ( ctx->state == e_file_descriptor_state::handshake )
    {
        if ( mode == mode_secured )
        {
            if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
            {
                return;
            }

            const int status = MBEDTLS_STATUS( mbedtls_ssl_handshake( &ctx->ssl ) );

            if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
            {
                return;
            }

            if ( status != 0 )
            {
                close( ctx, closure_tls_handshake_failed );
                return;
            }

            if ( MBEDTLS_STATUS( mbedtls_ssl_get_verify_result( &ctx->ssl ) ) != 0 )
            {
                close( ctx, closure_tls_handshake_failed );
                return;
            }
        }

        ctx->state = e_file_descriptor_state::open;

        switch ( endpoint )
        {
            case endpoint_server:
                break;

            case endpoint_client:
            {
                if ( c_ws_handshake::create( host.c_str(), allowed_origin.c_str(), "/", &ctx->stream.output, ctx->sec_websocket_accept, &extensions ) != c_ws_handshake::e_status::ok )
                {
                    close( ctx, closure_protocol_error );
                    return;
                }

                break;
            }
        }
    }

    if ( ctx->state == e_file_descriptor_state::open )
    {
        if ( ctx->ws_con_state == e_ws_con_state::open )
        {
            if ( mbedtls_timing_get_delay( &ctx->timer_ping_pong_ctx ) == 2 )
            {
                close( ctx, closure_abnormal );
            }

            if ( mbedtls_timing_get_delay( &ctx->timer_ping_ctx ) == 2 )
            {
                if ( c_ws_frame( opcode_ping ).write( &ctx->stream.output ) == e_ws_frame_status::status_ok )
                {
                    ctx->timer_pong( ping_timeout );
                }
            }
        }

        if ( state & MBEDTLS_NET_POLL_READ )
        {
            unsigned char buffer[ CHUNK_SIZE ];

            int status;

            if ( mode == mode_secured )
            {
                status = MBEDTLS_STATUS( mbedtls_ssl_read( &ctx->ssl, buffer, CHUNK_SIZE ) );
            }
            else
            {
                status = MBEDTLS_STATUS( mbedtls_net_recv_timeout( &ctx->net, buffer, CHUNK_SIZE, read_timeout ) );
            }

            if ( status > 0 )
            {
                if ( ctx->stream.input.push_back( buffer, status ) == c_byte_stream::e_status::ok )
                {
                    if ( ctx->stream.input.size() > message_limit )
                    {
                        close( ctx, closure_message_too_big );
                        return;
                    }

                    do
                    {
                        switch ( ctx->ws_con_state )
                        {
                            case e_ws_con_state::opening:
                            {
                                c_ws_handshake::e_status status_handshake = c_ws_handshake::e_status::ok;

                                switch ( endpoint )
                                {
                                    case endpoint_server:
                                        status_handshake = c_ws_handshake::server( host.c_str(), allowed_origin.c_str(), &ctx->stream.input, &ctx->stream.output, &extensions, &ctx->extensions );
                                        break;

                                    case endpoint_client:
                                        status_handshake = c_ws_handshake::client( ctx->sec_websocket_accept.c_str(), &ctx->stream.input, &ctx->stream.output, &ctx->extensions );
                                        break;

                                    default:
                                        break;
                                }

                                switch ( status_handshake )
                                {
                                    case status_busy:
                                    {
                                        return;
                                    }

                                    case status_ok:
                                    {
                                        if ( ctx->extensions.permessage_deflate.enabled )
                                        {
                                            ctx->frame.deflate( ctx->extensions.permessage_deflate.window_bits );
                                        }

                                        ctx->ws_con_state = e_ws_con_state::open;

                                        ctx->timer_ping( ping_interval );

                                        instance->on_open( ctx->net.fd, ctx->addr.to_string().c_str() );

                                        break;
                                    }

                                    case status_error:
                                    {
                                        close( ctx, closure_protocol_error );
                                        return;
                                    }

                                    default:
                                    {
                                        close( ctx, closure_internal_error );
                                        return;
                                    }
                                }

                                break;
                            }

                            case e_ws_con_state::open:
                            case e_ws_con_state::closing:
                            {
                                const e_ws_frame_status status_frame = ctx->frame.read( &ctx->stream.input );

                                switch ( status_frame )
                                {
                                    case e_ws_frame_status::status_incomplete:
                                    case e_ws_frame_status::status_fragment:
                                    {
                                        break;
                                    }

                                    case e_ws_frame_status::status_invalid_data:
                                    {
                                        close( ctx, closure_invalid_data );
                                        return;
                                    }

                                    case e_ws_frame_status::status_final:
                                    {
                                        const e_ws_frame_opcode opcode = ctx->frame.get_opcode();

                                        switch ( opcode )
                                        {
                                            case opcode_text:
                                            case opcode_binary:
                                            {
                                                std::thread( &impl_t::async_ws_frame, this, ctx->net.fd, std::move( ctx->frame ) ).detach();
                                                ctx->frame = {};
                                                break;
                                            }

                                            case opcode_ping:
                                            {
                                                if ( c_ws_frame( opcode_pong ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
                                                {
                                                    close( ctx, closure_internal_error );
                                                }

                                                break;
                                            }

                                            case opcode_pong:
                                            {
                                                ctx->reset_timer_pong();
                                                ctx->timer_ping( ping_interval );

                                                break;
                                            }

                                            case opcode_close:
                                            {
                                                if ( ctx->ws_con_state == e_ws_con_state::closing )
                                                {
                                                    ctx->ws_con_state = e_ws_con_state::closed;
                                                    close( ctx, closure_normal );
                                                }
                                                else
                                                {
                                                    if ( c_ws_frame( opcode_close ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
                                                    {
                                                        close( ctx, closure_internal_error );
                                                    }

                                                    ctx->ws_con_state = e_ws_con_state::closed;
                                                    close( ctx, closure_normal );
                                                }

                                                return;
                                            }

                                            default:
                                            {
                                                close( ctx, closure_internal_error );
                                                return;
                                            }
                                        }

                                        break;
                                    }

                                    case e_ws_frame_status::status_error:
                                    {
                                        close( ctx, closure_protocol_error );
                                        return;
                                    }

                                    default:
                                    {
                                        close( ctx, closure_internal_error );
                                        return;
                                    }
                                }

                                break;
                            }

                            default:
                            {
                                break;
                            }
                        }
                    }
                    while ( ctx->stream.input.available() );
                }
            }
            else
            {
                switch ( status )
                {
                    case 0:
                    case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    case MBEDTLS_ERR_SSL_TIMEOUT:
                    case MBEDTLS_ERR_NET_CONN_RESET:
                        close( ctx, closure_abnormal );
                        break;

                    default:
                    case MBEDTLS_ERR_SSL_WANT_READ:
                    case MBEDTLS_ERR_SSL_WANT_WRITE:
                        // pipe is busy
                        break;
                }
            }
        }

        if ( state & MBEDTLS_NET_POLL_WRITE )
        {
            if ( ctx->stream.output.available() )
            {
                const size_t length = ctx->stream.output.size() > CHUNK_SIZE ? CHUNK_SIZE : ctx->stream.output.size();

                int status;

                if ( mode == mode_secured )
                {
                    status = MBEDTLS_STATUS( mbedtls_ssl_write( &ctx->ssl, ctx->stream.output.pointer(), length ) );
                }
                else
                {
                    status = MBEDTLS_STATUS( mbedtls_net_send( &ctx->net, ctx->stream.output.pointer(), length ) );
                }

                if ( status > 0 )
                {
                    if ( ctx->stream.output.pop( status ) != c_byte_stream::e_status::ok )
                    {
                        ctx->stream.output.flush();
                    }
                }
                else
                {
                    switch ( status )
                    {
                        case 0:
                        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                        case MBEDTLS_ERR_NET_CONN_RESET:
                            close( ctx, closure_abnormal );
                            break;

                        default:
                        case MBEDTLS_ERR_SSL_WANT_READ:
                        case MBEDTLS_ERR_SSL_WANT_WRITE:
                            // pipe is busy
                            break;
                    }
                }
            }
        }
    }
}

e_ws_status
c_websocket::impl_t::bind( const char *bind_ip, const char *bind_port, int *out_fd )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_bind( &net, bind_ip, bind_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return status_error;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return status_error;
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.addr = addr_t( bind_ip ? bind_ip : "0.0.0.0" );
    new_fd.type = e_file_descriptor_type::bind;
    new_fd.state = e_file_descriptor_state::open;
    new_fd.ws_con_state = e_ws_con_state::open;
    fd_map.emplace( net.fd, new_fd );

    if ( out_fd )
    {
        *out_fd = net.fd;
    }

    return status_ok;
}

e_ws_status
c_websocket::impl_t::open( const char *host_name, const char *host_port, int *out_fd )
{
    mbedtls_net_context net;
    mbedtls_net_init( &net );

    if ( MBEDTLS_STATUS( mbedtls_net_connect( &net, host_name, host_port, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return status_error;
    }

    if ( MBEDTLS_STATUS( mbedtls_net_set_nonblock( &net ) ) != 0 )
    {
        mbedtls_net_free( &net );
        return status_error;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init( &ssl );

    if ( mode == mode_secured )
    {
        if ( MBEDTLS_STATUS( mbedtls_ssl_setup( &ssl, &this->ssl.context ) ) != 0 )
        {
            mbedtls_ssl_free( &ssl );
            mbedtls_net_free( &net );
            return status_error;
        }

        mbedtls_ssl_set_bio( &ssl, &net, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );
    }

    file_descriptor_context new_fd;
    new_fd.net = net;
    new_fd.ssl = ssl;
    new_fd.addr = addr_t( host_name );
    new_fd.type = e_file_descriptor_type::any;
    new_fd.state = e_file_descriptor_state::handshake;
    new_fd.ws_con_state = e_ws_con_state::opening;
    fd_map.emplace( net.fd, new_fd );

    if ( out_fd )
    {
        *out_fd = net.fd;
    }

    return status_ok;
}

void
c_websocket::impl_t::close( file_descriptor_context *ctx, const e_ws_closure_status closure_status )
{
    ctx->stream.input.flush();
    ctx->stream.output.flush();
    ctx->closure_status = closure_status;
    ctx->state = e_file_descriptor_state::close;
}

int
c_websocket::impl_t::operate()
{
    wait_lock();

    for ( auto it = fd_map.begin(); it != fd_map.end(); )
    {
        file_descriptor_context *ctx = &it->second;

        if ( ctx->state != e_file_descriptor_state::close )
        {
            ++it;
            continue;
        }

        if ( ctx->stream.output.available() )
        {
            ++it;
            continue;
        }

        if ( ctx->type != e_file_descriptor_type::bind )
        {
            const int state = poll( ctx );

            if ( !( state & MBEDTLS_NET_POLL_WRITE ) )
            {
                ++it;
                continue;
            }

            if ( mode == mode_secured )
            {
                const int status = MBEDTLS_STATUS( mbedtls_ssl_close_notify( &ctx->ssl ) );
                if ( status == MBEDTLS_ERR_SSL_WANT_READ || status == MBEDTLS_ERR_SSL_WANT_WRITE )
                {
                    ++it;
                    continue;
                }

                MBEDTLS_STATUS( mbedtls_ssl_session_reset( &ctx->ssl ) );
            }
        }

        instance->on_close( ctx->net.fd, ctx->closure_status );

        mbedtls_net_close( &ctx->net );

        mbedtls_net_free( &ctx->net );
        mbedtls_ssl_free( &ctx->ssl );

        it = fd_map.erase( it );
    }

    const size_t fd_count = fd_map.size();

    for ( auto &it : fd_map )
    {
        file_descriptor_context *ctx = &it.second;

        switch ( ctx->type )
        {
            case e_file_descriptor_type::bind:
            {
                // do not accept further file descriptors, if limit is exceeded.
                if ( fd_limit != 0 )
                {
                    if ( fd_count == fd_limit )
                    {
                        break;
                    }
                }

                accept( ctx );
                break;
            }

            case e_file_descriptor_type::any:
            {
                communicate( ctx );
                break;
            }

            default:
            {
                close( ctx, closure_internal_error );
                break;
            }
        }
    }

    unlock();

    return fd_count != 0;
}

void
c_websocket::impl_t::async_ws_frame( const int &fd, const c_ws_frame &frame ) const
{
    const e_ws_frame_opcode opcode = frame.get_opcode();
    unsigned char *payload = frame.get_payload();
    const size_t payload_size = frame.get_payload_size();

    instance->on_frame( fd, opcode, payload, payload_size );
}

void
c_websocket::on_open( const int fd, const char *addr )
{
    if ( event_open_callback )
    {
        event_open_callback( this, fd, addr );
    }
}

void
c_websocket::on_frame( const int fd, const e_ws_frame_opcode opcode, unsigned char *payload, const size_t size )
{
    if ( event_frame_callback )
    {
        event_frame_callback( this, fd, opcode, payload, size );
    }
}

void
c_websocket::on_close( const int fd, const e_ws_closure_status status )
{
    if ( event_close_callback )
    {
        event_close_callback( this, fd, status );
    }
}

void
c_websocket::on_error( const char *message )
{
    if ( event_error_callback )
    {
        event_error_callback( this, message );
    }
}

c_websocket::
c_websocket()
{
    event_open_callback = nullptr;
    event_close_callback = nullptr;
    event_frame_callback = nullptr;
    event_error_callback = nullptr;

    impl = new impl_t();
    impl->instance = this;
}

c_websocket::~
c_websocket()
{
    delete impl;
}

e_ws_status
c_websocket::setup( const ws_settings_t *settings ) const
{
    return impl->setup( settings );
}

e_ws_status
c_websocket::bind( const char *bind_ip, const char *bind_port, int *out_fd ) const
{
    return impl->bind( bind_ip, bind_port, out_fd );
}

e_ws_status
c_websocket::bind( const char *bind_port, int *out_fd ) const
{
    return impl->bind( nullptr, bind_port, out_fd );
}

e_ws_status
c_websocket::open( const char *host_name, const char *host_port, int *out_fd ) const
{
    return impl->open( host_name, host_port, out_fd );
}

void
c_websocket::close( const int fd )
{
    impl->wait_lock();

    if ( fd == -1 )
    {
        for ( const auto &it : impl->fd_map )
        {
            close( it.first );
        }

        return;
    }

    const auto it = impl->fd_map.find( fd );
    if ( it == impl->fd_map.end() )
    {
        impl->unlock();

        return;
    }

    file_descriptor_context *ctx = &it->second;

    if ( ctx->type == e_file_descriptor_type::bind )
    {
        impl_t::close( ctx, closure_normal );

        impl->unlock();

        return;
    }

    if ( ctx->ws_con_state == e_ws_con_state::open )
    {
        if ( c_ws_frame( opcode_close ).write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
        {
            impl_t::close( ctx, closure_internal_error );
        }
        else
        {
            ctx->ws_con_state = e_ws_con_state::closing;
        }

        impl->unlock();

        return;
    }

    impl_t::close( ctx, closure_abnormal );

    impl->unlock();
}

e_ws_status
c_websocket::on( const char *event, void *callback )
{
    if ( !std::strcmp( event, WS_EVENT_OPEN ) )
    {
        event_open_callback = reinterpret_cast< t_event_open >( callback );
        return status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_CLOSE ) )
    {
        event_close_callback = reinterpret_cast< t_event_close >( callback );
        return status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_FRAME ) )
    {
        event_frame_callback = reinterpret_cast< t_event_frame >( callback );
        return status_ok;
    }

    if ( !std::strcmp( event, WS_EVENT_ERROR ) )
    {
        event_error_callback = reinterpret_cast< t_event_error >( callback );
        return status_ok;
    }

    return status_error;
}

bool
c_websocket::operate() const
{
    return impl->operate();
}

e_ws_status
c_websocket::emit( const int fd, const c_ws_frame *frame ) const
{
    if ( !frame )
    {
        return status_error;
    }

    const auto it = impl->fd_map.find( fd );
    if ( it == impl->fd_map.end() )
    {
        return status_error;
    }

    const file_descriptor_context *ctx = &it->second;

    if ( ctx->state != e_file_descriptor_state::open )
    {
        return status_error;
    }

    if ( ctx->ws_con_state == e_ws_con_state::opening || ctx->ws_con_state == e_ws_con_state::closed )
    {
        return status_error;
    }

    if ( impl->auto_mask_frame )
    {
        frame->mask( gen_rnd_int() );
    }

    if ( ctx->extensions.permessage_deflate.enabled )
    {
        frame->deflate( ctx->extensions.permessage_deflate.window_bits );
    }

    if ( frame->write( &ctx->stream.output ) != e_ws_frame_status::status_ok )
    {
        return status_error;
    }

    return status_ok;
}
