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
#include <websocket/core/handshake.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha1.h>
#include <websocket/core/http.h>

/**
 * @brief Calculates the length of a C-style string at compile-time.
 *
 * This function iterates through the string until it finds the null
 * terminator ('\0'), counting the number of characters.
 *
 * @param s A pointer to a null-terminated string.
 * @return The length of the string (not including the null terminator).
 */
constexpr size_t
constexpr_strlen( const char* s )
{
    return *s ? 1 + constexpr_strlen( s + 1 ) : 0;
}

static std::string
string_to_lower( const std::string& str )
{
    std::string result = str;

    std::transform( result.begin(), result.end(), result.begin(), []( const unsigned char c )
    {
        return std::tolower( c );
    } );

    return result;
}

static bool
string_contains_case_insensitive( const std::string& main_str, const std::string& sub_str )
{
    const std::string lower_main_str = string_to_lower( main_str );
    const std::string lower_sub_str = string_to_lower( sub_str );

    return lower_main_str.find( lower_sub_str ) != std::string::npos;
}

/**
 * @brief Represents the WebSocket magic GUID.
 *
 * This is a static constant string that represents the WebSocket
 * magic GUID as specified in RFC 4122.
 */
static constexpr char WS_MAGIC[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/**
 * @brief The size of the WS_MAGIC string.
 *
 * This constant holds the length of the WS_MAGIC string
 * calculated at compile time.
 */
static constexpr size_t WS_MAGIC_SIZE = constexpr_strlen( WS_MAGIC );

c_ws_handshake::e_status
c_ws_handshake::random( const size_t count, std::string& output )
{
    constexpr const char* pers = "097290aafe141434bd15eace820031b16f40a4677979a386919bad2ba57f1547";

    unsigned char* block = static_cast< unsigned char* >( malloc( sizeof( unsigned char ) * count ) );
    if ( block == nullptr )
    {
        return error;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if ( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast< const unsigned char* >( pers ), std::strlen( pers ) ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );
        free( block );
        return error;
    }

    if ( mbedtls_ctr_drbg_random( &ctr_drbg, block, count ) != 0 )
    {
        mbedtls_ctr_drbg_free( &ctr_drbg );
        mbedtls_entropy_free( &entropy );
        free( block );
        return error;
    }

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    output.assign( reinterpret_cast< const char* >( block ), count );
    free( block );

    return ok;
}

c_ws_handshake::e_status
c_ws_handshake::secret( const std::string& input, std::string& output )
{
    // create sha1 hash
    unsigned char hash[ 20 ];

    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init( &sha1_ctx );

    if ( mbedtls_sha1_starts( &sha1_ctx ) != 0 )
    {
        mbedtls_sha1_free( &sha1_ctx );
        return error;
    }

    if ( mbedtls_sha1_update( &sha1_ctx, reinterpret_cast< const unsigned char* >( input.c_str() ), input.size() ) != 0 )
    {
        mbedtls_sha1_free( &sha1_ctx );
        return error;
    }

    if ( mbedtls_sha1_update( &sha1_ctx, reinterpret_cast< const unsigned char* >( WS_MAGIC ), WS_MAGIC_SIZE ) != 0 )
    {
        mbedtls_sha1_free( &sha1_ctx );
        return error;
    }

    if ( mbedtls_sha1_finish( &sha1_ctx, hash ) != 0 )
    {
        mbedtls_sha1_free( &sha1_ctx );
        return error;
    }

    mbedtls_sha1_free( &sha1_ctx );

    // base64 encode sha1 hash
    unsigned char b64[ 64 ];
    size_t olen = 0;

    if ( mbedtls_base64_encode( b64, sizeof( b64 ), &olen, hash, 20 ) != 0 )
    {
        return error;
    }

    // assign base64 encoded to output
    output.assign( reinterpret_cast< const char* >( b64 ), olen );

    return ok;
}

c_ws_handshake::e_status
c_ws_handshake::create( const char* host, const char* origin, const char* channel, c_byte_stream* output, std::string& out_accept_key, const ws_extensions_t* extensions )
{
    if ( output == nullptr )
    {
        return error;
    }

    // generate 16-byte random block
    std::string sec_websocket_key;

    if ( random( 16, sec_websocket_key ) != ok )
    {
        return error;
    }

    // base64 encode secret-key
    unsigned char b64[ 45 ];
    size_t olen = 0;

    if ( mbedtls_base64_encode( b64, sizeof( b64 ), &olen, reinterpret_cast< const unsigned char* >( sec_websocket_key.c_str() ), sec_websocket_key.size() ) != 0 )
    {
        return error;
    }

    // create accept-key out of secret-key
    std::string accept_key;

    if ( secret( std::string( reinterpret_cast< const char* >( b64 ), olen ), accept_key ) != ok )
    {
        return error;
    }

    // create request
    c_byte_stream request;

    request << "GET " << channel << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Upgrade: websocket\r\n";
    request << "Connection: Upgrade\r\n";
    request << "Sec-WebSocket-Key: " << b64 << "\r\n";
    request << "Sec-WebSocket-Version: 13\r\n";

    if ( extensions && extensions->permessage_deflate.enabled )
    {
        request << "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=" << static_cast< int >( extensions->permessage_deflate.window_bits ) << "\r\n";
    }

    if ( origin )
    {
        request << "Origin: " << origin << "\r\n";
    }

    request << "\r\n";

    if ( request.move( output, request.size(), 0 ) != c_byte_stream::e_status::ok )
    {
        return error;
    }

    out_accept_key = accept_key;

    return ok;
}

c_ws_handshake::e_status
c_ws_handshake::client( const char* accept_key, const c_byte_stream* input, c_byte_stream* output, ws_extensions_t* extensions )
{
    if ( output == nullptr )
    {
        return error;
    }

    if ( input == nullptr )
    {
        c_http::respond( c_http::e_status_code::http_status_code_internal_server_error, output );
        return error;
    }

    if ( !input->available() )
    {
        return busy;
    }

    c_http http;
    if ( c_http::parse( input, http ) != c_http::e_status::ok )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    input->flush();

    if ( http.get_version() != c_http::e_version::http_version_1_1 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_http_version_not_supported, output );
        return error;
    }

    if ( http.get_status_code() != c_http::e_status_code::http_status_code_switching_protocols )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    const std::map< std::string, std::string > headers = http.get_headers();

    // verify required attributes are present
    if ( headers.find( "Upgrade" ) == headers.end() ||
         headers.find( "Connection" ) == headers.end() ||
         headers.find( "Sec-WebSocket-Accept" ) == headers.end() )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Upgrade| header field contains websocket
    const std::string header_upgrade = headers.at( "Upgrade" );

    if ( !string_contains_case_insensitive( header_upgrade, "websocket" ) )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Connection| header field contains upgrade
    const std::string header_connection = headers.at( "Connection" );

    if ( !string_contains_case_insensitive( header_connection, "upgrade" ) )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    const std::string sec_websocket_accept = headers.at( "Sec-WebSocket-Accept" );

    // verify |Sec-WebSocket-Accept| header field matches accept-key
    if ( std::strcmp( sec_websocket_accept.c_str(), accept_key ) != 0 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    if ( headers.find( "Sec-WebSocket-Extensions" ) != headers.end() )
    {
        const std::string header_extensions = headers.at( "Sec-WebSocket-Extensions" );

        // check if permessage-deflate is enabled and enforce no-context-takeover (matches per-message zlib state)
        if ( header_extensions.find( "permessage-deflate" ) != std::string::npos )
        {
            bool got_client_no_context_takeover = false;
            bool got_server_no_context_takeover = false;

            if ( header_extensions.find( "client_no_context_takeover" ) != std::string::npos )
            {
                got_client_no_context_takeover = true;
            }

            if ( header_extensions.find( "server_no_context_takeover" ) != std::string::npos )
            {
                got_server_no_context_takeover = true;
            }

            int server_max_window_bits = 15;

            const size_t pos = header_extensions.find( "server_max_window_bits" );
            if ( pos != std::string::npos )
            {
                const size_t equals_pos = header_extensions.find( '=', pos );
                if ( equals_pos != std::string::npos )
                {
                    size_t end_pos = header_extensions.find_first_of( ";, \r\n", equals_pos + 1 );
                    if ( end_pos == std::string::npos )
                    {
                        end_pos = header_extensions.size();
                    }

                    try
                    {
                        server_max_window_bits = std::stoi( header_extensions.substr( equals_pos + 1, end_pos - ( equals_pos + 1 ) ) );
                    }
                    catch ( ... )
                    {
                        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
                        return error;
                    }
                }
            }

            if ( extensions )
            {
                if ( got_client_no_context_takeover == true && got_server_no_context_takeover == true )
                {
                    if ( server_max_window_bits < 8 )
                    {
                        server_max_window_bits = 8;
                    }
                    if ( server_max_window_bits > 15 )
                    {
                        server_max_window_bits = 15;
                    }

                    extensions->permessage_deflate.enabled = true;
                    extensions->permessage_deflate.window_bits = static_cast< unsigned char >( server_max_window_bits );
                }
                else
                {
                    extensions->permessage_deflate.enabled = false;
                }
            }
        }
    }

    return ok;
}

c_ws_handshake::e_status
c_ws_handshake::server( const char* host, const char* origin, const c_byte_stream* input, c_byte_stream* output, const ws_extensions_t* server_extensions, ws_extensions_t* client_extensions )
{
    if ( output == nullptr )
    {
        return error;
    }

    if ( input == nullptr )
    {
        c_http::respond( c_http::e_status_code::http_status_code_internal_server_error, output );
        return error;
    }

    if ( !input->available() )
    {
        return busy;
    }

    c_http http;
    if ( c_http::parse( input, http ) != c_http::e_status::ok )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    input->flush();

    if ( http.get_version() != c_http::e_version::http_version_1_1 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_http_version_not_supported, output );
        return error;
    }

    const std::map< std::string, std::string > headers = http.get_headers();

    // verify required attributes are present
    if ( headers.find( "Host" ) == headers.end() ||
         headers.find( "Upgrade" ) == headers.end() ||
         headers.find( "Connection" ) == headers.end() ||
         headers.find( "Sec-WebSocket-Key" ) == headers.end() ||
         headers.find( "Sec-WebSocket-Version" ) == headers.end() )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Host| header field containing the server's authority
    const std::string header_host = headers.at( "Host" );

    if ( std::strcmp( header_host.c_str(), host ) != 0 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Upgrade| header field contains websocket
    const std::string header_upgrade = headers.at( "Upgrade" );

    if ( !string_contains_case_insensitive( header_upgrade, "websocket" ) )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Connection| header field contains upgrade
    const std::string header_connection = headers.at( "Connection" );

    if ( !string_contains_case_insensitive( header_connection, "upgrade" ) )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Sec-WebSocket-Version| header field is set to supported websocket version
    const std::string version = headers.at( "Sec-WebSocket-Version" );

    if ( std::strcmp( version.c_str(), "13" ) != 0 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_upgrade_required, output );
        return error;
    }

    // [optional] verify |Origin| header field matches
    if ( std::strcmp( origin, "" ) != 0 && std::strcmp( origin, "null" ) != 0 )
    {
        if ( headers.find( "Origin" ) == headers.end() )
        {
            c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
            return error;
        }

        const std::string header_origin = headers.at( "Origin" );

        if ( !string_contains_case_insensitive( header_origin, host ) )
        {
            c_http::respond( c_http::e_status_code::http_status_code_forbidden, output );
            return error;
        }
    }

    // todo: [optional] verify |Sec-WebSocket-Protocol| header field
    /*
        Optionally, a |Sec-WebSocket-Protocol| header field, with a list
        of values indicating which protocols the client would like to
        speak, ordered by preference.
    */

    if ( client_extensions )
    {
        client_extensions->permessage_deflate.enabled = false;
    }

    if ( headers.find( "Sec-WebSocket-Extensions" ) != headers.end() )
    {
        const std::string header_extensions = headers.at( "Sec-WebSocket-Extensions" );

        // check if permessage-deflate is requested and enforce no-context-takeover (matches per-message zlib state)
        if ( header_extensions.find( "permessage-deflate" ) != std::string::npos )
        {
            bool req_client_no_context_takeover = false;
            bool req_server_no_context_takeover = false;

            if ( header_extensions.find( "client_no_context_takeover" ) != std::string::npos )
            {
                req_client_no_context_takeover = true;
            }

            if ( header_extensions.find( "server_no_context_takeover" ) != std::string::npos )
            {
                req_server_no_context_takeover = true;
            }

            int client_max_window_bits = 15;

            const size_t pos = header_extensions.find( "client_max_window_bits" );
            if ( pos != std::string::npos )
            {
                const size_t equals_pos = header_extensions.find( '=', pos );
                if ( equals_pos != std::string::npos )
                {
                    size_t end_pos = header_extensions.find_first_of( ";, \r\n", equals_pos + 1 );
                    if ( end_pos == std::string::npos )
                    {
                        end_pos = header_extensions.size();
                    }

                    try
                    {
                        client_max_window_bits = std::stoi( header_extensions.substr( equals_pos + 1, end_pos - ( equals_pos + 1 ) ) );
                    }
                    catch ( ... )
                    {
                        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
                        return error;
                    }
                }
            }

            if ( client_max_window_bits < 8 )
            {
                client_max_window_bits = 8;
            }
            if ( client_max_window_bits > 15 )
            {
                client_max_window_bits = 15;
            }

            if ( client_extensions )
            {
                if ( server_extensions && server_extensions->permessage_deflate.enabled )
                {
                    if ( req_client_no_context_takeover == true && req_server_no_context_takeover == true )
                    {
                        client_extensions->permessage_deflate.enabled = true;
                        client_extensions->permessage_deflate.window_bits = static_cast< unsigned char >( client_max_window_bits );
                    }
                    else
                    {
                        client_extensions->permessage_deflate.enabled = false;
                    }
                }
                else
                {
                    client_extensions->permessage_deflate.enabled = false;
                }
            }
        }
    }

    // generate |Sec-WebSocket-Accept| out of |Sec-WebSocket-Key|
    const std::string secret_key = headers.at( "Sec-WebSocket-Key" );
    std::string accept;

    if ( secret( secret_key, accept ) != ok )
    {
        c_http::respond( c_http::e_status_code::http_status_code_internal_server_error, output );
        return error;
    }

    *output << "HTTP/1.1 101 Switching Protocols\r\n";
    *output << "Upgrade: websocket\r\n";
    *output << "Connection: Upgrade\r\n";
    *output << "Sec-WebSocket-Accept: " << accept.c_str() << "\r\n";

    if ( client_extensions && client_extensions->permessage_deflate.enabled )
    {
        *output << "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover";

        if ( server_extensions && server_extensions->permessage_deflate.window_bits != client_extensions->permessage_deflate.window_bits )
        {
            *output << "; server_max_window_bits=" << static_cast< int >( server_extensions->permessage_deflate.window_bits );
        }

        *output << "\r\n";
    }

    *output << "\r\n";

    return ok;
}
