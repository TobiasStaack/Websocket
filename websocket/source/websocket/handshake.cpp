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
#define HANDSHAKE_LIMIT 16384

#include <websocket/core/handshake.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <utility>
#include <vector>

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

/**
 * @brief Converts a string to lower case.
 *
 * @param[in] str The string to convert.
 * @return The lower case form of the string.
 */
static std::string
string_to_lower( const std::string& str )
{
    std::string result = str;

    std::transform( result.begin(), result.end(), result.begin(), []( const unsigned char c )
    {
        return static_cast< char >( std::tolower( c ) );
    } );

    return result;
}

/**
 * @brief Checks whether a string contains a substring, ignoring case.
 *
 * @param[in] main_str The string to search in.
 * @param[in] sub_str The substring to look for.
 * @return `true` when the substring occurs.
 */
static bool
string_contains_case_insensitive( const std::string& main_str, const std::string& sub_str )
{
    const std::string lower_main_str = string_to_lower( main_str );
    const std::string lower_sub_str = string_to_lower( sub_str );

    return lower_main_str.find( lower_sub_str ) != std::string::npos;
}

/**
 * @brief Compares two strings ignoring case.
 *
 * @param[in] lhs The left string.
 * @param[in] rhs The right string.
 * @return `true` when both strings match.
 */
static bool
string_equals_case_insensitive( const std::string& lhs, const std::string& rhs )
{
    return string_to_lower( lhs ) == string_to_lower( rhs );
}

/**
 * @brief Checks whether a value is the base64 encoding of a 16 byte nonce.
 *
 * @param value The header field value to inspect.
 * @return `true` when the value is a well formed 24 character base64 block.
 */
static bool
is_base64_nonce( const std::string& value )
{
    if ( value.size() != 24 || value.compare( 22, 2, "==" ) != 0 )
    {
        return false;
    }

    for ( size_t i = 0; i < 22; ++i )
    {
        const char c = value[ i ];

        if ( !std::isalnum( static_cast< unsigned char >( c ) ) && c != '+' && c != '/' )
        {
            return false;
        }
    }

    return true;
}

/**
 * @brief Extracts the host of an origin without its scheme, port and path.
 *
 * @param origin The origin header field value.
 * @return The bare host of the origin.
 */
static std::string
origin_host( const std::string& origin )
{
    std::string result = origin;

    const size_t scheme = result.find( "://" );
    if ( scheme != std::string::npos )
    {
        result = result.substr( scheme + 3 );
    }

    const size_t end = result.find_first_of( "/:" );
    if ( end != std::string::npos )
    {
        result = result.substr( 0, end );
    }

    return result;
}

/**
 * @brief Compares the authority a client sent against the one the server is configured for.
 *
 * A configured authority without a port matches any port the client dials, which is what
 * RFC 6455 section 4.2.1 asks for: the server only has to recognise the authority as its own.
 * A configured port is compared as well, so a server bound to one port can reject another.
 *
 * @param header_host The `Host` header field value sent by the client.
 * @param host The authority the server was configured with.
 * @return `true` when the client addressed this server.
 */
static bool
authority_matches( const std::string& header_host, const char* host )
{
    if ( host == 0 || host[ 0 ] == '\0' )
    {
        return true;
    }

    const std::string configured( host );

    if ( string_equals_case_insensitive( header_host, configured ) )
    {
        return true;
    }

    // a configured authority without a port ignores the port the client dialled
    if ( configured.find( ':' ) != std::string::npos )
    {
        return false;
    }

    const size_t port = header_host.rfind( ':' );

    // an ipv6 literal keeps its colons inside brackets, only a trailing port may be dropped
    if ( port == std::string::npos || header_host.find( ']', port ) != std::string::npos )
    {
        return false;
    }

    return string_equals_case_insensitive( header_host.substr( 0, port ), configured );
}

/**
 * @brief Removes leading and trailing whitespace.
 *
 * @param[in] str The string to trim.
 * @return The trimmed string.
 */
static std::string
string_trim( const std::string& str )
{
    const size_t start = str.find_first_not_of( " \t\r\n" );
    const size_t end = str.find_last_not_of( " \t\r\n" );

    return start == std::string::npos ? "" : str.substr( start, end - start + 1 );
}

/**
 * @brief Splits a comma separated header field value into its trimmed items.
 *
 * @param value The header field value to split.
 * @return The items of the list, empty items are dropped.
 */
static std::vector< std::string >
split_list( const std::string& value )
{
    std::vector< std::string > items;

    size_t offset = 0;

    while ( offset <= value.size() )
    {
        const size_t comma = value.find( ',', offset );
        const size_t end = comma == std::string::npos ? value.size() : comma;

        const std::string item = string_trim( value.substr( offset, end - offset ) );
        if ( item.empty() == false )
        {
            items.push_back( item );
        }

        if ( comma == std::string::npos )
        {
            break;
        }

        offset = comma + 1;
    }

    return items;
}

/**
 * @brief A single extension offer of a `Sec-WebSocket-Extensions` header field.
 */
struct extension_offer_t
{
    std::string name;
    std::vector< std::pair< std::string, std::string > > params;

    bool
    has( const std::string& key ) const
    {
        for ( size_t i = 0; i < params.size(); ++i )
        {
            if ( params[ i ].first == key )
            {
                return true;
            }
        }

        return false;
    }
};

/**
 * @brief Parses a `Sec-WebSocket-Extensions` header field as described in RFC 7692 section 7.
 *
 * @param value The header field value to parse.
 * @return One entry per offered extension, in the order they were offered.
 */
static std::vector< extension_offer_t >
parse_extension_offers( const std::string& value )
{
    std::vector< extension_offer_t > offers;

    const std::vector< std::string > items = split_list( value );

    for ( size_t i = 0; i < items.size(); ++i )
    {
        const std::string& item = items[ i ];

        extension_offer_t offer;

        size_t offset = 0;

        while ( offset <= item.size() )
        {
            const size_t semicolon = item.find( ';', offset );
            const size_t end = semicolon == std::string::npos ? item.size() : semicolon;

            const std::string token = string_trim( item.substr( offset, end - offset ) );

            if ( token.empty() == false )
            {
                if ( offer.name.empty() )
                {
                    offer.name = string_to_lower( token );
                }
                else
                {
                    const size_t equals = token.find( '=' );

                    if ( equals == std::string::npos )
                    {
                        offer.params.push_back( std::make_pair( string_to_lower( token ), std::string() ) );
                    }
                    else
                    {
                        std::string param_value = string_trim( token.substr( equals + 1 ) );

                        // rfc 7692 7: a parameter value may be quoted
                        if ( param_value.size() >= 2 && param_value[ 0 ] == '"' && param_value[ param_value.size() - 1 ] == '"' )
                        {
                            param_value = param_value.substr( 1, param_value.size() - 2 );
                        }

                        offer.params.push_back( std::make_pair( string_to_lower( string_trim( token.substr( 0, equals ) ) ), param_value ) );
                    }
                }
            }

            if ( semicolon == std::string::npos )
            {
                break;
            }

            offset = semicolon + 1;
        }

        if ( offer.name.empty() == false )
        {
            offers.push_back( offer );
        }
    }

    return offers;
}

/**
 * @brief Reads a window size parameter and validates its range.
 *
 * @param value The parameter value, an empty string means the peer left the choice open.
 * @param out_bits Receives the parsed window size.
 * @return `true` when the value is absent or a valid window size between 8 and 15.
 */
static bool
parse_window_bits( const std::string& value, unsigned char& out_bits )
{
    if ( value.empty() )
    {
        return true;
    }

    for ( size_t i = 0; i < value.size(); ++i )
    {
        if ( std::isdigit( static_cast< unsigned char >( value[ i ] ) ) == 0 )
        {
            return false;
        }
    }

    const int bits = std::atoi( value.c_str() );

    // rfc 7692 7.1.2: the window size ranges from 8 to 15
    if ( bits < 8 || bits > 15 )
    {
        return false;
    }

    out_bits = static_cast< unsigned char >( bits );

    return true;
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
    if ( block == 0 )
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
c_ws_handshake::create( const char* host, const char* origin, const char* channel, const char* sub_protocols, c_byte_stream* output, std::string& out_accept_key, const ws_extensions_t* extensions )
{
    if ( output == 0 )
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

    request << "GET " << ( channel && channel[ 0 ] != '\0' ? channel : "/" ) << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "Upgrade: websocket\r\n";
    request << "Connection: Upgrade\r\n";
    request << "Sec-WebSocket-Key: " << b64 << "\r\n";
    request << "Sec-WebSocket-Version: 13\r\n";

    if ( sub_protocols && sub_protocols[ 0 ] != '\0' )
    {
        request << "Sec-WebSocket-Protocol: " << sub_protocols << "\r\n";
    }

    if ( extensions && extensions->permessage_deflate.enabled )
    {
        request << "Sec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=" << static_cast< int >( extensions->permessage_deflate.window_bits ) << "\r\n";
    }

    // rfc 6454 7.1: an origin is either a serialized origin or the literal null, never empty
    if ( origin && origin[ 0 ] != '\0' )
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
c_ws_handshake::client( const char* accept_key, const char* sub_protocols, const c_byte_stream* input, c_byte_stream* output, const ws_extensions_t* offered_extensions, ws_extensions_t* extensions, std::string& out_sub_protocol )
{
    if ( output == 0 )
    {
        return error;
    }

    if ( input == 0 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_internal_server_error, output );
        return error;
    }

    if ( input->available() == false )
    {
        return busy;
    }

    c_http http;
    const c_http::e_status status_parse = c_http::parse( input, http );

    // the handshake may arrive across several segments, wait until the field block is complete
    if ( status_parse == c_http::e_status::no_http_header )
    {
        if ( input->size() > HANDSHAKE_LIMIT )
        {
            c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
            return error;
        }

        return busy;
    }

    if ( status_parse != c_http::e_status::ok )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    {
        const size_t header_end = input->index_of( reinterpret_cast< const unsigned char* >( "\r\n\r\n" ), 4 );
        if ( header_end != c_byte_stream::npos )
        {
            input->pop( header_end + 4 );
        }
    }

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

    const http_headers_t headers = http.get_headers();

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

    if ( string_contains_case_insensitive( header_upgrade, "websocket" ) == false )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Connection| header field contains upgrade
    const std::string header_connection = headers.at( "Connection" );

    if ( string_contains_case_insensitive( header_connection, "upgrade" ) == false )
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

    // rfc 6455 4.1: the server must not name a subprotocol the client did not request
    if ( headers.find( "Sec-WebSocket-Protocol" ) != headers.end() )
    {
        const std::string confirmed = string_trim( headers.at( "Sec-WebSocket-Protocol" ) );
        const std::vector< std::string > requested = split_list( sub_protocols ? sub_protocols : "" );

        if ( std::find( requested.begin(), requested.end(), confirmed ) == requested.end() )
        {
            c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
            return error;
        }

        out_sub_protocol = confirmed;
    }

    if ( extensions )
    {
        extensions->permessage_deflate.enabled = false;
    }

    if ( headers.find( "Sec-WebSocket-Extensions" ) != headers.end() )
    {
        const std::vector< extension_offer_t > confirmed = parse_extension_offers( headers.at( "Sec-WebSocket-Extensions" ) );

        for ( size_t i = 0; i < confirmed.size(); ++i )
        {
            const extension_offer_t& agreed = confirmed[ i ];

            // rfc 6455 4.1: the server must not confirm an extension the client did not offer
            if ( agreed.name != "permessage-deflate" || !offered_extensions || !offered_extensions->permessage_deflate.enabled )
            {
                c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
                return error;
            }

            unsigned char inflate_window_bits = 15;
            unsigned char deflate_window_bits = 15;

            bool no_context_takeover = false;

            for ( size_t j = 0; j < agreed.params.size(); ++j )
            {
                const std::string& key = agreed.params[ j ].first;
                const std::string& value = agreed.params[ j ].second;

                bool usable = true;

                if ( key == "client_no_context_takeover" )
                {
                    no_context_takeover = value.empty();
                    usable = no_context_takeover;
                }
                else if ( key == "server_no_context_takeover" )
                {
                    usable = value.empty();
                }
                else if ( key == "server_max_window_bits" )
                {
                    usable = parse_window_bits( value, inflate_window_bits ) == true && value.empty() == false;
                }
                else if ( key == "client_max_window_bits" )
                {
                    usable = parse_window_bits( value, deflate_window_bits ) == true && value.empty() == false;
                }
                else
                {
                    usable = false;
                }

                if ( usable == false )
                {
                    c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
                    return error;
                }
            }

            // this implementation keeps no zlib context between messages, so a response without it is unusable
            if ( no_context_takeover == false )
            {
                c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
                return error;
            }

            if ( extensions )
            {
                extensions->permessage_deflate.enabled = true;
                extensions->permessage_deflate.window_bits = deflate_window_bits;
                extensions->permessage_deflate.deflate_window_bits = deflate_window_bits;
                extensions->permessage_deflate.inflate_window_bits = inflate_window_bits;
            }
        }
    }

    return ok;
}

c_ws_handshake::e_status
c_ws_handshake::server( const char* host, const char* origin, const char* sub_protocols, const c_byte_stream* input, c_byte_stream* output, const ws_extensions_t* server_extensions, ws_extensions_t* client_extensions, std::string& out_sub_protocol )
{
    if ( output == 0 )
    {
        return error;
    }

    if ( input == 0 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_internal_server_error, output );
        return error;
    }

    if ( input->available() == false )
    {
        return busy;
    }

    c_http http;
    const c_http::e_status status_parse = c_http::parse( input, http );

    // the handshake may arrive across several segments, wait until the field block is complete
    if ( status_parse == c_http::e_status::no_http_header )
    {
        if ( input->size() > HANDSHAKE_LIMIT )
        {
            c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
            return error;
        }

        return busy;
    }

    if ( status_parse != c_http::e_status::ok )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    {
        const size_t header_end = input->index_of( reinterpret_cast< const unsigned char* >( "\r\n\r\n" ), 4 );
        if ( header_end != c_byte_stream::npos )
        {
            input->pop( header_end + 4 );
        }
    }

    if ( http.get_version() != c_http::e_version::http_version_1_1 )
    {
        c_http::respond( c_http::e_status_code::http_status_code_http_version_not_supported, output );
        return error;
    }

    // rfc 6455 4.1: the handshake must be a http get request
    if ( http.get_method() != c_http::e_method::http_method_get )
    {
        c_http::respond( c_http::e_status_code::http_status_code_method_not_allowed, output );
        return error;
    }

    const http_headers_t headers = http.get_headers();

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

    if ( authority_matches( header_host, host ) == false )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Upgrade| header field contains websocket
    const std::string header_upgrade = headers.at( "Upgrade" );

    if ( string_contains_case_insensitive( header_upgrade, "websocket" ) == false )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Connection| header field contains upgrade
    const std::string header_connection = headers.at( "Connection" );

    if ( string_contains_case_insensitive( header_connection, "upgrade" ) == false )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
        return error;
    }

    // verify |Sec-WebSocket-Version| header field is set to supported websocket version
    const std::string version = headers.at( "Sec-WebSocket-Version" );

    if ( std::strcmp( version.c_str(), "13" ) != 0 )
    {
        // rfc 6455 4.2.2: the response must name the versions the server understands
        c_http::respond( c_http::e_status_code::http_status_code_upgrade_required, output, "Sec-WebSocket-Version: 13" );
        return error;
    }

    // rfc 6455 4.1: |Sec-WebSocket-Key| is a base64 encoded 16 byte nonce
    if ( is_base64_nonce( headers.at( "Sec-WebSocket-Key" ) ) == false )
    {
        c_http::respond( c_http::e_status_code::http_status_code_bad_request, output );
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

        // rfc 6455 10.2: the origin must match exactly, a substring test accepts lookalike hosts
        if ( string_equals_case_insensitive( origin_host( header_origin ), origin_host( origin ) ) == false )
        {
            c_http::respond( c_http::e_status_code::http_status_code_forbidden, output );
            return error;
        }
    }

    // rfc 6455 4.2.2: pick the first requested subprotocol the server supports, or none at all
    std::string accepted_protocol;

    if ( headers.find( "Sec-WebSocket-Protocol" ) != headers.end() )
    {
        const std::vector< std::string > requested = split_list( headers.at( "Sec-WebSocket-Protocol" ) );
        const std::vector< std::string > supported = split_list( sub_protocols ? sub_protocols : "" );

        for ( size_t i = 0; i < requested.size() && accepted_protocol.empty(); ++i )
        {
            for ( size_t j = 0; j < supported.size(); ++j )
            {
                if ( requested[ i ] == supported[ j ] )
                {
                    accepted_protocol = supported[ j ];
                    break;
                }
            }
        }
    }

    if ( client_extensions )
    {
        client_extensions->permessage_deflate.enabled = false;
    }

    // rfc 7692 7.1: accept the first permessage-deflate offer the server can serve
    std::string extension_response;

    if ( headers.find( "Sec-WebSocket-Extensions" ) != headers.end() && client_extensions && server_extensions && server_extensions->permessage_deflate.enabled )
    {
        const std::vector< extension_offer_t > offers = parse_extension_offers( headers.at( "Sec-WebSocket-Extensions" ) );

        for ( size_t i = 0; i < offers.size() && extension_response.empty(); ++i )
        {
            const extension_offer_t& offer = offers[ i ];

            if ( offer.name != "permessage-deflate" )
            {
                continue;
            }

            unsigned char deflate_window_bits = server_extensions->permessage_deflate.window_bits;
            unsigned char inflate_window_bits = 15;

            bool usable = true;

            for ( size_t j = 0; j < offer.params.size() && usable; ++j )
            {
                const std::string& key = offer.params[ j ].first;
                const std::string& value = offer.params[ j ].second;

                if ( key == "client_no_context_takeover" || key == "server_no_context_takeover" )
                {
                    usable = value.empty();
                }
                else if ( key == "server_max_window_bits" )
                {
                    unsigned char bits = 15;
                    usable = parse_window_bits( value, bits ) == true && value.empty() == false;

                    if ( usable && bits < deflate_window_bits )
                    {
                        deflate_window_bits = bits;
                    }
                }
                else if ( key == "client_max_window_bits" )
                {
                    usable = parse_window_bits( value, inflate_window_bits );
                }
                else
                {
                    // rfc 7692 7.1: an offer with an unknown parameter must be declined
                    usable = false;
                }
            }

            if ( usable == false )
            {
                continue;
            }

            // this implementation keeps no zlib context between messages, so both sides must not take one over
            extension_response = "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

            if ( deflate_window_bits != 15 )
            {
                std::ostringstream stream;
                stream << "; server_max_window_bits=" << static_cast< int >( deflate_window_bits );
                extension_response += stream.str();
            }

            // rfc 7692 7.1.2.2: client_max_window_bits may only be answered when the client offered it
            if ( offer.has( "client_max_window_bits" ) && inflate_window_bits != 15 )
            {
                std::ostringstream stream;
                stream << "; client_max_window_bits=" << static_cast< int >( inflate_window_bits );
                extension_response += stream.str();
            }
            else
            {
                inflate_window_bits = 15;
            }

            client_extensions->permessage_deflate.enabled = true;
            client_extensions->permessage_deflate.window_bits = deflate_window_bits;
            client_extensions->permessage_deflate.deflate_window_bits = deflate_window_bits;
            client_extensions->permessage_deflate.inflate_window_bits = inflate_window_bits;
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

    if ( accepted_protocol.empty() == false )
    {
        *output << "Sec-WebSocket-Protocol: " << accepted_protocol.c_str() << "\r\n";

        out_sub_protocol = accepted_protocol;
    }

    if ( extension_response.empty() == false )
    {
        *output << "Sec-WebSocket-Extensions: " << extension_response.c_str() << "\r\n";
    }

    *output << "\r\n";

    return ok;
}
