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
#include <websocket/core/http.h>

#include <map>
#include <string>

#include <regex>

static const std::map< std::string, c_http::e_method > methods = {
    { "GET", c_http::e_method::http_method_get },
    { "HEAD", c_http::e_method::http_method_head },
    { "POST", c_http::e_method::http_method_post },
    { "PUT", c_http::e_method::http_method_put },
    { "DELETE", c_http::e_method::http_method_delete },
    { "CONNECT", c_http::e_method::http_method_connect },
    { "OPTIONS", c_http::e_method::http_method_options },
    { "TRACE", c_http::e_method::http_method_trace },
    { "PATCH", c_http::e_method::http_method_patch }
};

static const std::map< std::string, c_http::e_version > versions = {
    { "HTTP/1.0", c_http::e_version::http_version_1_0 },
    { "HTTP/1.1", c_http::e_version::http_version_1_1 },
    { "HTTP/2", c_http::e_version::http_version_2 },
    { "HTTP/3", c_http::e_version::http_version_3 }
};

static const std::map< c_http::e_status_code, std::string > status_code_reasons = {
    { c_http::e_status_code::http_status_code_continue, "Continue" },
    { c_http::e_status_code::http_status_code_switching_protocols, "Switching Protocols" },
    { c_http::e_status_code::http_status_code_processing, "Processing" },
    { c_http::e_status_code::http_status_code_early_hints, "Early Hints" },
    { c_http::e_status_code::http_status_code_ok, "OK" },
    { c_http::e_status_code::http_status_code_created, "Created" },
    { c_http::e_status_code::http_status_code_accepted, "Accepted" },
    { c_http::e_status_code::http_status_code_non_authoritative_information, "Non-Authoritative Information" },
    { c_http::e_status_code::http_status_code_no_content, "No Content" },
    { c_http::e_status_code::http_status_code_reset_content, "Reset Content" },
    { c_http::e_status_code::http_status_code_partial_content, "Partial Content" },
    { c_http::e_status_code::http_status_code_multiple_choices, "Multiple Choices" },
    { c_http::e_status_code::http_status_code_moved_permanently, "Moved Permanently" },
    { c_http::e_status_code::http_status_code_found, "Found" },
    { c_http::e_status_code::http_status_code_see_other, "See Other" },
    { c_http::e_status_code::http_status_code_not_modified, "Not Modified" },
    { c_http::e_status_code::http_status_code_use_proxy, "Use Proxy" },
    { c_http::e_status_code::http_status_code_temporary_redirect, "Temporary Redirect" },
    { c_http::e_status_code::http_status_code_permanent_redirect, "Permanent Redirect" },
    { c_http::e_status_code::http_status_code_bad_request, "Bad Request" },
    { c_http::e_status_code::http_status_code_unauthorized, "Unauthorized" },
    { c_http::e_status_code::http_status_code_payment_required, "Payment Required" },
    { c_http::e_status_code::http_status_code_forbidden, "Forbidden" },
    { c_http::e_status_code::http_status_code_not_found, "Not Found" },
    { c_http::e_status_code::http_status_code_method_not_allowed, "Method Not Allowed" },
    { c_http::e_status_code::http_status_code_not_acceptable, "Not Acceptable" },
    { c_http::e_status_code::http_status_code_proxy_authentication_required, "Proxy Authentication Required" },
    { c_http::e_status_code::http_status_code_request_timeout, "Request Timeout" },
    { c_http::e_status_code::http_status_code_internal_server_error, "Internal Server Error" },
    { c_http::e_status_code::http_status_code_not_implemented, "Not Implemented" },
    { c_http::e_status_code::http_status_code_bad_gateway, "Bad Gateway" },
    { c_http::e_status_code::http_status_code_service_unavailable, "Service Unavailable" },
    { c_http::e_status_code::http_status_code_gateway_timeout, "Gateway Timeout" },
    { c_http::e_status_code::http_status_code_http_version_not_supported, "HTTP Version Not Supported" }
};

c_http::
    c_http()
{
    method = e_method::http_method_unknown;
    version = e_version::http_version_unknown;
    status_code = e_status_code::http_status_code_ok;
}

c_http::~c_http()
{
    body.close();
}

c_http::e_method
c_http::get_method() const
{
    return method;
}

const std::string &
c_http::get_resource() const
{
    return resource;
}

c_http::e_version
c_http::get_version() const
{
    return version;
}


c_http::e_status_code
c_http::get_status_code() const
{
    return status_code;
}

const std::string &
c_http::get_reason() const
{
    return reason;
}

const std::map< std::string, std::string > &
c_http::get_headers() const
{
    return headers;
}

const c_byte_stream &
c_http::get_body() const
{
    return body;
}

c_http::e_status
c_http::parse( const c_byte_stream *input, c_http &http )
{
    if ( !input || !input->available() )
    {
        return e_status::error;
    }

    size_t pos = 0, offset = 0;

    auto method = e_method::http_method_unknown;
    std::string resource = "/";
    auto version = e_version::http_version_unknown;
    auto status_code = e_status_code::http_status_code_ok;
    std::string reason;
    std::map< std::string, std::string > headers;
    c_byte_stream body;

    // determinate header length
    const size_t header_len = input->index_of( reinterpret_cast< const unsigned char * >( "\r\n\r\n" ), 4 );
    if ( header_len == c_byte_stream::npos )
    {
        return e_status::no_http_header;
    }

    // meta data
    if ( ( pos = input->index_of( reinterpret_cast< const unsigned char * >( "\r\n" ), 2, offset, header_len + 2 ) ) != c_byte_stream::npos )
    {
        const auto begin = reinterpret_cast< const char * >( input->pointer( offset ) );
        const char *end = begin + pos;

        const std::regex rgx( R"(^(?:(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+)?(?:([^\s]+)\s+)?HTTP/(\d+\.\d+)(?:\s+(\d{3})\s+([^\r\n]*))?$)" );

        std::match_results< const char * > matches;

        if ( !std::regex_match( begin, end, matches, rgx ) )
        {
            return e_status::no_http_format;
        }

        if ( matches[ 1 ].matched )
        {
            if ( methods.find( matches[ 1 ].str() ) != methods.end() )
            {
                method = methods.at( matches[ 1 ].str() );
            }
        }

        if ( matches[ 2 ].matched )
        {
            resource = matches[ 2 ].str();
        }

        if ( !matches[ 3 ].matched )
        {
            return e_status::no_http_version;
        }

        std::string tmp( "HTTP/" );
        tmp += matches[ 3 ].str();

        if ( versions.find( tmp ) != versions.end() )
        {
            version = versions.at( tmp );
        }

        if ( matches[ 4 ].matched )
        {
            int ival = 0;

            try
            {
                ival = std::stoi( matches[ 4 ].str() );
            }
            catch ( ... )
            {
                return e_status::no_valid_http_status_code;
            }

            status_code = static_cast< e_status_code >( ival );
        }

        if ( matches[ 5 ].matched )
        {
            reason = matches[ 5 ].str();
        }

        offset = pos + 1;
    }
    else
    {
        return e_status::no_http_header;
    }

    // header fields
    while ( ( pos = input->index_of( reinterpret_cast< const unsigned char * >( "\r\n" ), 2, offset, header_len + 2 ) ) != c_byte_stream::npos )
    {
        const size_t pos_col = input->index_of( ':', offset, pos );

        if ( pos_col == c_byte_stream::npos )
        {
            return e_status::error;
        }

        std::string key;
        key.resize( pos_col - offset );

        std::string value;
        value.resize( pos - pos_col );

        if ( input->copy( reinterpret_cast< unsigned char * >( &key[ 0 ] ), pos_col - offset, nullptr, offset ) != c_byte_stream::e_status::ok )
        {
            return e_status::error;
        }

        if ( input->copy( reinterpret_cast< unsigned char * >( &value[ 0 ] ), pos - pos_col, nullptr, pos_col + 1 ) != c_byte_stream::e_status::ok )
        {
            return e_status::error;
        }

        auto trim = []( const std::string &s ) -> std::string
        {
            const size_t start = s.find_first_not_of( " \t\r\n" );
            const size_t end = s.find_last_not_of( " \t\r\n" );
            return start == std::string::npos || end == std::string::npos ? "" : s.substr( start, end - start + 1 );
        };

        key = trim( key );
        value = trim( value );

        headers.emplace( key, value );

        offset = pos + 1;
    }

    // body
    const size_t body_len = input->size() - header_len - 4;

    if ( body_len != 0 )
    {
        body.resize( body_len );
        if ( input->copy( body.pointer( 0 ), body_len, nullptr, header_len + 4 ) != c_byte_stream::e_status::ok )
        {
            return e_status::error;
        }
    }

    http.method = method;
    http.resource = std::move( resource );
    http.version = version;
    http.status_code = status_code;
    http.reason = std::move( reason );
    http.headers = std::move( headers );
    http.body = std::move( body );

    return e_status::ok;
}

void
c_http::respond( e_status_code status_code, c_byte_stream *output )
{
    if ( !output )
    {
        return;
    }

    std::string reason;

    if ( status_code_reasons.find( status_code ) != status_code_reasons.end() )
    {
        reason = status_code_reasons.at( status_code );
    }

    *output << "HTTP/1.1 " << static_cast< unsigned int >( status_code ) << " " << reason.c_str() << "\r\n";
    *output << "Content-Length: 0\r\n";
    *output << "Connection: close\r\n";
    *output << "\r\n";
}
