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
#pragma once


#include <websocket/core/byte_stream.h>

#include <map>
#include <string>

/** \cond */

/**
 * @brief Case insensitive ordering for http field names as required by RFC 7230 section 3.2.
 */
struct http_field_less
{
    /**
     * @brief Orders two field names ignoring their case.
     *
     * @param[in] lhs The left field name.
     * @param[in] rhs The right field name.
     * @return `true` when lhs sorts before rhs.
     */
    bool
    operator()( const std::string &lhs, const std::string &rhs ) const;
};

typedef std::map< std::string, std::string, http_field_less > http_headers_t;

class c_http final
{
public:
    /**
     * @enum e_method
     * @brief Enum class representing HTTP request methods.
     *
     * This enum defines the various HTTP request methods such as GET, POST, PUT, DELETE, etc.
     * Each method is assigned a unique `uint8_t` value for efficient storage and comparison.
     */
    enum class e_method : unsigned char
    {
        http_method_unknown = 0x0, /**< Unknown HTTP method. */
        http_method_get = 0x1, /**< HTTP GET method, used to retrieve data from the server. */
        http_method_head = 0x2, /**< HTTP HEAD method, used to retrieve only the headers of a resource. */
        http_method_post = 0x3, /**< HTTP POST method, used to send data to the server to create or modify a resource. */
        http_method_put = 0x4, /**< HTTP PUT method, used to send data to the server to update a resource. */
        http_method_delete = 0x5, /**< HTTP DELETE method, used to delete a resource from the server. */
        http_method_connect = 0x6, /**< HTTP CONNECT method, used to establish a network connection to a server. */
        http_method_options = 0x7, /**< HTTP OPTIONS method, used to describe the communication options for the target resource. */
        http_method_trace = 0x8, /**< HTTP TRACE method, used to perform a diagnostic trace of the request. */
        http_method_patch = 0x9 /**< HTTP PATCH method, used to apply partial modifications to a resource. */
    };

    /**
     * @enum e_version
     * @brief Enum class representing HTTP versions.
     *
     * This enum defines the various versions of HTTP supported, including HTTP/1.0, HTTP/1.1, HTTP/2, and HTTP/3.
     * Each version is assigned a unique `uint8_t` value.
     */
    enum class e_version : unsigned char
    {
        http_version_unknown = 0, /**< Unknown HTTP version. */
        http_version_1_0 = 1, /**< HTTP/1.0 - The first version of HTTP, introduced basic communication. */
        http_version_1_1 = 2, /**< HTTP/1.1 - Introduced persistent connections and other enhancements. */
        http_version_2 = 3, /**< HTTP/2 - Introduced multiplexing and header compression for improved performance. */
        http_version_3 = 4 /**< HTTP/3 - Introduced QUIC protocol for faster and more secure connections. */
    };

    /**
     * @enum e_status_code
     * @brief Enum class representing HTTP status codes.
     */
    enum class e_status_code : unsigned int
    {
        // 1xx informational
        http_status_code_continue = 100, /**< The server has received the request headers and the client should proceed to send the request body. */
        http_status_code_switching_protocols = 101, /**< The requester has asked the server to switch protocols and the server is acknowledging that it will do so. */
        http_status_code_processing = 102, /**< The server has received and is processing the request, but no response is available yet. */
        http_status_code_early_hints = 103, /**< A hint to the client about preloading resources while the server is processing the request. */

        // 2xx success
        http_status_code_ok = 200, /**< Standard response for successful HTTP requests. */
        http_status_code_created = 201, /**< The request has been fulfilled and resulted in a new resource being created. */
        http_status_code_accepted = 202, /**< The request has been accepted for processing, but the processing has not been completed. */
        http_status_code_non_authoritative_information = 203, /**< The server successfully processed the request, but is returning information from another source. */
        http_status_code_no_content = 204, /**< The server successfully processed the request, but is not returning any content. */
        http_status_code_reset_content = 205, /**< The server successfully processed the request, but requires the requester to reset the document view. */
        http_status_code_partial_content = 206, /**< The server is delivering only part of the resource due to a range header sent by the client. */
        http_status_code_multi_status = 207, /**< The message body that follows is by default an XML message and can contain multiple separate responses. */
        http_status_code_already_reported = 208, /**< The members of a DAV binding have already been enumerated in a previous reply to this request. */
        http_status_code_im_used = 226, /**< The server has fulfilled a GET request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance. */

        // 3xx redirection
        http_status_code_multiple_choices = 300, /**< Indicates multiple options for the resource from which the client may choose. */
        http_status_code_moved_permanently = 301, /**< This and all future requests should be directed to the given URI. */
        http_status_code_found = 302, /**< The resource is temporarily under a different URI. */
        http_status_code_see_other = 303, /**< The response to the request can be found under another URI using a GET method. */
        http_status_code_not_modified = 304, /**< Indicates that the resource has not been modified since the version specified by the request headers. */
        http_status_code_use_proxy = 305, /**< The requested resource is only available through a proxy, the address for which is provided in the response. */
        http_status_code_temporary_redirect = 307, /**< The resource is temporarily under a different URI, and the client should continue to use the original URI for future requests. */
        http_status_code_permanent_redirect = 308, /**< The resource is permanently under a different URI. */

        // 4xx client errors
        http_status_code_bad_request = 400, /**< The server cannot or will not process the request due to a client error. */
        http_status_code_unauthorized = 401, /**< Authentication is required and has failed or has not been provided. */
        http_status_code_payment_required = 402, /**< Reserved for future use. */
        http_status_code_forbidden = 403, /**< The client does not have access rights to the content. */
        http_status_code_not_found = 404, /**< The server can not find the requested resource. */
        http_status_code_method_not_allowed = 405, /**< The request method is known by the server but is not supported by the target resource. */
        http_status_code_not_acceptable = 406, /**< The requested resource is capable of generating only content not acceptable according to the Accept headers. */
        http_status_code_proxy_authentication_required = 407, /**< The client must first authenticate itself with the proxy. */
        http_status_code_request_timeout = 408, /**< The server timed out waiting for the request. */
        http_status_code_conflict = 409, /**< The request could not be completed due to a conflict with the current state of the resource. */
        http_status_code_gone = 410, /**< The resource requested is no longer available and will not be available again. */
        http_status_code_length_required = 411, /**< The request did not specify the length of its content, which is required by the requested resource. */
        http_status_code_precondition_failed = 412, /**< The server does not meet one of the preconditions specified in the request. */
        http_status_code_payload_too_large = 413, /**< The request is larger than the server is willing or able to process. */
        http_status_code_uri_too_long = 414, /**< The URI provided was too long for the server to process. */
        http_status_code_unsupported_media_type = 415, /**< The request entity has a media type which the server or resource does not support. */
        http_status_code_range_not_satisfiable = 416, /**< The client has asked for a portion of the file, but the server cannot supply that portion. */
        http_status_code_expectation_failed = 417, /**< The server cannot meet the requirements of the Expect request-header field. */
        http_status_code_im_a_teapot = 418, /**< I'm a teapot (Easter egg defined in RFC 2324). */
        http_status_code_misdirected_request = 421, /**< The request was directed at a server that is not able to produce a response. */
        http_status_code_unprocessable_entity = 422, /**< The request was well-formed but was unable to be followed due to semantic errors. */
        http_status_code_locked = 423, /**< The resource that is being accessed is locked. */
        http_status_code_failed_dependency = 424, /**< The request failed due to failure of a previous request. */
        http_status_code_too_early = 425, /**< Indicates that the server is unwilling to risk processing a request that might be replayed. */
        http_status_code_upgrade_required = 426, /**< The client should switch to a different protocol. */
        http_status_code_precondition_required = 428, /**< The origin server requires the request to be conditional. */
        http_status_code_too_many_requests = 429, /**< The user has sent too many requests in a given amount of time. */
        http_status_code_request_header_fields_too_large = 431, /**< The server is unwilling to process the request because its header fields are too large. */
        http_status_code_unavailable_for_legal_reasons = 451, /**< The user-agent requested a resource that cannot legally be provided. */

        // 5xx server errors
        http_status_code_internal_server_error = 500, /**< The server encountered an unexpected condition that prevented it from fulfilling the request. */
        http_status_code_not_implemented = 501, /**< The server does not support the functionality required to fulfill the request. */
        http_status_code_bad_gateway = 502, /**< The server, while acting as a gateway or proxy, received an invalid response from the upstream server. */
        http_status_code_service_unavailable = 503, /**< The server is currently unavailable (because it is overloaded or down for maintenance). */
        http_status_code_gateway_timeout = 504, /**< The server, while acting as a gateway or proxy, did not receive a timely response from the upstream server. */
        http_status_code_http_version_not_supported = 505, /**< The server does not support the HTTP protocol version used in the request. */
        http_status_code_variant_also_negotiates = 506, /**< Transparent content negotiation for the request results in a circular reference. */
        http_status_code_insufficient_storage = 507, /**< The server is unable to store the representation needed to complete the request. */
        http_status_code_loop_detected = 508, /**< The server detected an infinite loop while processing the request. */
        http_status_code_not_extended = 510, /**< Further extensions to the request are required for the server to fulfill it. */
        http_status_code_network_authentication_required = 511 /**< The client needs to authenticate to gain network access. */
    };

    /**
     * @brief Enum class representing HTTP parsing statuses.
     *
     * Indicates the result of HTTP parsing operations, providing detailed
     * error codes for specific parsing failures.
     */
    enum class e_status : unsigned char
    {
        ok = 0x0, /**< Parsing succeeded with no errors. */
        error = 0x1, /**< A general error occurred during parsing. */
        no_http_format = 0x2, /**< No valid HTTP request or response format detected. */
        no_http_header = 0x3, /**< The HTTP header is incomplete (missing CRLF or other expected components). */
        no_http_version = 0x4, /**< The HTTP version is missing or not specified. */
        no_valid_http_status_code = 0x5 /**< The status code in the HTTP message is not a valid integer. */
    };

private:
    e_method method;           /**< @brief Request method, unknown for responses. */
    std::string resource;      /**< @brief Requested resource, defaults to "/". */
    e_version version;         /**< @brief Protocol version of the message. */
    e_status_code status_code; /**< @brief Status code, only meaningful for responses. */
    std::string reason;        /**< @brief Reason phrase accompanying the status code. */
    http_headers_t headers;    /**< @brief Header fields, matched case insensitively. */
    c_byte_stream body;        /**< @brief Message body following the field block. */

public:
    /**
     * @brief Creates an empty message with unknown method and version.
     */
    c_http();

    /**
     * @brief Releases the message body.
     */
    ~
    c_http();

    /**
     * @brief Retrieves the request method.
     *
     * @return The method, `http_method_unknown` for responses.
     */
    e_method
    get_method() const;

    /**
     * @brief Retrieves the requested resource.
     *
     * @return The resource path, "/" when the message carried none.
     */
    const std::string &
    get_resource() const;

    /**
     * @brief Retrieves the protocol version.
     *
     * @return The version, `http_version_unknown` when it could not be parsed.
     */
    e_version
    get_version() const;

    /**
     * @brief Retrieves the response status code.
     *
     * @return The status code, meaningful only for responses.
     */
    e_status_code
    get_status_code() const;

    /**
     * @brief Retrieves the reason phrase.
     *
     * @return The reason phrase, empty when the message carried none.
     */
    const std::string &
    get_reason() const;

    /**
     * @brief Retrieves the header fields.
     *
     * Field names are compared case insensitively and repeated fields are joined
     * into one comma separated value, as RFC 7230 section 3.2.2 prescribes.
     *
     * @return The header fields of the message.
     */
    const http_headers_t &
    get_headers() const;

    /**
     * @brief Retrieves the message body.
     *
     * @return The bytes following the field block.
     */
    const c_byte_stream &
    get_body() const;

    /**
     * @brief Parses a request or response from a byte stream.
     *
     * The stream is left untouched, the caller decides when to consume it.
     *
     * @param[in] input Stream holding the message.
     * @param[out] http Receives the parsed message.
     * @return `ok` on success, `no_http_header` while the field block is still incomplete,
     *         or another status describing what failed.
     */
    static e_status
    parse( const c_byte_stream *input, c_http &http );

    /**
     * @brief Writes a minimal response with the given status code.
     *
     * @param[in] status_code The status code to send.
     * @param[out] output Receives the response bytes.
     * @param[in] extra_field Optional additional field line without the trailing CRLF, may be NULL.
     */
    static void
    respond( e_status_code status_code, c_byte_stream *output, const char *extra_field = 0 );
};
/** \endcond */
