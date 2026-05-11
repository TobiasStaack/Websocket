#pragma once

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#include <stdbool.h>
#endif

#define WS_EVENT_OPEN "open"
#define WS_EVENT_CLOSE "close"
#define WS_EVENT_FRAME "frame"
#define WS_EVENT_ERROR "error"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @enum e_ws_status
 * @brief Defines the status codes for WebSocket operations.
 *
 * This enum represents different status codes that can be returned by
 * WebSocket operations to indicate success, error, or a busy state.
 */
#ifdef __cplusplus
enum e_ws_status : unsigned char
#else
typedef enum e_ws_status
#endif
{
    status_ok = 0x0, /**< @brief Operation was successful. */
    status_error = 0x1, /**< @brief An error occurred during the operation. */
    status_busy = 0x2 /**< @brief The socket is currently busy. */
}
#ifdef __cplusplus
;
#else
e_ws_status;
#endif

/**
 * @enum e_ws_mode
 * @brief Defines the security mode for WebSocket communication.
 *
 * This enum is used to set or indicate whether the WebSocket communication
 * is secured (SSL/TLS) or unsecured.
 */
#ifdef __cplusplus
enum e_ws_mode : unsigned char
#else
typedef enum e_ws_mode
#endif
{
    mode_unsecured = 0x0, /**< @brief Unsecured mode. */
    mode_secured = 0x1 /**< @brief Secured mode (SSL). */
}
#ifdef __cplusplus
;
#else
e_ws_mode;
#endif

/**
 * @enum e_ws_endpoint_type
 * @brief Defines the type of WebSocket endpoint.
 *
 * This enum is used to specify whether the WebSocket endpoint is acting
 * as a server or a client.
 */
#ifdef __cplusplus
enum e_ws_endpoint_type : unsigned char
#else
typedef enum e_ws_endpoint_type
#endif
{
    endpoint_server = 0x0, /**< @brief The endpoint is a server. */
    endpoint_client = 0x1 /**< @brief The endpoint is a client. */
}
#ifdef __cplusplus
;
#else
e_ws_endpoint_type;
#endif

/**
 * @enum e_ws_closure_status
 * @brief RFC6455 Status codes indicating a reason for closure.
 *
 * This enum defines status codes as defined in RFC6455 to indicate a reason for closure.
 */
#ifdef __cplusplus
enum e_ws_closure_status : int
#else
typedef enum e_ws_closure_status
#endif
{
    closure_normal = 1000, /**< 1000 indicates a normal closure, meaning that the purpose for which the connection was established has been fulfilled. */
    closure_going_away = 1001, /**< 1001 indicates that an endpoint is "going away", such as a server going down or a browser having navigated away from a page. */
    closure_protocol_error = 1002, /**< 1002 indicates that an endpoint is terminating the connection due to a protocol error. */
    closure_unsupported_data = 1003, /**< 1003 indicates that an endpoint is terminating the connection because it has received a type of data it cannot accept. */
    closure_reserved_1004 = 1004, /**< Reserved for future use. */
    closure_no_status_received = 1005, /**< 1005 is a reserved value to indicate that no status code was present. */
    closure_abnormal = 1006, /**< 1006 is reserved to indicate the connection was closed abnormally without sending or receiving a Close control frame. */
    closure_invalid_data = 1007, /**< 1007 indicates the connection is terminated due to data inconsistency, e.g., non-UTF-8 data within a text message. */
    closure_policy_violation = 1008, /**< 1008 indicates the connection is terminated due to a policy violation. */
    closure_message_too_big = 1009, /**< 1009 indicates the connection is terminated because the message was too large to process. */
    closure_missing_extension = 1010, /**< 1010 indicates the client terminated the connection due to missing required extensions in the handshake response. */
    closure_internal_error = 1011, /**< 1011 indicates the server terminated the connection due to an unexpected condition preventing fulfillment of the request. */
    closure_tls_handshake_failed = 1015 /**< 1015 is reserved to indicate connection closure due to a failed TLS handshake, such as an unverifiable server certificate. */
}
#ifdef __cplusplus
;
#else
e_ws_closure_status;
#endif

/**
 * @brief WebSocket extensions configuration structure.
 *
 * This structure holds configuration parameters for WebSocket extensions.
 */
typedef struct
{
    /**
     * @brief Configuration for the "permessage-deflate" extension.
     */
    struct
    {
        /**
         * @brief Flag indicating if the permessage-deflate extension is enabled.
         *
         * Set to `true` if the extension is enabled, otherwise `false`.
         */
        bool enabled;

        /**
         * @brief Window size bits for the permessage-deflate extension.
         *
         * Specifies the window size, where higher values allow for larger
         * compression windows and better compression ratios but require more memory.
         */
        unsigned char window_bits;
    } permessage_deflate;
} ws_extensions_t;

/**
 * @struct ws_settings_t
 * @brief WebSocket settings
 *
 * This structure holds various configuration settings for a WebSocket
 * connection, including endpoint type, security options, timeouts, and
 * SSL/TLS credentials.
 */
typedef struct
{
    e_ws_endpoint_type endpoint; /**< @brief Type of the WebSocket endpoint (client or server). */

    e_ws_mode mode; /**< @brief Operation mode (secured or unsecured). */

    unsigned int read_timeout; /**< @brief Read timeout in milliseconds. Defines how long to wait for reading data. */
    unsigned int poll_timeout; /**< @brief Poll timeout in milliseconds. Defines how long to wait during polling operations. */

    char *ssl_seed; /**< @brief Seed for the SSL/TLS random number generator. */
    char *ssl_ca_cert; /**< @brief CA certificate used for SSL/TLS verification. */
    char *ssl_own_cert; /**< @brief Own certificate for the WebSocket connection, used by clients or servers. */
    char *ssl_private_key; /**< @brief Private key associated with the own certificate, used for SSL/TLS encryption. */

    size_t fd_limit; /**< @brief Maximum number of file descriptors that the WebSocket should manage. */

    char *host; /**< @brief Hostname or IP address of the WebSocket server. This field must be filled. */
    char *allowed_origin; /**< @brief Allowed origin for WebSocket connections (used in CORS scenarios). This field can be NULL. */

    unsigned int ping_interval; /**< @brief Interval in milliseconds between WebSocket ping messages to maintain connection. */
    unsigned int ping_timeout; /**< @brief Timeout in milliseconds to wait for a pong message after sending a ping. */

    size_t message_limit; /**< @brief Message limit in bytes. (default 4mb) */

    bool auto_mask_frame; /** @brief Enable/Disable automatic frame masking with random generated secret. (default enabled) */

    ws_extensions_t extensions; /** @brief configurable Websocket extensions */
} ws_settings_t;

/**
 * @brief Initializes the WebSocket settings structure with default values.
 *
 * This function sets the default values for the WebSocket settings, ensuring
 * that the structure is properly initialized before use. The default values
 * include:
 * - `endpoint` is set to `endpoint_server`.
 * - `mode` is set to `mode_unsecured`.
 * - Timeouts (read and poll) are set to 0.
 * - SSL/TLS fields (seed, certificates, private key) are set to NULL.
 * - `fd_limit` is set to 0.
 * - `host` and `allowed_origin` are set to NULL.
 * - `ping_interval` is set to 60 seconds (60000 ms).
 * - `ping_timeout` is set to 30 seconds (30000 ms).
 *
 * @param[in,out] settings Pointer to the WebSocket settings structure to initialize.
 */
#ifdef __cplusplus
inline void ws_settings_init( ws_settings_t *settings )
#else
static inline void ws_settings_init( ws_settings_t *settings )
#endif
{
#ifdef __cplusplus
    settings->endpoint = e_ws_endpoint_type::endpoint_server;
    settings->mode = e_ws_mode::mode_unsecured;
#else
    settings->endpoint = endpoint_server;
    settings->mode = mode_unsecured;
#endif

    settings->read_timeout = 0;
    settings->poll_timeout = 0;

    settings->ssl_seed = NULL;
    settings->ssl_ca_cert = NULL;
    settings->ssl_own_cert = NULL;
    settings->ssl_private_key = NULL;

    settings->fd_limit = 0;

    settings->host = NULL;
    settings->allowed_origin = NULL;

    settings->ping_interval = 60 * 1000;
    settings->ping_timeout = 30 * 1000;

    settings->message_limit = 4 * 1024 * 1024; // 4mb in bytes

    settings->auto_mask_frame = true;

    settings->extensions.permessage_deflate.enabled = false;
    settings->extensions.permessage_deflate.window_bits = 15;
}

/**
 * @brief Frees the dynamically allocated memory in the WebSocket settings structure.
 *
 * This function safely frees any memory that was allocated for the WebSocket
 * settings structure, specifically for the SSL/TLS fields (`ssl_seed`, `ssl_ca_cert`,
 * `ssl_own_cert`, `ssl_private_key`), the `host`, and `allowed_origin` fields.
 * After freeing the memory, the respective pointers are set to NULL to prevent
 * dangling pointers.
 *
 * @param[in,out] settings Pointer to the WebSocket settings structure to destroy.
 */
#ifdef __cplusplus
inline void ws_settings_destroy( ws_settings_t *settings )
#else
static inline void ws_settings_destroy( ws_settings_t *settings )
#endif
{
    if ( settings->ssl_seed )
    {
#ifdef __cplusplus
        std::free( settings->ssl_seed );
#else
        free( settings->ssl_seed );
#endif
        settings->ssl_seed = NULL;
    }

    if ( settings->ssl_ca_cert )
    {
#ifdef __cplusplus
        std::free( settings->ssl_ca_cert );
#else
        free( settings->ssl_ca_cert );
#endif
        settings->ssl_ca_cert = NULL;
    }

    if ( settings->ssl_own_cert )
    {
#ifdef __cplusplus
        std::free( settings->ssl_own_cert );
#else
        free( settings->ssl_own_cert );
#endif
        settings->ssl_own_cert = NULL;
    }

    if ( settings->ssl_private_key )
    {
#ifdef __cplusplus
        std::free( settings->ssl_private_key );
#else
        free( settings->ssl_private_key );
#endif
        settings->ssl_private_key = 0;
    }

    if ( settings->host )
    {
#ifdef __cplusplus
        std::free( settings->host );
#else
        free( settings->host );
#endif
        settings->host = NULL;
    }

    if ( settings->allowed_origin )
    {
#ifdef __cplusplus
        std::free( settings->allowed_origin );
#else
        free( settings->allowed_origin );
#endif
        settings->allowed_origin = NULL;
    }
}

#ifdef __cplusplus
}
#endif
