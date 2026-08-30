/**
 * @mainpage Websocket Library
 *
 * @section intro_sec Introduction
 *
 * This WebSocket Library offers a straightforward C++ and C API. It can be utilized as either a shared/static library or included directly in projects that support at least C++11. The library includes an example demonstrating how to set up either a server or client endpoint.
 *
 * It facilitates WebSocket communication in both secure and unsecured modes, making it suitable for real-time, web-based applications.
 *
 * @section features_sec Features
 * - Support for both client and server endpoints
 * - Availability of C and C++ APIs
 * - Support for both secure (SSL) and unsecured communication
 * - Ability to process WebSocket frames, including encoding and decoding them
 *
 * @section usage_sec Usage
 *
 * This example illustrates how to use the WebSocket library by referring to the example implementation in
 * the file `example.cpp`. In this file, you will find:
 *
 * - Initialize WebSocket settings with `ws_settings_init` and clean up using `ws_settings_destroy`.
 * - Create a WebSocket context using the `c_websocket` class or, for the C API, use `websocket_create` and `websocket_destroy` for cleanup.
 * - Manage connections by handling events such as `on_open`, `on_close`, `on_frame`, and `on_error` with the `c_websocket::on` method or `websocket_on` for the C API.
 * - Set up the WebSocket using the `c_websocket::setup` method or `websocket_setup` for the C API.
 * - Bind to an interface with `c_websocket::bind` or `websocket_bind` for the C API.
 * - Open a connection to an endpoint using `c_websocket::open` or `websocket_open` for the C API.
 * - In the main loop, call `c_websocket::operate` or `websocket_operate` for the C API until it returns false.
 * - Create frames using the `c_ws_frame` class or `websocket_frame_create` for the C API, and clean up with `websocket_frame_destroy`.
 * - Push payloads to frames with the `c_ws_frame::push` method or `websocket_frame_push` for the C API.
 * - Emit frames using the `c_websocket::emit` method or `websocket_frame_emit` for the C API.
 *
 * For a complete implementation, please refer to the `example.cpp` file.
 *
 * @section license_sec License
 *
 * This software is provided under the MIT License:
 * \code
 * MIT License
 *
 * Copyright (c) 2024 Tobias Staack
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * \endcode
 */

#pragma once

#include <websocket/api/websocket_api.h>

#include <websocket/defs/socketDefs.h>

#include <websocket/core/frame.h>

/**
 * @brief Websocket skeleton
 *
 * RFC6455
 *
 * The `c_websocket` class provides an interface for handling WebSocket
 * communication. It allows binding to IP addresses and ports, opening
 * file descriptors, emitting frames, and registering event listeners.
 * This class acts as a base for implementing WebSocket servers or clients,
 * facilitating real-time, bidirectional communication over a single TCP
 * connection.
 *
 * ## Features
 * - **Binding**: Bind to a specific IP address and port to listen for incoming
 *   WebSocket connections.
 * - **Opening Connections**: Open a connection to a specified host and port.
 * - **Emitting Frames**: Send WebSocket frames through a specified file descriptor.
 * - **Event Handling**: Register callback functions to respond to various WebSocket
 *   events, such as connection opening, closing, frame reception, and error handling.
 *
 * ## Usage
 *
 * To use the `c_websocket` class:
 * 1. Create an instance of the class.
 * 2. Bind to a desired IP address and port using the `bind` method.
 * 3. Open a connection to a remote WebSocket server using the `open` method.
 * 4. Register event handlers using the `on` method to handle WebSocket events.
 * 5. Call the `operate` method in a loop to manage communication and event processing.
 * 6. Use the `emit` method to send frames to connected clients or servers.
 * 7. Close the connection with the `close` method when done.
 *
 * This interface can be implemented by derived classes to provide specific
 * functionalities for different WebSocket applications.
 *
 * @see e_ws_status
 * @see t_event_open
 * @see t_event_close
 * @see t_event_frame
 * @see t_event_error
 */
class WEBSOCKET_API c_websocket
{
    /**
     * @brief Function pointer type for handling the WebSocket `open` event.
     *
     * This function pointer can be used to listen for WebSocket connection
     * openings in the C API. It is triggered when the WebSocket handshake is
     * successfully completed.
     *
     * @param[in] ctx The address of the current WebSocket context.
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] addr The address of the connected peer.
     */
    typedef void ( *t_event_open )( void *ctx, int fd, const char *addr );

    /**
     * @brief Function pointer type for handling the WebSocket `close` event.
     *
     * This function pointer can be used to listen for WebSocket connection
     * closures in the C API. It is triggered when the WebSocket connection
     * is closed by either the server or the client.
     *
     * @param[in] ctx The address of the current WebSocket context.
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] status The status code indicating the closure reason.
     */
    typedef void ( *t_event_close )( void *ctx, int fd, e_ws_closure_status status );

    /**
     * @brief Function pointer type for handling WebSocket frame reception.
     *
     * This function pointer can be used to listen for WebSocket frame
     * reception in the C API. It is triggered when a WebSocket frame with
     * text or binary data is received.
     *
     * @param[in] ctx The address of the current WebSocket context.
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] opcode The opcode of the WebSocket frame, indicating its type (e.g., text, binary).
     * @param[in] payload A pointer to the payload data received.
     * @param[in] size The size of the payload in bytes.
     */
    typedef void ( *t_event_frame )( void *ctx, int fd, e_ws_frame_opcode opcode, unsigned char *payload, size_t size );

    /**
     * @brief Function pointer type for handling WebSocket errors.
     *
     * This function pointer can be used to listen for WebSocket errors in
     * the C API. It is triggered when an error occurs during WebSocket
     * communication.
     *
     * @param[in] ctx The address of the current WebSocket context.
     * @param[in] message A descriptive message of the error that occurred.
     */
    typedef void ( *t_event_error )( void *ctx, const char *message );

    /**
     * @brief Callback triggered when the WebSocket connection is opened.
     *
     * This method should be overridden when deriving from `c_websocket` to handle
     * the WebSocket `open` event. It is called once the WebSocket handshake
     * has been successfully completed.
     *
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] addr The address of the connected peer.
     */
    virtual void
    on_open( int fd, const char *addr );

    /**
     * @brief Callback triggered when a WebSocket text or binary frame is received.
     *
     * This method should be overridden to handle incoming WebSocket frames containing
     * text or binary data. It will only be triggered for frames with `TEXT` or `BINARY`
     * opcodes. Any other opcodes (e.g., ping, pong, or close) are handled internally.
     *
     * The callback runs inside `operate` so messages of one connection arrive in the
     * order they were sent. A long running callback delays every other connection,
     * so hand lengthy work to a worker of your own.
     *
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] opcode The opcode of the WebSocket frame, indicating the frame type (TEXT or BINARY).
     * @param[in] payload A pointer to the payload data received in the frame.
     * @param[in] size The size of the payload in bytes.
     */
    virtual void
    on_frame( int fd, e_ws_frame_opcode opcode, unsigned char *payload, size_t size );

    /**
     * @brief Callback triggered when the WebSocket connection is closed.
     *
     * This method should be overridden to handle WebSocket connection closure.
     * It is called when the WebSocket connection is closed either by the server
     * or the client.
     *
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @param[in] status The status code indicating the closure reason.
     */
    virtual void
    on_close( int fd, e_ws_closure_status status );

    /**
     * @brief Callback triggered when a WebSocket error occurs.
     *
     * This method should be overridden to handle WebSocket errors, such as
     * connection issues or unexpected conditions during communication.
     *
     * @param[in] message A descriptive message of the error that occurred.
     */
    virtual void
    on_error( const char *message );

public:
    /**
     * @brief Creates an unconfigured WebSocket instance.
     *
     * Call `setup` before binding or opening a connection.
     */
    c_websocket();

    /**
     * @brief Closes every managed file descriptor and releases the instance.
     */
    virtual ~c_websocket();

    /**
     * @brief Copying is disabled, an instance owns its file descriptors.
     */
    c_websocket( const c_websocket &rhs ) = delete;

    /**
     * @brief Copy assignment is disabled, an instance owns its file descriptors.
     */
    c_websocket &
    operator=( const c_websocket &rhs ) = delete;

public:
    /**
     * @brief Initializes the WebSocket settings.
     *
     * This method must be called before invoking any operations such as binding,
     * opening connections, or starting the communication loop. It configures
     * the WebSocket with the provided settings.
     *
     * @param[in] settings A pointer to a `ws_settings_t` structure that contains the
     *                 configuration settings for the WebSocket.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` if the settings were successfully applied.
     *         - `e_ws_status::status_error` if there was an issue with the provided settings.
     */
    e_ws_status
    setup( const ws_settings_t *settings ) const;

    /**
     * @brief Binds a file descriptor to the specified IP address and port.
     *
     * This function binds a file descriptor to the given IP address and port for
     * WebSocket communication. It creates a listening socket on the specified
     * interface and port. The resulting file descriptor is stored in `out_fd`.
     *
     * @param[in] bind_ip The IP address to bind to. If set to `NULL`, it will bind to all interfaces.
     * @param[in] bind_port The port to bind to.
     * @param[out] out_fd A pointer to an integer where the bound file descriptor will be stored.
     *               This can be set to `NULL` if the file descriptor is not needed.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` on success.
     *         - `e_ws_status::status_error` on failure.
     */
    e_ws_status
    bind( const char *bind_ip, const char *bind_port, int *out_fd ) const;

    /**
     * @brief Binds a file descriptor to the specified port.
     *
     * This function binds a file descriptor to the given port for WebSocket communication.
     * It creates a listening socket on all available interfaces. The resulting file descriptor
     * is stored in `out_fd`.
     *
     * @param[in] bind_port The port to bind to.
     * @param[out] out_fd A pointer to an integer where the bound file descriptor will be stored.
     *               This can be set to `NULL` if the file descriptor is not needed.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` on success.
     *         - `e_ws_status::status_error` on failure.
     */
    e_ws_status
    bind( const char *bind_port, int *out_fd ) const;

    /**
     * @brief Opens a file descriptor to the specified host and port.
     *
     * This function attempts to establish a connection to the specified host
     * and port for WebSocket communication. It creates a socket and stores
     * the resulting file descriptor in `out_fd`.
     *
     * @param[in] host_name The hostname or IP address of the destination to connect to.
     * @param[in] host_port The port number of the destination service to connect to.
     * @param[out] out_fd A pointer to an integer where the opened file descriptor will be stored.
     *               This can be set to `NULL` if the file descriptor is not needed.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` on success.
     *         - `e_ws_status::status_error` on failure.
     */
    e_ws_status
    open( const char *host_name, const char *host_port, int *out_fd ) const;

    /**
     * @brief Closes the specified file descriptor or all open file descriptors.
     *
     * This function closes the given file descriptor for WebSocket communication.
     * If the provided file descriptor (`fd`) is set to `-1`, it will close all
     * currently bound or opened file descriptors.
     *
     * @param[in] fd The file descriptor to close. If set to `-1`, all bound or opened
     *           file descriptors will be closed.
     */
    void
    close( int fd = -1 );

    /**
     * @brief Registers an event handler for a specified WebSocket event.
     *
     * This function allows you to register a callback function for a specific
     * WebSocket event. The available event names are defined as macros:
     *
     * - `WS_EVENT_OPEN`: The event name for when a WebSocket connection is opened.
     * - `WS_EVENT_CLOSE`: The event name for when a WebSocket connection is closed.
     * - `WS_EVENT_FRAME`: The event name for when a WebSocket frame is received.
     * - `WS_EVENT_ERROR`: The event name for when a WebSocket error occurs.
     *
     * The corresponding macros are defined as:
     * ```c
     * #define WS_EVENT_OPEN "open"
     * #define WS_EVENT_CLOSE "close"
     * #define WS_EVENT_FRAME "frame"
     * #define WS_EVENT_ERROR "error"
     * ```
     *
     * @param[in] event The name of the event to listen for. It should be one of the
     *              following string literals:
     *              - `"open"`: for the connection opened event.
     *              - `"close"`: for the connection closed event.
     *              - `"frame"`: for the frame received event.
     *              - `"error"`: for the error event.
     * @param[in] callback A function pointer to the callback function that will be
     *                 invoked when the specified event occurs. The function pointer
     *                 must match one of the event typedefs defined earlier.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` on success.
     *         - `e_ws_status::status_error` on failure.
     */
    e_ws_status
    on( const char *event, void *callback );

    /**
     * @brief Handles the main communication loop for the WebSocket.
     *
     * This function is intended to be called in a loop to manage the WebSocket
     * communication, including accepting new file descriptors and processing
     * events for existing connections.
     *
     * It will continue to run as long as there are active file descriptors,
     * such as bound or opened ones.
     *
     * @return `true` if there are active file descriptors (i.e., at least one
     *         bound or opened connection remains).
     *         `false` if no active file descriptors are present.
     */
    bool
    operate() const;

    /**
     * @brief Sends a WebSocket frame to the specified file descriptor.
     *
     * This function writes the provided frame to the output stream of the given
     * file descriptor (`fd`). The frame will later be sent to the connected endpoint.
     * It is important to note that `emit` does not confirm the status of the outgoing
     * message; it only writes to the output stream of the specified file descriptor.
     *
     * The frame keeps its payload, so the same frame may be emitted to several
     * connections. Frames are only accepted while the connection is open, once the
     * closure handshake has started RFC 6455 section 5.5.1 forbids further data frames.
     *
     * @param[in] fd The file descriptor of the WebSocket connection to which the frame
     *           will be sent.
     * @param[in] frame A pointer to a `c_ws_frame` object that contains the data to be
     *              sent.
     * @return An `e_ws_status` code indicating the result of the operation:
     *         - `e_ws_status::status_ok` on successful write to the output stream.
     *         - `e_ws_status::status_error` if the write operation fails.
     */
    e_ws_status
    emit( int fd, const c_ws_frame *frame ) const;

    /**
     * @brief Retrieves the subprotocol agreed on during the opening handshake.
     *
     * @param[in] fd The file descriptor of the WebSocket connection.
     * @return The negotiated subprotocol, or an empty string when none was agreed on.
     */
    const char *
    get_sub_protocol( int fd ) const;

private:
    /**
     * @brief Function pointer for the WebSocket `open` event callback (used in the C API).
     *
     * This is used in the C API to listen for WebSocket `open` events. If the `on_open`
     * virtual method is not overridden and this function pointer is not set to `NULL`,
     * it will be called when the WebSocket connection is successfully opened. However,
     * if the `on_open` method is overridden, this callback will not be used.
     */
    t_event_open event_open_callback;

    /**
     * @brief Function pointer for the WebSocket `close` event callback (used in the C API).
     *
     * This is used in the C API to listen for WebSocket `close` events. If the `on_close`
     * virtual method is not overridden and this function pointer is not set to `NULL`,
     * it will be called when the WebSocket connection is closed. If the `on_close` method
     * is overridden, this callback will not be used.
     */
    t_event_close event_close_callback;

    /**
     * @brief Function pointer for the WebSocket frame reception event callback (used in the C API).
     *
     * This is used in the C API to listen for WebSocket frame reception events. If the `on_frame`
     * virtual method is not overridden and this function pointer is not set to `NULL`,
     * it will be called when a WebSocket frame (text or binary) is received. If the `on_frame`
     * method is overridden, this callback will not be used.
     */
    t_event_frame event_frame_callback;

    /**
     * @brief Function pointer for the WebSocket error event callback (used in the C API).
     *
     * This is used in the C API to listen for WebSocket error events. If the `on_error`
     * virtual method is not overridden and this function pointer is not set to `NULL`,
     * it will be called when an error occurs. If the `on_error` method is overridden,
     * this callback will not be used.
     */
    t_event_error event_error_callback;

private:
    struct impl_t; /**< @brief Opaque connection state, kept out of the public header. */
    impl_t *impl;  /**< @brief Pointer to the connection state. */
};
