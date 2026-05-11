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

#include <websocket/api/websocket_api.h>

#ifdef WEBSOCKET_C_API

#include <websocket/defs/frameDefs.h>
#include <websocket/defs/socketDefs.h>

#ifdef __cplusplus
extern "C" {
#endif

WEBSOCKET_API void *
websocket_create();

WEBSOCKET_API e_ws_status
websocket_setup( void *ctx, const ws_settings_t *settings );

WEBSOCKET_API e_ws_status
websocket_bind( void *ctx, const char *bind_ip, const char *bind_port, int *out_fd );

WEBSOCKET_API e_ws_status
websocket_open( void *ctx, const char *host_ip, const char *host_port, int *out_fd );

WEBSOCKET_API e_ws_status
websocket_on( void *ctx, const char *event_name, void *callback );

WEBSOCKET_API bool
websocket_operate( void *ctx );

WEBSOCKET_API void
websocket_destroy( void *ctx );

WEBSOCKET_API void *
websocket_frame_create( e_ws_frame_opcode opcode );

WEBSOCKET_API void
websocket_frame_mask( void *ctx, int key );

WEBSOCKET_API bool
websocket_frame_push( void *ctx, const unsigned char *data, size_t size );

WEBSOCKET_API void
websocket_frame_flush( void *ctx );

WEBSOCKET_API bool
websocket_frame_emit( void *ctx, int fd, void *frame );

WEBSOCKET_API void
websocket_frame_destroy( void *ctx );

WEBSOCKET_API void
websocket_close( void *ctx, int fd );

#ifdef __cplusplus
}
#endif

#endif
