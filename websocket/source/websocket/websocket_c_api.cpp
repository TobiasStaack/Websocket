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

#ifdef WEBSOCKET_C_API

#include <websocket/api/websocket_c_api.h>

#include <websocket/core/websocket.h>

#include <memory>

void *
websocket_create()
{
    void *ptr = std::malloc( sizeof( c_websocket ) );
    if ( ptr == nullptr )
    {
        return nullptr;
    }

    return new ( ptr ) c_websocket();
}

e_ws_status
websocket_setup( void *ctx, const ws_settings_t *settings )
{
    if ( !ctx )
    {
        return status_error;
    }

    return static_cast< c_websocket * >( ctx )->setup( settings );
}

e_ws_status
websocket_bind( void *ctx, const char *bind_ip, const char *bind_port, int *out_fd )
{
    if ( !ctx )
    {
        return status_error;
    }

    return static_cast< c_websocket * >( ctx )->bind( bind_ip, bind_port, out_fd );
}

e_ws_status
websocket_open( void *ctx, const char *host_ip, const char *host_port, int *out_fd )
{
    if ( !ctx )
    {
        return status_error;
    }

    return static_cast< c_websocket * >( ctx )->open( host_ip, host_port, out_fd );
}

e_ws_status
websocket_on( void *ctx, const char *event_name, void *callback )
{
    if ( !ctx )
    {
        return status_error;
    }

    return static_cast< c_websocket * >( ctx )->on( event_name, callback );
}

bool
websocket_operate( void *ctx )
{
    if ( !ctx )
    {
        return false;
    }

    return static_cast< c_websocket * >( ctx )->operate();
}

void
websocket_destroy( void *ctx )
{
    if ( !ctx )
    {
        return;
    }

    static_cast< c_websocket * >( ctx )->~c_websocket();

    std::free( ctx );
}

void *
websocket_frame_create( const e_ws_frame_opcode opcode )
{
    void *ptr = std::malloc( sizeof( c_ws_frame ) );
    if ( ptr == nullptr )
    {
        return nullptr;
    }

    return new ( ptr ) c_ws_frame( opcode );
}

void
websocket_frame_mask( void *ctx, const int key )
{
    if ( !ctx )
    {
        return;
    }

    static_cast< c_ws_frame * >( ctx )->mask( key );
}

bool
websocket_frame_push( void *ctx, const unsigned char *data, const size_t size )
{
    if ( !ctx )
    {
        return false;
    }

    return static_cast< c_ws_frame * >( ctx )->push( data, size );
}

void
websocket_frame_flush( void *ctx )
{
    if ( !ctx )
    {
        return;
    }

    static_cast< c_ws_frame * >( ctx )->flush();
}

bool
websocket_frame_emit( void *ctx, const int fd, void *frame )
{
    if ( !ctx || !frame )
    {
        return false;
    }

    return static_cast< c_websocket * >( ctx )->emit( fd, static_cast< c_ws_frame * >( frame ) );
}

void
websocket_frame_destroy( void *ctx )
{
    if ( !ctx )
    {
        return;
    }

    static_cast< c_ws_frame * >( ctx )->~c_ws_frame();

    std::free( ctx );
}

void
websocket_close( void *ctx, const int fd )
{
    if ( !ctx )
    {
        return;
    }

    static_cast< c_websocket * >( ctx )->close( fd );
}

#endif
