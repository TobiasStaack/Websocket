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

#include <websocket/core/flate.h>

#include <websocket/core/deflate.h>

#include <websocket/core/inftrees.h>

#include <websocket/core/inflate.h>

c_flate::e_status
c_flate::deflate( const c_byte_stream *input, const c_byte_stream *output, const size_t window_size )
{
    z_stream strm = {};

    int ret = deflateInit2( &strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -1 * window_size, 8, Z_DEFAULT_STRATEGY );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    strm.avail_in = input->size();
    strm.next_in = input->pointer();

    std::vector< unsigned char > buffer( 32768 );

    do
    {
        strm.avail_out = buffer.size();
        strm.next_out = buffer.data();

        ret = ::deflate( &strm, Z_FINISH );
        if ( ret == Z_STREAM_ERROR )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }

        if ( output->push_back( buffer.data(), buffer.size() - strm.avail_out ) != c_byte_stream::e_status::ok )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }
    }
    while ( strm.avail_out == 0 );

    deflateEnd( &strm );

    return ( ret == Z_STREAM_END ) ? e_status::status_ok : e_status::status_error;
}

c_flate::e_status
c_flate::inflate( const c_byte_stream *input, const c_byte_stream *output, const size_t window_size )
{
    z_stream strm = {};

    int ret = inflateInit2( &strm, -1 * window_size );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    strm.avail_in = input->size();
    strm.next_in = input->pointer();

    std::vector< unsigned char > buffer( 32768 );

    do
    {
        strm.avail_out = buffer.size();
        strm.next_out = buffer.data();

        ret = ::inflate( &strm, Z_SYNC_FLUSH );
        if ( ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }

        if ( output->push_back( buffer.data(), buffer.size() - strm.avail_out ) != c_byte_stream::e_status::ok )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }
    }
    while ( strm.avail_in > 0 );

    inflateEnd( &strm );

    return ( ret == Z_OK || ret == Z_STREAM_END ) ? e_status::status_ok : e_status::status_error;
}
