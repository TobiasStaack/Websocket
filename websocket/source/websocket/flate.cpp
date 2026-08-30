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

#include <cstring>
#include <limits>

static const unsigned char FLATE_TAIL[ 4 ] = { 0x00, 0x00, 0xFF, 0xFF };

c_flate::e_status
c_flate::deflate( const c_byte_stream* input, const c_byte_stream* output, const unsigned char window_bits )
{
    if ( input == 0 || output == 0 )
    {
        return e_status::status_error;
    }

    if ( input->size() == 0 )
    {
        return e_status::status_ok;
    }

    z_stream strm = {};
    int ret = deflateInit2( &strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -static_cast< int >( window_bits ), 8, Z_DEFAULT_STRATEGY );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    const unsigned char* in_ptr = input->pointer();
    size_t in_left = input->size();
    std::vector< unsigned char > buffer( 32768 );
    std::vector< unsigned char > deflated;

    do
    {
        if ( strm.avail_in == 0 && in_left > 0 )
        {
            const size_t chunk = std::min( in_left, static_cast< size_t >( std::numeric_limits< uInt >::max() ) );
            strm.next_in = const_cast< Bytef* >( in_ptr );
            strm.avail_in = static_cast< uInt >( chunk );
            in_ptr += chunk;
            in_left -= chunk;
        }

        const int flush = ( in_left == 0 ) ? Z_SYNC_FLUSH : Z_NO_FLUSH;

        do
        {
            strm.next_out = buffer.data();
            strm.avail_out = static_cast< uInt >( buffer.size() );

            ret = ::deflate( &strm, flush );

            if ( ret == Z_STREAM_ERROR || ret == Z_BUF_ERROR )
            {
                deflateEnd( &strm );
                return e_status::status_error;
            }

            const size_t produced = buffer.size() - strm.avail_out;
            if ( produced > 0 )
            {
                try
                {
                    deflated.insert( deflated.end(), buffer.data(), buffer.data() + produced );
                }
                catch ( ... )
                {
                    deflateEnd( &strm );
                    return e_status::status_error;
                }
            }
        }
        while ( strm.avail_out == 0 );
    }
    while ( in_left > 0 );

    deflateEnd( &strm );

    // rfc 7692 7.2.1: strip the trailing 0x00 0x00 0xFF 0xFF emitted by the sync flush
    if ( deflated.size() >= sizeof( FLATE_TAIL ) && std::memcmp( deflated.data() + deflated.size() - sizeof( FLATE_TAIL ), FLATE_TAIL, sizeof( FLATE_TAIL ) ) == 0 )
    {
        deflated.resize( deflated.size() - sizeof( FLATE_TAIL ) );
    }

    if ( deflated.empty() )
    {
        return output->push_back( static_cast< unsigned char >( 0x00 ) ) == c_byte_stream::e_status::ok ? e_status::status_ok : e_status::status_error;
    }

    if ( output->push_back( deflated.data(), deflated.size() ) != c_byte_stream::e_status::ok )
    {
        return e_status::status_error;
    }

    return e_status::status_ok;
}

c_flate::e_status
c_flate::inflate( const c_byte_stream* input, const c_byte_stream* output, const unsigned char window_bits, const size_t limit )
{
    if ( input == 0 || output == 0 )
    {
        return e_status::status_error;
    }

    if ( input->size() == 0 )
    {
        return e_status::status_ok;
    }

    z_stream strm = {};
    int ret = inflateInit2( &strm, -static_cast< int >( window_bits ) );
    if ( ret != Z_OK )
    {
        return e_status::status_error;
    }

    const unsigned char* in_ptr = input->pointer();
    size_t in_left = input->size();
    std::vector< unsigned char > buffer( 32768 );

    // rfc 7692 7.2.2: append 0x00 0x00 0xFF 0xFF before decompressing
    bool tail_appended = false;
    size_t produced_total = 0;

    for ( ;; )
    {
        if ( strm.avail_in == 0 )
        {
            if ( in_left > 0 )
            {
                const size_t chunk = std::min( in_left, static_cast< size_t >( std::numeric_limits< uInt >::max() ) );
                strm.next_in = const_cast< Bytef* >( in_ptr );
                strm.avail_in = static_cast< uInt >( chunk );
                in_ptr += chunk;
                in_left -= chunk;
            }
            else if ( tail_appended == false )
            {
                strm.next_in = const_cast< Bytef* >( FLATE_TAIL );
                strm.avail_in = sizeof( FLATE_TAIL );
                tail_appended = true;
            }
            else
            {
                break;
            }
        }

        strm.next_out = buffer.data();
        strm.avail_out = static_cast< uInt >( buffer.size() );

        ret = ::inflate( &strm, Z_NO_FLUSH );

        if ( ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }

        const size_t produced = buffer.size() - strm.avail_out;
        if ( produced > 0 )
        {
            produced_total += produced;

            if ( limit != 0 && produced_total > limit )
            {
                inflateEnd( &strm );
                return e_status::status_error;
            }

            if ( output->push_back( buffer.data(), produced ) != c_byte_stream::e_status::ok )
            {
                inflateEnd( &strm );
                return e_status::status_error;
            }
        }

        if ( ret == Z_STREAM_END )
        {
            break;
        }

        if ( produced == 0 && strm.avail_in == 0 && in_left == 0 && tail_appended )
        {
            break;
        }
    }

    inflateEnd( &strm );

    return e_status::status_ok;
}
