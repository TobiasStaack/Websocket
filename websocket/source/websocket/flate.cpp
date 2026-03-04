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

c_flate::e_status
c_flate::deflate( const c_byte_stream* input, const c_byte_stream* output, const unsigned char window_bits )
{
    if ( input == nullptr || output == nullptr )
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

    ret = Z_OK;

    for ( ;; )
    {
        if ( strm.avail_in == 0 && in_left > 0 )
        {
            size_t chunk = in_left;
            if ( chunk > static_cast< size_t >( std::numeric_limits< uInt >::max() ) )
            {
                chunk = static_cast< size_t >( std::numeric_limits< uInt >::max() );
            }

            strm.next_in = const_cast< Bytef* >( in_ptr );
            strm.avail_in = static_cast< uInt >( chunk );

            in_ptr += chunk;
            in_left -= chunk;
        }

        strm.next_out = buffer.data();
        strm.avail_out = static_cast< uInt >( buffer.size() );

        const int flush_mode = ( in_left == 0 && strm.avail_in == 0 ) ? Z_FINISH : Z_NO_FLUSH;

        ret = ::deflate( &strm, flush_mode );

        if ( ret != Z_OK && ret != Z_STREAM_END )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }

        const size_t produced = buffer.size() - static_cast< size_t >( strm.avail_out );
        if ( produced > 0 )
        {
            if ( output->push_back( buffer.data(), produced ) != c_byte_stream::e_status::ok )
            {
                deflateEnd( &strm );
                return e_status::status_error;
            }
        }

        if ( ret == Z_STREAM_END )
        {
            break;
        }

        if ( flush_mode == Z_FINISH && produced == 0 )
        {
            deflateEnd( &strm );
            return e_status::status_error;
        }
    }

    deflateEnd( &strm );
    return e_status::status_ok;
}

c_flate::e_status
c_flate::inflate( const c_byte_stream* input, const c_byte_stream* output, const unsigned char window_bits )
{
    if ( input == nullptr || output == nullptr )
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

    ret = Z_OK;

    for ( ;; )
    {
        if ( strm.avail_in == 0 && in_left > 0 )
        {
            size_t chunk = in_left;
            if ( chunk > static_cast< size_t >( std::numeric_limits< uInt >::max() ) )
            {
                chunk = static_cast< size_t >( std::numeric_limits< uInt >::max() );
            }

            strm.next_in = const_cast< Bytef* >( in_ptr );
            strm.avail_in = static_cast< uInt >( chunk );

            in_ptr += chunk;
            in_left -= chunk;
        }

        strm.next_out = buffer.data();
        strm.avail_out = static_cast< uInt >( buffer.size() );

        ret = ::inflate( &strm, Z_NO_FLUSH );

        if ( ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_STREAM_ERROR )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }

        const size_t produced = buffer.size() - static_cast< size_t >( strm.avail_out );
        if ( produced > 0 )
        {
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

        if ( ret == Z_BUF_ERROR )
        {
            if ( strm.avail_in == 0 && in_left == 0 )
            {
                inflateEnd( &strm );
                return e_status::status_error;
            }
        }

        if ( produced == 0 && strm.avail_in == 0 && in_left == 0 )
        {
            inflateEnd( &strm );
            return e_status::status_error;
        }
    }

    inflateEnd( &strm );
    return e_status::status_ok;
}