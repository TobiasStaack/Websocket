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

#define CHUNK_SIZE 8192

#include <websocket/core/frame.h>

#include <websocket/core/byte_stream.h>
#include <websocket/core/endian.h>

#include <websocket/core/flate.h>

#include <cstring>
#include <memory>

union ws_frame_byte1_t
{
    unsigned char value;

    struct
    {
        e_ws_frame_opcode opcode : 4;
        bool rsv3 : 1;
        bool rsv2 : 1;
        bool rsv1 : 1;
        bool fin : 1;
    } bits;
};

static_assert( sizeof( ws_frame_byte1_t ) == sizeof( unsigned char ), "ws_frame_byte1_t size mismatch" );

union ws_frame_byte2_t
{
    unsigned char value;

    struct
    {
        unsigned char payload_length : 7;
        bool mask : 1;
    } bits;
};

static_assert( sizeof( ws_frame_byte2_t ) == sizeof( unsigned char ), "ws_frame_byte2_t size mismatch" );

struct c_ws_frame::impl_t
{
    e_ws_frame_opcode opcode;
    unsigned char key[ 4 ]{};
    unsigned char window_bits;
    c_byte_stream payload;

    bool
    is_masked() const;

    static e_ws_frame_status
    encode( e_ws_frame_opcode opcode, bool mask, const unsigned char* mask_key, unsigned char window_bits, const c_byte_stream* input, const c_byte_stream* output );

    static e_ws_frame_status
    decode( const c_byte_stream* input, const c_byte_stream* output, e_ws_frame_opcode& opcode, unsigned char window_bits );

    impl_t()
    {
        opcode = opcode_binary;
        std::memset( key, 0, 4 );
        window_bits = 0;
    }

    ~impl_t()
    {
        payload.close();
    }
};

c_ws_frame::
    c_ws_frame()
{
    impl = new impl_t();
}

c_ws_frame::
    c_ws_frame( const e_ws_frame_opcode opcode )
{
    impl = new impl_t();
    impl->opcode = opcode;
}

c_ws_frame::~c_ws_frame()
{
    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }
}

c_ws_frame::
    c_ws_frame( const c_ws_frame& other )
{
    impl = new impl_t();
    impl->opcode = other.impl->opcode;
    std::memcpy( impl->key, other.impl->key, sizeof( impl->key ) );
    impl->payload = other.impl->payload;
}

c_ws_frame::
    c_ws_frame( c_ws_frame&& other ) noexcept
{
    impl = other.impl;
    other.impl = nullptr;
}

c_ws_frame&
c_ws_frame::operator=( const c_ws_frame& other )
{
    if ( this == &other )
    {
        return *this;
    }

    impl->opcode = other.impl->opcode;
    std::memcpy( impl->key, other.impl->key, sizeof( impl->key ) );
    impl->payload = other.impl->payload;

    return *this;
}

c_ws_frame&
c_ws_frame::operator=( c_ws_frame&& other ) noexcept
{
    if ( this == &other )
    {
        return *this;
    }

    impl = other.impl;
    other.impl = nullptr;

    return *this;
}

bool
c_ws_frame::impl_t::is_masked() const
{
    const unsigned int value = static_cast< uint32_t >( key[ 0 ] ) << 24 |
        static_cast< uint32_t >( key[ 1 ] ) << 16 |
        static_cast< uint32_t >( key[ 2 ] ) << 8 |
        static_cast< uint32_t >( key[ 3 ] );

    return value != 0;
}

void
c_ws_frame::mask( const unsigned int key ) const
{
    impl->key[ 0 ] = key >> 24 & 0xFF;
    impl->key[ 1 ] = key >> 16 & 0xFF;
    impl->key[ 2 ] = key >> 8 & 0xFF;
    impl->key[ 3 ] = key & 0xFF;
}

void
c_ws_frame::deflate( const unsigned char window_bits ) const
{
    impl->window_bits = window_bits;
}

bool
c_ws_frame::push( const unsigned char* data, const size_t size ) const
{
    return impl->payload.push( data, size ) == c_byte_stream::e_status::ok;
}

void
c_ws_frame::flush() const
{
    impl->payload.flush();
}

e_ws_frame_opcode
c_ws_frame::get_opcode() const
{
    return impl->opcode;
}

unsigned char*
c_ws_frame::get_payload() const
{
    return impl->payload.pointer();
}

size_t
c_ws_frame::get_payload_size() const
{
    return impl->payload.size();
}

bool
c_ws_frame::is_payload_utf8() const
{
    return impl->payload.is_utf8();
}

e_ws_frame_status
c_ws_frame::write( const c_byte_stream* output ) const
{
    switch ( impl->opcode )
    {
        case opcode_text:
        case opcode_binary:
        case opcode_close:
        case opcode_ping:
        case opcode_pong:
            break;

        default:
            return e_ws_frame_status::status_error;
    }

    return impl_t::encode( impl->opcode, impl->is_masked(), reinterpret_cast< unsigned char* >( &impl->key ), impl->window_bits, &impl->payload, output );
}

e_ws_frame_status
c_ws_frame::read( const c_byte_stream* input ) const
{
    e_ws_frame_opcode out_opcode = opcode_binary;

    const e_ws_frame_status status = impl_t::decode( input, &impl->payload, out_opcode, impl->window_bits );

    impl->opcode = out_opcode;

    return status;
}

e_ws_frame_status
c_ws_frame::impl_t::encode( const e_ws_frame_opcode opcode, const bool mask, const unsigned char* mask_key, const unsigned char window_bits, const c_byte_stream* input, const c_byte_stream* output )
{
    if ( !input || !output )
    {
        return e_ws_frame_status::status_error;
    }

    if ( opcode == opcode_text )
    {
        if ( input->to_utf8() != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    if ( window_bits != 0 )
    {
        const c_byte_stream deflated;

        if ( c_flate::deflate( input, &deflated, window_bits ) != c_flate::e_status::status_ok )
        {
            return e_ws_frame_status::status_ok;
        }

        *const_cast< c_byte_stream* >( input ) = std::move( *const_cast< c_byte_stream* >( &deflated ) );
    }

    size_t offset = 0, size = input->size();

    do
    {
        c_byte_stream fragment;

        ws_frame_byte1_t byte1{};

        byte1.bits.fin = size <= CHUNK_SIZE;
        byte1.bits.rsv1 = window_bits != 0;
        byte1.bits.rsv2 = false;
        byte1.bits.rsv3 = false;
        byte1.bits.opcode = offset == 0 ? opcode : opcode_continuation;

        if ( fragment.push_back( byte1.value ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        ws_frame_byte2_t byte2{};

        byte2.bits.mask = mask;

        const size_t payload_length = std::min< size_t >( CHUNK_SIZE, size );

        if ( payload_length > 65535 )
        {
            byte2.bits.payload_length = 127;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }

            unsigned long long network_payload_length = c_endian::host_to_network_64( payload_length );

            if ( fragment.push_back( reinterpret_cast< unsigned char* >( &network_payload_length ), 8 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
        else if ( payload_length > 125 )
        {
            byte2.bits.payload_length = 126;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }

            unsigned short network_payload_length = c_endian::host_to_network_16( static_cast< unsigned short >( payload_length ) );

            if ( fragment.push_back( reinterpret_cast< unsigned char* >( &network_payload_length ), 2 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
        else
        {
            byte2.bits.payload_length = payload_length;

            if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        if ( mask )
        {
            if ( input->available() )
            {
                unsigned char* payload = input->pointer( offset );
                if ( !payload )
                {
                    return e_ws_frame_status::status_error;
                }

                for ( size_t i = 0; i < payload_length; ++i )
                {
                    payload[ i ] = payload[ i ] ^ mask_key[ i % 4 ];
                }
            }

            if ( fragment.push_back( mask_key, 4 ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        if ( input->available() )
        {
            if ( input->move( &fragment, payload_length, offset ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }

        if ( fragment.move( output, fragment.size(), 0 ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        offset += payload_length;
        size -= payload_length;
    }
    while ( size > 0 );

    return e_ws_frame_status::status_ok;
}

e_ws_frame_status
c_ws_frame::impl_t::decode( const c_byte_stream* input, const c_byte_stream* output, e_ws_frame_opcode& opcode, const unsigned char window_bits )
{
    if ( !input || !output )
    {
        return e_ws_frame_status::status_error;
    }

    if ( !input->available() )
    {
        return e_ws_frame_status::status_incomplete;
    }

    const ws_frame_byte1_t byte1 = { *input->pointer() };

    switch ( byte1.bits.opcode )
    {
        case opcode_continuation:
        {
            if ( byte1.bits.fin )
            {
                return e_ws_frame_status::status_error;
            }
            break;
        }

        case opcode_text:
        case opcode_binary:
        case opcode_close:
        case opcode_ping:
        case opcode_pong:
        {
            opcode = byte1.bits.opcode;
            break;
        }

        case opcode_rsv1_further_non_control:
        case opcode_rsv2_further_non_control:
        case opcode_rsv3_further_non_control:
        case opcode_rsv4_further_non_control:
        case opcode_rsv5_further_non_control:
        case opcode_rsv1_further_control:
        case opcode_rsv2_further_control:
        case opcode_rsv3_further_control:
        case opcode_rsv4_further_control:
        case opcode_rsv5_further_control:
        default:
        {
            return e_ws_frame_status::status_error;
        }
    }

    if ( input->size() < 2 )
    {
        return e_ws_frame_status::status_incomplete;
    }

    const ws_frame_byte2_t byte2 = { *input->pointer( 1 ) };

    size_t payload_length = byte2.bits.payload_length;
    size_t offset = 2;

    if ( input->size() < ( payload_length == 127 ? 8 : 2 ) )
    {
        return e_ws_frame_status::status_incomplete;
    }

    if ( payload_length == 126 )
    {
        input->copy( reinterpret_cast< unsigned char* >( &payload_length ), 2, nullptr, offset );

        payload_length = static_cast< unsigned long long >( c_endian::network_to_host_16( static_cast< unsigned short >( payload_length ) ) );

        offset += 2;
    }
    else if ( payload_length == 127 )
    {
        input->copy( reinterpret_cast< unsigned char* >( &payload_length ), 8, nullptr, offset );

        payload_length = c_endian::network_to_host_64( payload_length );

        offset += 8;
    }

    if ( input->size() < offset )
    {
        return e_ws_frame_status::status_incomplete;
    }

    unsigned char mask_key[ 4 ] = {};

    if ( byte2.bits.mask )
    {
        input->copy( reinterpret_cast< unsigned char* >( &mask_key ), 4, nullptr, offset );

        offset += 4;
    }

    if ( input->size() < offset + payload_length )
    {
        return e_ws_frame_status::status_incomplete;
    }

    if ( payload_length > 0 )
    {
        unsigned char* payload = input->pointer( offset );

        if ( !payload )
        {
            return e_ws_frame_status::status_error;
        }

        if ( byte2.bits.mask )
        {
            for ( size_t i = 0; i < payload_length; ++i )
            {
                payload[ i ] = payload[ i ] ^ mask_key[ i % 4 ];
            }
        }

        if ( byte1.bits.rsv1 )
        {
            const c_byte_stream inflate_input;

            if ( input->move( &inflate_input, payload_length, offset ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }

            if ( c_flate::inflate( &inflate_input, output, window_bits ) != c_flate::e_status::status_ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
        else
        {
            if ( input->move( output, payload_length, offset ) != c_byte_stream::e_status::ok )
            {
                return e_ws_frame_status::status_error;
            }
        }
    }

    input->pop( offset );

    const e_ws_frame_status status = byte1.bits.fin ? e_ws_frame_status::status_final : e_ws_frame_status::status_fragment;

    if ( status == e_ws_frame_status::status_final )
    {
        if ( opcode == opcode_text )
        {
            if ( !output->is_utf8() )
            {
                output->flush();
                return e_ws_frame_status::status_invalid_data;
            }
        }
    }

    return status;
}
