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

#include <websocket/core/frame.h>

#include <websocket/core/byte_stream.h>
#include <websocket/core/endian.h>

#include <websocket/core/flate.h>

#include <cstdint>
#include <cstring>
#include <limits>
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

/**
 * @brief Checks whether an opcode denotes a control frame.
 *
 * @param[in] opcode The opcode to inspect.
 * @return `true` for close, ping and pong.
 */
static FORCE_INLINE bool
is_control_opcode( const e_ws_frame_opcode opcode )
{
    return ( opcode & 0x8 ) != 0;
}

/**
 * @brief Validates utf-8 while it arrives, so a broken text message fails on the frame that breaks it.
 *
 * RFC 6455 section 8.1 only requires the connection to fail, but a message may span
 * many frames and there is no reason to buffer all of them before noticing.
 */
struct utf8_validator_t
{
    unsigned char remaining;
    unsigned char lower;
    unsigned char upper;

    void
    reset()
    {
        remaining = 0;
        lower = 0x80;
        upper = 0xBF;
    }

    bool
    feed( const unsigned char* data, const size_t size )
    {
        for ( size_t i = 0; i < size; ++i )
        {
            const unsigned char byte = data[ i ];

            if ( remaining != 0 )
            {
                if ( byte < lower || byte > upper )
                {
                    return false;
                }

                lower = 0x80;
                upper = 0xBF;
                --remaining;

                continue;
            }

            if ( byte <= 0x7F )
            {
                continue;
            }

            if ( byte < 0xC2 || byte > 0xF4 )
            {
                return false;
            }

            if ( byte <= 0xDF )
            {
                remaining = 1;
            }
            else if ( byte <= 0xEF )
            {
                remaining = 2;

                // exclude overlong forms and the surrogate range
                if ( byte == 0xE0 )
                {
                    lower = 0xA0;
                }
                else if ( byte == 0xED )
                {
                    upper = 0x9F;
                }
            }
            else
            {
                remaining = 3;

                // exclude overlong forms and code points beyond u+10ffff
                if ( byte == 0xF0 )
                {
                    lower = 0x90;
                }
                else if ( byte == 0xF4 )
                {
                    upper = 0x8F;
                }
            }
        }

        return true;
    }

    bool
    complete() const
    {
        return remaining == 0;
    }

    utf8_validator_t()
    {
        reset();
    }
};

struct c_ws_frame::impl_t
{
    e_ws_frame_opcode opcode;
    unsigned char key[ 4 ]{};
    bool masked;
    unsigned char deflate_window_bits;
    unsigned char inflate_window_bits;
    size_t limit;
    bool fragmented;
    bool compressed;
    bool expect_mask;
    utf8_validator_t utf8;
    c_byte_stream payload;

    static e_ws_frame_status
    encode( e_ws_frame_opcode opcode, bool mask, const unsigned char* mask_key, unsigned char window_bits, const c_byte_stream* input, const c_byte_stream* output );

    e_ws_frame_status
    decode( const c_byte_stream* input, impl_t* control );

    impl_t()
    {
        opcode = opcode_binary;
        std::memset( key, 0, 4 );
        masked = false;
        deflate_window_bits = 0;
        inflate_window_bits = 0;
        limit = 0;
        fragmented = false;
        compressed = false;
        expect_mask = false;
        utf8.reset();
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
        impl = 0;
    }
}

c_ws_frame::
    c_ws_frame( const c_ws_frame& other )
{
    impl = new impl_t();

    if ( other.impl )
    {
        *impl = *other.impl;
    }
}

c_ws_frame::
    c_ws_frame( c_ws_frame&& other ) noexcept
{
    impl = other.impl;
    other.impl = 0;
}

c_ws_frame&
c_ws_frame::operator=( const c_ws_frame& other )
{
    if ( this == &other )
    {
        return *this;
    }

    if ( impl == 0 )
    {
        impl = new impl_t();
    }

    if ( other.impl )
    {
        *impl = *other.impl;
    }

    return *this;
}

c_ws_frame&
c_ws_frame::operator=( c_ws_frame&& other ) noexcept
{
    if ( this == &other )
    {
        return *this;
    }

    if ( impl )
    {
        delete impl;
    }

    impl = other.impl;
    other.impl = 0;

    return *this;
}

void
c_ws_frame::mask( const unsigned int key ) const
{
    impl->key[ 0 ] = key >> 24 & 0xFF;
    impl->key[ 1 ] = key >> 16 & 0xFF;
    impl->key[ 2 ] = key >> 8 & 0xFF;
    impl->key[ 3 ] = key & 0xFF;

    impl->masked = true;
}

void
c_ws_frame::deflate( const unsigned char window_bits ) const
{
    impl->deflate_window_bits = window_bits;
}

void
c_ws_frame::inflate( const unsigned char window_bits ) const
{
    impl->inflate_window_bits = window_bits;
}

void
c_ws_frame::expect_mask( const bool state ) const
{
    impl->expect_mask = state;
}

void
c_ws_frame::limit( const size_t size ) const
{
    impl->limit = size;
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

    impl->fragmented = false;
    impl->compressed = false;
    impl->utf8.reset();
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

    return impl_t::encode( impl->opcode, impl->masked, impl->key, impl->deflate_window_bits, &impl->payload, output );
}

e_ws_frame_status
c_ws_frame::read( const c_byte_stream* input, const c_ws_frame* control ) const
{
    return impl->decode( input, control ? control->impl : 0 );
}

e_ws_frame_status
c_ws_frame::impl_t::encode( const e_ws_frame_opcode opcode, const bool mask, const unsigned char* mask_key, const unsigned char window_bits, const c_byte_stream* input, const c_byte_stream* output )
{
    if ( input == 0 || output == 0 )
    {
        return e_ws_frame_status::status_error;
    }

    c_byte_stream payload( *input );

    if ( opcode == opcode_text )
    {
        if ( payload.to_utf8() != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    bool compressed = false;

    if ( window_bits != 0 && !is_control_opcode( opcode ) && payload.size() != 0 )
    {
        c_byte_stream deflated;

        if ( c_flate::deflate( &payload, &deflated, window_bits ) != c_flate::e_status::status_ok )
        {
            return e_ws_frame_status::status_error;
        }

        payload = std::move( deflated );

        compressed = true;
    }

    const size_t payload_length = payload.size();

    if ( is_control_opcode( opcode ) && payload_length > 125 )
    {
        return e_ws_frame_status::status_error;
    }

    c_byte_stream fragment;

    ws_frame_byte1_t byte1{};

    byte1.bits.fin = true;
    byte1.bits.rsv1 = compressed;
    byte1.bits.rsv2 = false;
    byte1.bits.rsv3 = false;
    byte1.bits.opcode = opcode;

    if ( fragment.push_back( byte1.value ) != c_byte_stream::e_status::ok )
    {
        return e_ws_frame_status::status_error;
    }

    ws_frame_byte2_t byte2{};

    byte2.bits.mask = mask;

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
        byte2.bits.payload_length = static_cast< unsigned char >( payload_length );

        if ( fragment.push_back( byte2.value ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    if ( mask )
    {
        if ( fragment.push_back( mask_key, 4 ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }

        if ( payload_length != 0 )
        {
            unsigned char* data = payload.pointer( 0 );

            if ( data == 0 )
            {
                return e_ws_frame_status::status_error;
            }

            for ( size_t i = 0; i < payload_length; ++i )
            {
                data[ i ] = data[ i ] ^ mask_key[ i % 4 ];
            }
        }
    }

    if ( payload_length != 0 )
    {
        if ( payload.move( &fragment, payload_length, 0 ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    if ( fragment.move( output, fragment.size(), 0 ) != c_byte_stream::e_status::ok )
    {
        return e_ws_frame_status::status_error;
    }

    return e_ws_frame_status::status_ok;
}

e_ws_frame_status
c_ws_frame::impl_t::decode( const c_byte_stream* input, impl_t* control )
{
    if ( input == 0 || control == 0 )
    {
        return e_ws_frame_status::status_error;
    }

    if ( input->size() < 2 )
    {
        return e_ws_frame_status::status_incomplete;
    }

    const ws_frame_byte1_t byte1 = { *input->pointer( 0 ) };
    const ws_frame_byte2_t byte2 = { *input->pointer( 1 ) };

    // rfc 6455 5.2: reserved bits stay cleared unless a negotiated extension defines them
    if ( byte1.bits.rsv2 || byte1.bits.rsv3 )
    {
        return e_ws_frame_status::status_error;
    }

    switch ( byte1.bits.opcode )
    {
        case opcode_continuation:
        case opcode_text:
        case opcode_binary:
        case opcode_close:
        case opcode_ping:
        case opcode_pong:
            break;

        default:
            return e_ws_frame_status::status_error;
    }

    const bool is_control = is_control_opcode( byte1.bits.opcode );

    if ( is_control )
    {
        // rfc 6455 5.5: control frames are never fragmented and never compressed
        if ( byte1.bits.fin == false || byte1.bits.rsv1 == true )
        {
            return e_ws_frame_status::status_error;
        }
    }
    else if ( byte1.bits.opcode == opcode_continuation )
    {
        // rfc 6455 5.4: a continuation needs a started message, rfc 7692 6.1 keeps rsv1 on the first frame
        if ( fragmented == false || byte1.bits.rsv1 == true )
        {
            return e_ws_frame_status::status_error;
        }
    }
    else
    {
        // rfc 6455 5.4: a data frame must not interrupt a running fragment chain
        if ( fragmented )
        {
            return e_ws_frame_status::status_error;
        }

        if ( byte1.bits.rsv1 && inflate_window_bits == 0 )
        {
            return e_ws_frame_status::status_error;
        }
    }

    size_t payload_length = byte2.bits.payload_length;
    size_t offset = 2;

    if ( payload_length == 126 )
    {
        if ( input->size() < offset + 2 )
        {
            return e_ws_frame_status::status_incomplete;
        }

        unsigned short extended = 0;

        input->copy( reinterpret_cast< unsigned char* >( &extended ), 2, 0, offset );

        extended = c_endian::network_to_host_16( extended );

        offset += 2;

        // rfc 6455 5.2: the length must use the minimal number of bytes
        if ( extended < 126 )
        {
            return e_ws_frame_status::status_error;
        }

        payload_length = extended;
    }
    else if ( payload_length == 127 )
    {
        if ( input->size() < offset + 8 )
        {
            return e_ws_frame_status::status_incomplete;
        }

        unsigned long long extended = 0;

        input->copy( reinterpret_cast< unsigned char* >( &extended ), 8, 0, offset );

        extended = c_endian::network_to_host_64( extended );

        offset += 8;

        // rfc 6455 5.2: the most significant bit stays zero and the length must be minimal
        if ( ( extended >> 63 ) != 0 || extended <= 65535 )
        {
            return e_ws_frame_status::status_error;
        }

        if ( extended > std::numeric_limits< size_t >::max() - offset - 4 )
        {
            return e_ws_frame_status::status_too_big;
        }

        payload_length = static_cast< size_t >( extended );
    }

    // rfc 6455 5.5: control frames carry at most 125 bytes
    if ( is_control && payload_length > 125 )
    {
        return e_ws_frame_status::status_error;
    }

    // rfc 6455 5.1: a client masks every frame, a server masks none
    if ( byte2.bits.mask != expect_mask )
    {
        return e_ws_frame_status::status_error;
    }

    unsigned char mask_key[ 4 ] = {};

    if ( byte2.bits.mask )
    {
        if ( input->size() < offset + 4 )
        {
            return e_ws_frame_status::status_incomplete;
        }

        input->copy( mask_key, 4, 0, offset );

        offset += 4;
    }

    if ( !is_control && limit != 0 )
    {
        if ( payload.size() > limit || payload_length > limit - payload.size() )
        {
            return e_ws_frame_status::status_too_big;
        }
    }

    if ( input->size() < offset + payload_length )
    {
        return e_ws_frame_status::status_incomplete;
    }

    impl_t* target = is_control ? control : this;

    if ( is_control )
    {
        target->payload.flush();
        target->opcode = byte1.bits.opcode;
    }
    else if ( byte1.bits.opcode != opcode_continuation )
    {
        opcode = byte1.bits.opcode;
        compressed = byte1.bits.rsv1;

        utf8.reset();
    }

    if ( payload_length != 0 )
    {
        unsigned char* data = input->pointer( offset );

        if ( data == 0 )
        {
            return e_ws_frame_status::status_error;
        }

        if ( byte2.bits.mask )
        {
            for ( size_t i = 0; i < payload_length; ++i )
            {
                data[ i ] = data[ i ] ^ mask_key[ i % 4 ];
            }
        }

        // rfc 6455 8.1: a compressed message can only be checked once it is inflated
        if ( is_control == false && opcode == opcode_text && compressed == false )
        {
            if ( utf8.feed( data, payload_length ) == false )
            {
                input->pop( offset + payload_length );

                payload.flush();
                fragmented = false;

                return e_ws_frame_status::status_invalid_data;
            }
        }

        if ( input->move( &target->payload, payload_length, offset ) != c_byte_stream::e_status::ok )
        {
            return e_ws_frame_status::status_error;
        }
    }

    input->pop( offset );

    if ( is_control )
    {
        return e_ws_frame_status::status_control;
    }

    if ( byte1.bits.fin == false )
    {
        fragmented = true;

        return e_ws_frame_status::status_fragment;
    }

    fragmented = false;

    const bool was_compressed = compressed;

    if ( compressed )
    {
        c_byte_stream inflated;

        if ( c_flate::inflate( &payload, &inflated, inflate_window_bits, limit ) != c_flate::e_status::status_ok )
        {
            payload.flush();

            return e_ws_frame_status::status_error;
        }

        payload = std::move( inflated );

        compressed = false;
    }

    if ( opcode == opcode_text )
    {
        // an incomplete sequence at the end of the message is invalid as well
        if ( was_compressed ? payload.is_utf8() == false : utf8.complete() == false )
        {
            payload.flush();

            return e_ws_frame_status::status_invalid_data;
        }
    }

    return e_ws_frame_status::status_final;
}
