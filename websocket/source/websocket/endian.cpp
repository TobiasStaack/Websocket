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

#include <websocket/core/endian.h>

unsigned short
c_endian::host_to_network_16( const unsigned short value )
{
    return swap_16( value );
}

unsigned int
c_endian::host_to_network_32( const unsigned int value )
{
    return swap_32( value );
}

unsigned long long
c_endian::host_to_network_64( const unsigned long long value )
{
    return swap_64( value );
}

unsigned short
c_endian::network_to_host_16( const unsigned short value )
{
    return swap_16( value );
}

unsigned int
c_endian::network_to_host_32( const unsigned int value )
{
    return swap_32( value );
}

unsigned long long
c_endian::network_to_host_64( const unsigned long long value )
{
    return swap_64( value );
}

unsigned short
c_endian::little_endian_16( const unsigned short value )
{
    return is_big() ? swap_16( value ) : value;
}

unsigned int
c_endian::little_endian_32( const unsigned int value )
{
    return is_big() ? swap_32( value ) : value;
}

unsigned long long
c_endian::little_endian_64( const unsigned long long value )
{
    return is_big() ? swap_64( value ) : value;
}

unsigned short
c_endian::big_endian_16( const unsigned short value )
{
    return is_big() ? static_cast< unsigned short >( swap_64( value ) ) : value;
}

unsigned int
c_endian::big_endian_32( const unsigned int value )
{
    return is_little() ? swap_32( value ) : value;
}

unsigned long long
c_endian::big_endian_64( const unsigned long long value )
{
    return is_little() ? swap_64( value ) : value;
}

bool
c_endian::is_little()
{
    unsigned int x = 1;
    return *reinterpret_cast< unsigned char * >( &x ) == 1;
}

bool
c_endian::is_big()
{
    return !is_little();
}

unsigned short
c_endian::swap_16( const unsigned short value )
{
    return value << 8 | value >> 8;
}

unsigned int
c_endian::swap_32( const unsigned int value )
{
    return value >> 24 & 0x000000FF |
        value >> 8 & 0x0000FF00 |
        value << 8 & 0x00FF0000 |
        value << 24 & 0xFF000000;
}

unsigned long long
c_endian::swap_64( const unsigned long long value )
{
    return value >> 56 & 0x00000000000000FFULL |
        value >> 40 & 0x000000000000FF00ULL |
        value >> 24 & 0x0000000000FF0000ULL |
        value >> 8 & 0x00000000FF000000ULL |
        value << 8 & 0x000000FF00000000ULL |
        value << 24 & 0x0000FF0000000000ULL |
        value << 40 & 0x00FF000000000000ULL |
        value << 56 & 0xFF00000000000000ULL;
}
