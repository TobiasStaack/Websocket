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

#include <websocket/core/byte_stream.h>

#include <cstring>
#include <mutex>
#include <vector>

static unsigned
__to_chars_len( unsigned int __value, int __base = 10 ) noexcept
{
    unsigned __n = 1;
    const unsigned __b2 = __base * __base;
    const unsigned __b3 = __b2 * __base;
    const unsigned long __b4 = __b3 * __base;
    for ( ;; )
    {
        if ( __value < ( unsigned )__base )
            return __n;
        if ( __value < __b2 )
            return __n + 1;
        if ( __value < __b3 )
            return __n + 2;
        if ( __value < __b4 )
            return __n + 3;
        __value /= __b4;
        __n += 4;
    }
}

static void
__to_chars_10_impl( char *__first, unsigned __len, unsigned int __val ) noexcept
{
    constexpr char __digits[ 201 ] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    unsigned __pos = __len - 1;
    while ( __val >= 100 )
    {
        auto const __num = ( __val % 100 ) * 2;
        __val /= 100;
        __first[ __pos ] = __digits[ __num + 1 ];
        __first[ __pos - 1 ] = __digits[ __num ];
        __pos -= 2;
    }
    if ( __val >= 10 )
    {
        auto const __num = __val * 2;
        __first[ 1 ] = __digits[ __num + 1 ];
        __first[ 0 ] = __digits[ __num ];
    }
    else
        __first[ 0 ] = '0' + __val;
}

struct c_byte_stream::impl_t
{
    mutable std::recursive_mutex mutex;
    std::vector< unsigned char > container;

    bool
    try_lock() const;

    void
    wait_lock() const;

    void
    unlock() const;

    e_status
    push( const unsigned char *source, size_t size );

    e_status
    push_back( const unsigned char *source, size_t size );

    e_status
    pull( unsigned char *destination, size_t &size, size_t offset );

    e_status
    pull_back( unsigned char *destination, size_t &size, size_t offset );

    e_status
    move( const c_byte_stream *destination, size_t size, size_t offset );

    e_status
    copy( unsigned char *destination, size_t size, size_t *available, size_t offset ) const;

    e_status
    pop( size_t size );

    e_status
    pop_back( size_t size );

    e_status
    erase( size_t start, size_t size );

    void
    flush();

    int
    compare( const unsigned char *pattern, size_t size, size_t offset, size_t end ) const;

    size_t
    index_of( int val, size_t offset, size_t end );

    size_t
    index_of( const unsigned char *pattern, size_t size, size_t offset, size_t end ) const;

    size_t
    index_of_back( int val, size_t offset, size_t end ) const;

    size_t
    index_of_back( const unsigned char *pattern, size_t size, size_t offset, size_t end ) const;

    unsigned char *
    pointer( size_t offset ) const;

    bool
    is_utf8() const;

    e_status
    to_utf8();
};

bool
c_byte_stream::impl_t::try_lock() const
{
    return mutex.try_lock();
}

void
c_byte_stream::impl_t::wait_lock() const
{
    mutex.lock();
}

void
c_byte_stream::impl_t::unlock() const
{
    mutex.unlock();
}

c_byte_stream::
    c_byte_stream()
{
    impl = new impl_t();
}

c_byte_stream::
    c_byte_stream( const c_byte_stream &other )
{
    impl = new impl_t();

    std::lock( impl->mutex, other.impl->mutex );
    std::lock_guard< std::recursive_mutex > lhs_lock( impl->mutex, std::adopt_lock );
    std::lock_guard< std::recursive_mutex > rhs_lock( other.impl->mutex, std::adopt_lock );

    impl->container = other.impl->container;
}

c_byte_stream &
c_byte_stream::operator=( const c_byte_stream &other )
{
    if ( this == &other )
    {
        return *this;
    }

    std::lock( impl->mutex, other.impl->mutex );
    std::lock_guard< std::recursive_mutex > lhs_lock( impl->mutex, std::adopt_lock );
    std::lock_guard< std::recursive_mutex > rhs_lock( other.impl->mutex, std::adopt_lock );

    impl->container = other.impl->container;

    return *this;
}

c_byte_stream::
    c_byte_stream( c_byte_stream &&other ) noexcept
{
    impl = other.impl;
    other.impl = nullptr;
}

c_byte_stream &
c_byte_stream::operator=( c_byte_stream &&other ) noexcept
{
    if ( this == &other )
    {
        return *this;
    }

    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }

    impl = other.impl;
    other.impl = nullptr;

    return *this;
}

c_byte_stream::~c_byte_stream()
{
    if ( impl )
    {
        delete impl;
        impl = nullptr;
    }
}

c_byte_stream &
c_byte_stream::operator<<( const unsigned char value )
{
    if ( push_back( value ) != e_status::ok )
    {
        return *this;
    }

    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( const char *value )
{
    const size_t size = std::strlen( value );
    push_back( reinterpret_cast< unsigned char * >( const_cast< char * >( value ) ), size );
    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( unsigned char *value )
{
    const size_t size = std::strlen( reinterpret_cast< const char * >( value ) );
    push_back( value, size );
    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( const int value )
{
    const bool neg = value < 0;
    const auto uval = neg ? static_cast< unsigned >( ~value ) + 1u : value;
    const auto len = __to_chars_len( uval );

    const auto first = new char[ len ];

    __to_chars_10_impl( &first[ neg ], len, uval );

    push_back( reinterpret_cast< unsigned char * >( first ), neg + len );

    delete[] first;

    return *this;
}

c_byte_stream &
c_byte_stream::operator<<( const unsigned int value )
{
    const auto len = __to_chars_len( value );

    const auto first = new char[ len ];

    __to_chars_10_impl( &first[ false ], len, value );

    push_back( reinterpret_cast< unsigned char * >( first ), len );

    delete[] first;

    return *this;
}

void
c_byte_stream::close() const
{
    impl->wait_lock();

    impl->flush();

    impl->unlock();
}

void
c_byte_stream::resize( const size_t size ) const
{
    impl->wait_lock();

    impl->container.resize( size );

    impl->unlock();
}

c_byte_stream::e_status
c_byte_stream::impl_t::push( const unsigned char *source, const size_t size )
{
    try
    {
        container.insert( container.begin(), source, source + size );
    }
    catch ( const std::bad_alloc & )
    {
        return e_status::out_of_memory;
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::push_back( const unsigned char *source, const size_t size )
{
    try
    {
        container.insert( container.end(), source, source + size );
    }
    catch ( const std::bad_alloc & )
    {
        return e_status::out_of_memory;
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pull( unsigned char *destination, size_t &size, const size_t offset )
{
    if ( offset >= container.size() )
    {
        return e_status::out_of_bound;
    }

    size = std::min< size_t >( size, container.size() - offset );

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return pop( size );
}


c_byte_stream::e_status
c_byte_stream::impl_t::pull_back( unsigned char *destination, size_t &size, const size_t offset )
{
    if ( offset >= container.size() )
    {
        return e_status::out_of_bound;
    }

    size = std::min< size_t >( size, container.size() - offset );

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return pop_back( size );
}

c_byte_stream::e_status
c_byte_stream::impl_t::move( const c_byte_stream *destination, const size_t size, const size_t offset )
{
    if ( offset >= container.size() )
    {
        return e_status::out_of_bound;
    }

    if ( offset + size > container.size() )
    {
        return e_status::out_of_bound;
    }

    try
    {
        const auto begin = container.begin() + static_cast< ptrdiff_t >( offset );
        const auto end = begin + static_cast< ptrdiff_t >( size );

        destination->impl->container.insert( destination->impl->container.end(),
            std::make_move_iterator( begin ),
            std::make_move_iterator( end ) );

        container.erase( begin, end );
    }
    catch ( const std::bad_alloc & )
    {
        return e_status::out_of_memory;
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::copy( unsigned char *destination, size_t size, size_t *available, const size_t offset ) const
{
    if ( offset >= container.size() )
    {
        return e_status::out_of_bound;
    }

    size = std::min< size_t >( size, container.size() - offset );

    if ( available )
    {
        *available = size;
    }

    try
    {
        std::memcpy( destination, container.data() + offset, size );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pop( const size_t size )
{
    if ( size > container.size() )
    {
        return e_status::out_of_bound;
    }

    try
    {
        container.erase( container.begin(), container.begin() + static_cast< ptrdiff_t >( size ) );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::pop_back( const size_t size )
{
    if ( size > container.size() )
    {
        return e_status::out_of_bound;
    }

    try
    {
        container.erase( container.end() - static_cast< ptrdiff_t >( size ), container.end() );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

c_byte_stream::e_status
c_byte_stream::impl_t::erase( const size_t start, const size_t size )
{
    if ( start >= container.size() || start + size > container.size() )
    {
        return e_status::out_of_bound;
    }

    try
    {
        container.erase( container.begin() + static_cast< ptrdiff_t >( start ), container.begin() + static_cast< ptrdiff_t >( start ) + static_cast< ptrdiff_t >( size ) );
    }
    catch ( ... )
    {
        return e_status::error;
    }

    return e_status::ok;
}

void
c_byte_stream::impl_t::flush()
{
    container.clear();
}

int
c_byte_stream::impl_t::compare( const unsigned char *pattern, size_t size, const size_t offset, const size_t end ) const
{
    if ( container.empty() || size == 0 || offset >= container.size() )
    {
        return -1;
    }

    size = std::min< size_t >( size, container.size() - offset );

    const size_t n = std::min< size_t >( end, size );

    return std::memcmp( container.data() + offset, pattern, n );
}

size_t
c_byte_stream::impl_t::index_of( const int val, const size_t offset, const size_t end )
{
    if ( container.empty() || offset >= container.size() )
    {
        return npos;
    }

    size_t n = std::min( end, container.size() );

    if ( offset >= n )
    {
        return npos;
    }

    n = n - offset;

    const auto ptr = static_cast< unsigned char * >( std::memchr( container.data() + offset, static_cast< unsigned char >( val ), n ) );

    if ( ptr == nullptr )
    {
        return npos;
    }

    return ptr - container.data();
}

size_t
c_byte_stream::impl_t::index_of( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    if ( container.empty() || size == 0 || size > container.size() || offset >= container.size() )
    {
        return npos;
    }

    size_t n = std::min( end, container.size() );

    if ( offset >= n )
    {
        return npos;
    }

    n = n - size;

    for ( size_t i = offset; i <= n; ++i )
    {
        if ( compare( pattern, size, i, npos ) == 0 )
        {
            return i;
        }
    }

    return npos;
}


size_t
c_byte_stream::impl_t::index_of_back( const int val, const size_t offset, const size_t end ) const
{
    if ( container.empty() || offset >= container.size() )
    {
        return npos;
    }

    constexpr size_t b = npos;
    const size_t n = std::min< size_t >( end, b );

    for ( size_t i = offset; i != n; --i )
    {
        if ( container[ i ] == static_cast< unsigned char >( val ) )
        {
            return i;
        }
    }

    return npos;
}

size_t
c_byte_stream::impl_t::index_of_back( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    if ( container.empty() || size == 0 || size > container.size() || offset >= container.size() )
    {
        return npos;
    }

    constexpr size_t b = npos;
    const size_t n = std::min< size_t >( end, b );

    for ( size_t i = offset; i != n; --i )
    {
        if ( compare( pattern, size, i, end ) == 0 )
        {
            return i;
        }

        if ( i == 0 )
        {
            break;
        }
    }

    return npos;
}

unsigned char *
c_byte_stream::impl_t::pointer( const size_t offset ) const
{
    if ( container.empty() || offset >= container.size() )
    {
        return nullptr;
    }

    return const_cast< unsigned char * >( container.data() + offset );
}

bool
c_byte_stream::impl_t::is_utf8() const
{
    if ( container.empty() )
    {
        return false;
    }

    size_t i = 0;
    const size_t len = container.size();

    while ( i < len )
    {
        const unsigned char c = container[ i ];
        int n = 0;

        if ( c <= 0x7F )
        {
            // 1-byte ascii (0xxxxxxx)
            n = 0;
        }
        else if ( ( c & 0xE0 ) == 0xC0 )
        {
            // 2-byte sequence (110xxxxx)
            n = 1;
        }
        else if ( ( c & 0xF0 ) == 0xE0 )
        {
            // 3-byte sequence (1110xxxx)
            n = 2;
        }
        else if ( ( c & 0xF8 ) == 0xF0 )
        {
            // 4-byte sequence (11110xxx)
            n = 3;
        }
        // if ( c == 0xED && i + 1 < len && ( container[ i + 1 ] & 0xA0 ) == 0xA0 )
        // invalid surrogate half
        else
        {
            // invalid utf-8 start byte
            return false;
        }

        // verify that the `n` continuation bytes start with 10xxxxxx
        for ( int j = 0; j < n; ++j )
        {
            if ( ++i >= len || ( container[ i ] & 0xC0 ) != 0x80 )
            {
                return false;
            }
        }

        ++i;
    }

    return true;
}

c_byte_stream::e_status
c_byte_stream::impl_t::to_utf8()
{
    if ( container.empty() )
    {
        return e_status::error;
    }

    size_t i = 0;

    const size_t len = container.size();
    std::vector< unsigned char > utf8;

    while ( i < len )
    {
        const unsigned char c = container[ i ];
        int n = 0;

        if ( c <= 0x7F )
        {
            // 1-byte ASCII

            try
            {
                utf8.push_back( c );
            }
            catch ( const std::bad_alloc & )
            {
                return e_status::out_of_memory;
            }
            catch ( ... )
            {
                return e_status::error;
            }

            ++i;
        }
        else if ( ( c & 0xE0 ) == 0xC0 )
        {
            // 2-byte sequence
            n = 1;
        }
        else if ( ( c & 0xF0 ) == 0xE0 )
        {
            // 3-byte sequence
            n = 2;
        }
        else if ( ( c & 0xF8 ) == 0xF0 )
        {
            // 4-byte sequence
            n = 3;
        }
        else
        {
            return e_status::error; // invalid start byte
        }

        // check if enough continuation bytes exist
        if ( i + n >= len )
        {
            return e_status::error; // truncated sequence
        }

        for ( int j = 1; j <= n; ++j )
        {
            if ( ( container[ i + j ] & 0xC0 ) != 0x80 )
            {
                return e_status::error; // invalid continuation byte
            }
        }

        // append valid sequence
        for ( int j = 0; j <= n; ++j )
        {
            try
            {
                utf8.push_back( container[ i + j ] );
            }
            catch ( const std::bad_alloc & )
            {
                return e_status::out_of_memory;
            }
            catch ( ... )
            {
                return e_status::error;
            }
        }

        i += n + 1;
    }

    flush();

    // replace container content with converted utf-8 data
    container = std::move( utf8 );

    return e_status::ok;
}


c_byte_stream::e_status
c_byte_stream::push( const unsigned char value ) const
{
    impl->wait_lock();

    const e_status status = impl->push( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_async( const unsigned char value ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->push( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push( const unsigned char *source, const size_t size ) const
{
    impl->wait_lock();

    const e_status status = impl->push( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_async( const unsigned char *source, const size_t size ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->push( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back( const unsigned char value ) const
{
    impl->wait_lock();

    const e_status status = impl->push_back( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back_async( const unsigned char value ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->push_back( &value, 1 );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back( const unsigned char *source, const size_t size ) const
{
    impl->wait_lock();

    const e_status status = impl->push_back( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::push_back_async( const unsigned char *source, const size_t size ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->push_back( source, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull( unsigned char *destination, size_t &size, const size_t offset ) const
{
    impl->wait_lock();

    const e_status status = impl->pull( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_async( unsigned char *destination, size_t &size, const size_t offset ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->pull( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_back( unsigned char *destination, size_t &size, const size_t offset ) const
{
    impl->wait_lock();

    const e_status status = impl->pull_back( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pull_back_async( unsigned char *destination, size_t &size, const size_t offset ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->pull_back( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::move( const c_byte_stream *destination, const size_t size, const size_t offset ) const
{
    impl->wait_lock();

    const e_status status = impl->move( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::move_async( const c_byte_stream *destination, const size_t size, const size_t offset ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->move( destination, size, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::copy( unsigned char *destination, const size_t size, size_t *available, const size_t offset ) const
{
    impl->wait_lock();

    const e_status status = impl->copy( destination, size, available, offset );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::copy_async( unsigned char *destination, const size_t size, size_t *available, const size_t offset ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->copy( destination, size, available, offset );

    impl->unlock();

    return status;
}

unsigned char *
c_byte_stream::pointer( const size_t offset ) const
{
    return impl->pointer( offset );
}

c_byte_stream::e_status
c_byte_stream::pop( const size_t size ) const
{
    impl->wait_lock();

    const e_status status = impl->pop( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_async( const size_t size ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->pop( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_back( const size_t size ) const
{
    impl->wait_lock();

    const e_status status = impl->pop_back( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::pop_back_async( const size_t size ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->pop_back( size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::erase( const size_t start, const size_t size ) const
{
    impl->wait_lock();

    const e_status status = impl->erase( start, size );

    impl->unlock();

    return status;
}

c_byte_stream::e_status
c_byte_stream::erase_async( const size_t start, const size_t size ) const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    const e_status status = impl->erase( start, size );

    impl->unlock();

    return status;
}

void
c_byte_stream::flush() const
{
    impl->wait_lock();

    impl->flush();

    impl->unlock();
}

c_byte_stream::e_status
c_byte_stream::flush_async() const
{
    if ( !impl->try_lock() )
    {
        return e_status::busy;
    }

    impl->flush();

    impl->unlock();

    return e_status::ok;
}

int
c_byte_stream::compare( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    impl->wait_lock();

    const int ret = impl->compare( pattern, size, offset, end );

    impl->unlock();

    return ret;
}

int
c_byte_stream::compare_async( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    if ( !impl->try_lock() )
    {
        return -1;
    }

    const int ret = impl->compare( pattern, size, offset, end );

    impl->unlock();

    return ret;
}

size_t
c_byte_stream::index_of( const int val, const size_t offset, const size_t end ) const
{
    impl->wait_lock();

    const size_t pos = impl->index_of( val, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_async( const int val, const size_t offset, const size_t end ) const
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    const size_t pos = impl->index_of( val, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    impl->wait_lock();

    const size_t pos = impl->index_of( pattern, size, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_async( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    const size_t pos = impl->index_of( pattern, size, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back( const int val, const size_t offset, const size_t end ) const
{
    impl->wait_lock();

    const size_t pos = impl->index_of_back( val, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    impl->wait_lock();

    const size_t pos = impl->index_of_back( pattern, size, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back_async( const int val, const size_t offset, const size_t end ) const
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    const size_t pos = impl->index_of_back( val, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::index_of_back_async( const unsigned char *pattern, const size_t size, const size_t offset, const size_t end ) const
{
    if ( !impl->try_lock() )
    {
        return npos;
    }

    const size_t pos = impl->index_of_back( pattern, size, offset, end );

    impl->unlock();

    return pos;
}

size_t
c_byte_stream::size() const
{
    return impl->container.size();
}

std::vector< unsigned char > *
c_byte_stream::container() const
{
    return &impl->container;
}


bool
c_byte_stream::available() const
{
    return size() > 0;
}

bool
c_byte_stream::is_utf8() const
{
    return impl->is_utf8();
}

c_byte_stream::e_status
c_byte_stream::to_utf8() const
{
    return impl->to_utf8();
}
