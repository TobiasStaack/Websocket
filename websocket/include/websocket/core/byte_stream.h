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

#include <vector>

/** \cond */
class c_byte_stream final
{
public:
    enum class e_status
    {
        ok = 0, /**< Operation succeeded. */
        error, /**< An error occurred during the operation. */
        busy, /**< The pipe is currently busy. */
        out_of_memory, /**< Memory allocation failed. */
        out_of_bound /**< Operation attempted to access out-of-bound memory. */
    };

#if defined( _WIN64 ) || defined( __x86_64__ ) || defined( __ppc64__ )
    static constexpr size_t npos = ~0LLU; /**< Represents an invalid index for 64-bit systems. */
#else
    static constexpr size_t npos = ~0U; /**< Represents an invalid index for 32-bit systems. */
#endif

    c_byte_stream();

    c_byte_stream( const c_byte_stream &other );

    c_byte_stream &
    operator=( const c_byte_stream &other );

    c_byte_stream( c_byte_stream &&other ) noexcept;

    c_byte_stream &
    operator=( c_byte_stream &&other ) noexcept;

    ~
    c_byte_stream();

    c_byte_stream &
    operator<<( unsigned char value );

    c_byte_stream &
    operator<<( const char *value );

    c_byte_stream &
    operator<<( const unsigned char *value );

    c_byte_stream &
    operator<<( int value );

    c_byte_stream &
    operator<<( unsigned int value );

    void
    close() const;

    void
    resize( size_t size ) const;

    e_status
    push( const unsigned char value ) const;

    e_status
    push_async( const unsigned char value ) const;

    e_status
    push( const unsigned char *source, size_t size ) const;

    e_status
    push_async( const unsigned char *source, size_t size ) const;

    e_status
    push_back( const unsigned char value ) const;

    e_status
    push_back_async( const unsigned char value ) const;

    e_status
    push_back( const unsigned char *source, size_t size ) const;

    e_status
    push_back_async( const unsigned char *source, size_t size ) const;

    void
    pull( unsigned char* destination, size_t& size, size_t offset = 0 ) const;

    e_status
    pull_async( unsigned char *destination, size_t &size, size_t offset = 0 ) const;

    void
    pull_back( unsigned char* destination, size_t& size, size_t offset = 0 ) const;

    e_status
    pull_back_async( unsigned char *destination, size_t &size, size_t offset = 0 ) const;

    e_status
    move( const c_byte_stream *destination, size_t size, size_t offset ) const;

    e_status
    move_async( const c_byte_stream *destination, size_t size, size_t offset ) const;

    void
    copy( unsigned char* destination, size_t size, size_t* available = nullptr, size_t offset = 0 ) const;

    e_status
    copy_async( unsigned char *destination, size_t size, size_t *available = nullptr, size_t offset = 0 ) const;

    unsigned char *
    pointer( size_t offset = 0 ) const;

    void
    pop( size_t size ) const;

    e_status
    pop_async( size_t size ) const;

    void
    pop_back( size_t size ) const;

    e_status
    pop_back_async( size_t size ) const;

    void
    erase( size_t start, size_t size ) const;

    e_status
    erase_async( size_t start, size_t size ) const;

    void
    flush() const;

    e_status
    flush_async() const;

    int
    compare( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    int
    compare_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of( int val, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_async( int val, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_back( int val, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_back_async( int val, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_back( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    size_t
    index_of_back_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    size_t
    size() const;

    std::vector< unsigned char > *
    container() const;

    bool
    available() const;

    bool
    is_utf8() const;

    e_status
    to_utf8() const;

private:
    struct impl_t;
    impl_t *impl;
};
/** \endcond */
