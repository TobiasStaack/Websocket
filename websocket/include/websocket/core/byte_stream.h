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

#include <cstddef>
#include <vector>

/** \cond */

/**
 * @class c_byte_stream
 * @brief Growable byte buffer used for the socket streams and frame payloads.
 *
 * Bytes are appended at either end and taken from either end, which is what framing needs:
 * received data is appended at the back and consumed from the front once a frame is complete.
 * Every method marked `_async` performs the same work but reports a status instead of
 * failing silently, so a caller can react to an allocation problem.
 */
class c_byte_stream final
{
public:
    /**
     * @enum e_status
     * @brief Outcome of a stream operation.
     */
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

    /**
     * @brief Creates an empty stream.
     */
    c_byte_stream();

    /**
     * @brief Creates a stream holding a copy of another stream's bytes.
     *
     * @param[in] other The stream to copy.
     */
    c_byte_stream( const c_byte_stream &other );

    /**
     * @brief Replaces this stream with a copy of another stream.
     *
     * @param[in] other The stream to copy.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator=( const c_byte_stream &other );

    /**
     * @brief Takes over another stream's bytes, leaving it empty.
     *
     * @param[in,out] other The stream to move from.
     */
    c_byte_stream( c_byte_stream &&other ) noexcept;

    /**
     * @brief Replaces this stream by taking over another stream's bytes.
     *
     * @param[in,out] other The stream to move from.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator=( c_byte_stream &&other ) noexcept;

    /**
     * @brief Releases the buffer held by the stream.
     */
    ~
    c_byte_stream();

    /**
     * @brief Appends a single byte.
     *
     * @param[in] value The byte to append.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator<<( unsigned char value );

    /**
     * @brief Appends a null terminated string without its terminator.
     *
     * @param[in] value The string to append.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator<<( const char *value );

    /**
     * @brief Appends a null terminated byte sequence without its terminator.
     *
     * @param[in] value The sequence to append.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator<<( const unsigned char *value );

    /**
     * @brief Appends the decimal representation of a signed integer.
     *
     * @param[in] value The value to append.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator<<( int value );

    /**
     * @brief Appends the decimal representation of an unsigned integer.
     *
     * @param[in] value The value to append.
     * @return A reference to this stream.
     */
    c_byte_stream &
    operator<<( unsigned int value );

    /**
     * @brief Drops all bytes and releases the buffer.
     */
    void
    close() const;

    /**
     * @brief Resizes the stream, new bytes are zero initialized.
     *
     * @param[in] size The new size in bytes.
     */
    void
    resize( size_t size ) const;

    /**
     * @brief Inserts a single byte at the front.
     *
     * @param[in] value The byte to insert.
     * @return `ok` on success, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push( unsigned char value ) const;

    /**
     * @brief Inserts a single byte at the front once the stream is free.
     *
     * @param[in] value The byte to insert.
     * @return `ok` on success, `busy` when the stream is in use, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_async( unsigned char value ) const;

    /**
     * @brief Inserts a block of bytes at the front.
     *
     * @param[in] source Pointer to the bytes to insert.
     * @param[in] size Number of bytes to insert.
     * @return `ok` on success, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push( const unsigned char *source, size_t size ) const;

    /**
     * @brief Inserts a block of bytes at the front once the stream is free.
     *
     * @param[in] source Pointer to the bytes to insert.
     * @param[in] size Number of bytes to insert.
     * @return `ok` on success, `busy` when the stream is in use, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_async( const unsigned char *source, size_t size ) const;

    /**
     * @brief Appends a single byte at the back.
     *
     * @param[in] value The byte to append.
     * @return `ok` on success, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_back( unsigned char value ) const;

    /**
     * @brief Appends a single byte at the back once the stream is free.
     *
     * @param[in] value The byte to append.
     * @return `ok` on success, `busy` when the stream is in use, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_back_async( unsigned char value ) const;

    /**
     * @brief Appends a block of bytes at the back.
     *
     * @param[in] source Pointer to the bytes to append.
     * @param[in] size Number of bytes to append.
     * @return `ok` on success, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_back( const unsigned char *source, size_t size ) const;

    /**
     * @brief Appends a block of bytes at the back once the stream is free.
     *
     * @param[in] source Pointer to the bytes to append.
     * @param[in] size Number of bytes to append.
     * @return `ok` on success, `busy` when the stream is in use, `out_of_memory` when the buffer could not grow.
     */
    e_status
    push_back_async( const unsigned char *source, size_t size ) const;

    /**
     * @brief Copies bytes out of the front and removes them.
     *
     * @param[out] destination Receives the bytes.
     * @param[in,out] size Number of bytes requested, set to the number actually taken.
     * @param[in] offset Offset from the front to start at.
     */
    void
    pull( unsigned char* destination, size_t& size, size_t offset = 0 ) const;

    /**
     * @brief Copies bytes out of the front and removes them, once the stream is free.
     *
     * @param[out] destination Receives the bytes.
     * @param[in,out] size Number of bytes requested, set to the number actually taken.
     * @param[in] offset Offset from the front to start at.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    pull_async( unsigned char *destination, size_t &size, size_t offset = 0 ) const;

    /**
     * @brief Copies bytes out of the back and removes them.
     *
     * @param[out] destination Receives the bytes.
     * @param[in,out] size Number of bytes requested, set to the number actually taken.
     * @param[in] offset Offset from the back to start at.
     */
    void
    pull_back( unsigned char* destination, size_t& size, size_t offset = 0 ) const;

    /**
     * @brief Copies bytes out of the back and removes them, once the stream is free.
     *
     * @param[out] destination Receives the bytes.
     * @param[in,out] size Number of bytes requested, set to the number actually taken.
     * @param[in] offset Offset from the back to start at.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    pull_back_async( unsigned char *destination, size_t &size, size_t offset = 0 ) const;

    /**
     * @brief Transfers bytes into another stream, removing them from this one.
     *
     * @param[out] destination Stream receiving the bytes at its back.
     * @param[in] size Number of bytes to transfer.
     * @param[in] offset Offset from the front to start at.
     * @return `ok` on success, `out_of_bound` when the range exceeds the stream, `out_of_memory` when the destination could not grow.
     */
    e_status
    move( const c_byte_stream *destination, size_t size, size_t offset ) const;

    /**
     * @brief Transfers bytes into another stream once the stream is free.
     *
     * @param[out] destination Stream receiving the bytes at its back.
     * @param[in] size Number of bytes to transfer.
     * @param[in] offset Offset from the front to start at.
     * @return `ok` on success, `busy` when the stream is in use, `out_of_bound` when the range exceeds the stream.
     */
    e_status
    move_async( const c_byte_stream *destination, size_t size, size_t offset ) const;

    /**
     * @brief Copies bytes out without removing them.
     *
     * The copy is clamped to what the stream holds, so a short stream yields fewer bytes
     * rather than reading past its end.
     *
     * @param[out] destination Receives the bytes.
     * @param[in] size Number of bytes to copy.
     * @param[out] available Receives the number of bytes actually copied, may be NULL.
     * @param[in] offset Offset from the front to start at.
     */
    void
    copy( unsigned char* destination, size_t size, size_t* available = 0, size_t offset = 0 ) const;

    /**
     * @brief Copies bytes out without removing them, once the stream is free.
     *
     * @param[out] destination Receives the bytes.
     * @param[in] size Number of bytes to copy.
     * @param[out] available Receives the number of bytes actually copied, may be NULL.
     * @param[in] offset Offset from the front to start at.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    copy_async( unsigned char *destination, size_t size, size_t *available = 0, size_t offset = 0 ) const;

    /**
     * @brief Returns a pointer into the stream's bytes.
     *
     * The pointer is invalidated by any operation that changes the stream.
     *
     * @param[in] offset Offset from the front.
     * @return Pointer to the byte at the offset, or 0 when the offset is out of bounds.
     */
    unsigned char *
    pointer( size_t offset = 0 ) const;

    /**
     * @brief Removes bytes from the front.
     *
     * @param[in] size Number of bytes to remove, ignored when it exceeds the stream.
     */
    void
    pop( size_t size ) const;

    /**
     * @brief Removes bytes from the front once the stream is free.
     *
     * @param[in] size Number of bytes to remove.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    pop_async( size_t size ) const;

    /**
     * @brief Removes bytes from the back.
     *
     * @param[in] size Number of bytes to remove, ignored when it exceeds the stream.
     */
    void
    pop_back( size_t size ) const;

    /**
     * @brief Removes bytes from the back once the stream is free.
     *
     * @param[in] size Number of bytes to remove.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    pop_back_async( size_t size ) const;

    /**
     * @brief Removes a range of bytes from anywhere in the stream.
     *
     * @param[in] start Offset of the first byte to remove.
     * @param[in] size Number of bytes to remove.
     */
    void
    erase( size_t start, size_t size ) const;

    /**
     * @brief Removes a range of bytes once the stream is free.
     *
     * @param[in] start Offset of the first byte to remove.
     * @param[in] size Number of bytes to remove.
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    erase_async( size_t start, size_t size ) const;

    /**
     * @brief Drops all bytes but keeps the allocated buffer.
     */
    void
    flush() const;

    /**
     * @brief Drops all bytes once the stream is free.
     *
     * @return `ok` on success, `busy` when the stream is in use.
     */
    e_status
    flush_async() const;

    /**
     * @brief Compares a byte pattern against a range of the stream.
     *
     * @param[in] pattern The bytes to compare against.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start comparing at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return 0 when the range matches, a non zero value otherwise.
     */
    int
    compare( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Compares a byte pattern once the stream is free.
     *
     * @param[in] pattern The bytes to compare against.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start comparing at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return 0 when the range matches, a non zero value otherwise.
     */
    int
    compare_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches forward for a single byte.
     *
     * @param[in] val The byte to look for.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the first match, or `npos` when the byte does not occur.
     */
    size_t
    index_of( int val, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches forward for a single byte once the stream is free.
     *
     * @param[in] val The byte to look for.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the first match, or `npos` when the byte does not occur.
     */
    size_t
    index_of_async( int val, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches forward for a byte pattern.
     *
     * @param[in] pattern The bytes to look for.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the first match, or `npos` when the pattern does not occur.
     */
    size_t
    index_of( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches forward for a byte pattern once the stream is free.
     *
     * @param[in] pattern The bytes to look for.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the first match, or `npos` when the pattern does not occur.
     */
    size_t
    index_of_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches backward for a single byte.
     *
     * @param[in] val The byte to look for.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the last match, or `npos` when the byte does not occur.
     */
    size_t
    index_of_back( int val, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches backward for a single byte once the stream is free.
     *
     * @param[in] val The byte to look for.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the last match, or `npos` when the byte does not occur.
     */
    size_t
    index_of_back_async( int val, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches backward for a byte pattern.
     *
     * @param[in] pattern The bytes to look for.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the last match, or `npos` when the pattern does not occur.
     */
    size_t
    index_of_back( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Searches backward for a byte pattern once the stream is free.
     *
     * @param[in] pattern The bytes to look for.
     * @param[in] size Length of the pattern.
     * @param[in] offset Offset to start searching at.
     * @param[in] end Offset to stop at, `npos` for the end of the stream.
     * @return Offset of the last match, or `npos` when the pattern does not occur.
     */
    size_t
    index_of_back_async( const unsigned char *pattern, size_t size, size_t offset = 0, size_t end = npos ) const;

    /**
     * @brief Retrieves the number of bytes held by the stream.
     *
     * @return The size in bytes.
     */
    size_t
    size() const;

    /**
     * @brief Returns the underlying container.
     *
     * @return Pointer to the container backing the stream.
     */
    std::vector< unsigned char > *
    container() const;

    /**
     * @brief Checks whether the stream holds any bytes.
     *
     * @return `true` when the stream is not empty.
     */
    bool
    available() const;

    /**
     * @brief Checks whether the stream holds well formed UTF-8.
     *
     * Overlong encodings, surrogate halves and code points beyond U+10FFFF are rejected.
     * An empty stream is valid UTF-8.
     *
     * @return `true` when the bytes form valid UTF-8.
     */
    bool
    is_utf8() const;

    /**
     * @brief Rewrites the stream so it holds well formed UTF-8.
     *
     * Invalid sequences are replaced with U+FFFD, a stream that is already valid is left alone.
     *
     * @return `ok` on success, `out_of_memory` when the buffer could not grow.
     */
    e_status
    to_utf8() const;

private:
    struct impl_t; /**< @brief Opaque stream state, kept out of the public header. */
    impl_t *impl;  /**< @brief Pointer to the stream state. */
};
/** \endcond */
