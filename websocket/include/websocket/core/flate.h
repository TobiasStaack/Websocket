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

#include <websocket/core/byte_stream.h>

/**
 * @class c_flate
 * @brief Provides methods for compressing and decompressing byte streams using the DEFLATE algorithm.
 *
 * This class utilizes the zlib library for implementing the DEFLATE algorithm as specified in
 * the relevant RFCs, ensuring efficient and effective compression and decompression of data.
 */
class c_flate
{
public:
    /**
     * @enum e_status
     * @brief Enumeration representing the status of compression and decompression operations.
     */
    enum class e_status : unsigned char
    {
        status_ok = 0x0,   /**< Operation completed successfully. */
        status_error = 0x1 /**< An error occurred during the operation. */
    };

    /**
     * @brief Compresses the input byte stream using the DEFLATE algorithm.
     *
     * This method uses zlib for compression as per the specified RFCs.
     *
     * @param input Pointer to the input byte stream to be compressed.
     * @param output Pointer to the output byte stream where compressed data will be stored.
     * @param window_bits Size of the sliding window to use for compression.
     *
     * @return e_status The status of the compression operation.
     */
    static e_status
    deflate( const c_byte_stream* input, const c_byte_stream* output, unsigned char window_bits );

    /**
     * @brief Decompresses the input byte stream using the DEFLATE algorithm.
     *
     * This method uses zlib for decompression as per the specified RFCs.
     *
     * @param input Pointer to the input byte stream to be decompressed.
     * @param output Pointer to the output byte stream where decompressed data will be stored.
     * @param window_bits Size of the sliding window to use for decompression.
     *
     * @return e_status The status of the decompression operation.
     */
    static e_status
    inflate( const c_byte_stream* input, const c_byte_stream* output, unsigned char window_bits );
};
