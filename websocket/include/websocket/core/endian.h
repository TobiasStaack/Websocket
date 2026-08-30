#pragma once

/** \cond */

/**
 * @class c_endian
 * @brief Converts integers between host byte order and the byte orders used on the wire.
 *
 * WebSocket carries its extended payload lengths in network byte order, so a frame has to
 * be translated in both directions regardless of what the host uses natively.
 */
class c_endian final
{
public:
    /**
     * @brief Converts a 16-bit value from host to network byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in network byte order.
     */
    static unsigned short
    host_to_network_16( unsigned short value );

    /**
     * @brief Converts a 32-bit value from host to network byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in network byte order.
     */
    static unsigned int
    host_to_network_32( unsigned int value );

    /**
     * @brief Converts a 64-bit value from host to network byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in network byte order.
     */
    static unsigned long long
    host_to_network_64( unsigned long long value );

    /**
     * @brief Converts a 16-bit value from network to host byte order.
     *
     * @param[in] value The value in network byte order.
     * @return The value in host byte order.
     */
    static unsigned short
    network_to_host_16( unsigned short value );

    /**
     * @brief Converts a 32-bit value from network to host byte order.
     *
     * @param[in] value The value in network byte order.
     * @return The value in host byte order.
     */
    static unsigned int
    network_to_host_32( unsigned int value );

    /**
     * @brief Converts a 64-bit value from network to host byte order.
     *
     * @param[in] value The value in network byte order.
     * @return The value in host byte order.
     */
    static unsigned long long
    network_to_host_64( unsigned long long value );

    /**
     * @brief Converts a 16-bit value from host to little endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in little endian byte order.
     */
    static unsigned short
    little_endian_16( unsigned short value );

    /**
     * @brief Converts a 32-bit value from host to little endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in little endian byte order.
     */
    static unsigned int
    little_endian_32( unsigned int value );

    /**
     * @brief Converts a 64-bit value from host to little endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in little endian byte order.
     */
    static unsigned long long
    little_endian_64( unsigned long long value );

    /**
     * @brief Converts a 16-bit value from host to big endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in big endian byte order.
     */
    static unsigned short
    big_endian_16( unsigned short value );

    /**
     * @brief Converts a 32-bit value from host to big endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in big endian byte order.
     */
    static unsigned int
    big_endian_32( unsigned int value );

    /**
     * @brief Converts a 64-bit value from host to big endian byte order.
     *
     * @param[in] value The value in host byte order.
     * @return The value in big endian byte order.
     */
    static unsigned long long
    big_endian_64( unsigned long long value );

    /**
     * @brief Checks whether the host stores integers least significant byte first.
     *
     * @return `true` on a little endian host.
     */
    static bool
    is_little();

    /**
     * @brief Checks whether the host stores integers most significant byte first.
     *
     * @return `true` on a big endian host.
     */
    static bool
    is_big();

private:
    /**
     * @brief Reverses the bytes of a 16-bit value.
     *
     * @param[in] value The value to reverse.
     * @return The value with its bytes reversed.
     *
     * @internal
     */
    static unsigned short
    swap_16( unsigned short value );

    /**
     * @brief Reverses the bytes of a 32-bit value.
     *
     * @param[in] value The value to reverse.
     * @return The value with its bytes reversed.
     *
     * @internal
     */
    static unsigned int
    swap_32( unsigned int value );

    /**
     * @brief Reverses the bytes of a 64-bit value.
     *
     * @param[in] value The value to reverse.
     * @return The value with its bytes reversed.
     *
     * @internal
     */
    static unsigned long long
    swap_64( unsigned long long value );
};
/** \endcond */
