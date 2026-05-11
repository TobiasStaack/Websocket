#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
enum class e_ws_frame_status : unsigned char
{
    status_ok = 0x0, /**< Status indicates all is OK */
    status_error = 0x1, /**< Status indicates an error occurred */
    status_invalid_data = 0x2, /**< Status indicates message is not valid */
    status_incomplete = 0x3, /**< Status indicates message is waiting for more information */
    status_fragment = 0x4, /**< Status indicates a message fragment was processed */
    status_final = 0x5 /**< Status indicates the message is final */
};
#endif

#ifdef __cplusplus
enum e_ws_frame_opcode : unsigned char
#else
typedef enum e_ws_frame_opcode
#endif
{
    opcode_continuation = 0x0,
    opcode_text = 0x1,
    opcode_binary = 0x2,
    opcode_rsv1_further_non_control = 0x3,
    opcode_rsv2_further_non_control = 0x4,
    opcode_rsv3_further_non_control = 0x5,
    opcode_rsv4_further_non_control = 0x6,
    opcode_rsv5_further_non_control = 0x7,
    opcode_close = 0x8,
    opcode_ping = 0x9,
    opcode_pong = 0xA,
    opcode_rsv1_further_control = 0xB,
    opcode_rsv2_further_control = 0xC,
    opcode_rsv3_further_control = 0xD,
    opcode_rsv4_further_control = 0xE,
    opcode_rsv5_further_control = 0xF
}
#ifdef __cplusplus
;
#else
e_ws_frame_opcode;
#endif

#ifdef __cplusplus
}
#endif
