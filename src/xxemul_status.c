#include "xxemul/xxemul.h"

/* Keep status formatting independent of the native CPU backends so a DEX
 * client does not pull them into its static link. */
const char *xxemul_status_string(xxemul_status status)
{
    switch (status) {
        case XXEMUL_STATUS_OK: return "ok";
        case XXEMUL_STATUS_HALTED: return "halted";
        case XXEMUL_STATUS_LIMIT_REACHED: return "instruction limit reached";
        case XXEMUL_STATUS_INVALID_ARGUMENT: return "invalid argument";
        case XXEMUL_STATUS_OUT_OF_MEMORY: return "out of memory";
        case XXEMUL_STATUS_ADDRESS_FAULT: return "address fault";
        case XXEMUL_STATUS_DECODE_ERROR: return "decode error";
        case XXEMUL_STATUS_UNSUPPORTED_INSTRUCTION: return "unsupported instruction";
        case XXEMUL_STATUS_IO_ERROR: return "I/O error";
        case XXEMUL_STATUS_INVALID_IMAGE: return "invalid executable image";
        case XXEMUL_STATUS_INPUT_REQUIRED: return "keyboard input required";
        case XXEMUL_STATUS_UNSUPPORTED_IMAGE: return "unsupported executable image";
        case XXEMUL_STATUS_BREAKPOINT: return "breakpoint";
        default: return "unknown status";
    }
}
