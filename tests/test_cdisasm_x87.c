#include <cdisasm/cdisasm.h>

#include <stdio.h>

int main(void)
{
    static const uint8_t code[] = {0xdf, 0x2c, 0x24};
    cdisasm_x86_instruction instruction;
    cdisasm_x86_decode_flags flags;
    if (cdisasm_x86_cpu_decode_flag_mask(
            CDISASM_CPU_X86, CDISASM_X86_MODE_32,
            &flags) != CDISASM_STATUS_OK) {
        return 1;
    }
    uint32_t size = cdisasm_x86_decode(
        CDISASM_CPU_X86, CDISASM_X86_MODE_32,
        code, sizeof(code), 0x1000u, &flags, &instruction);

    if (size != sizeof(code)
        || instruction.name_id != CDISASM_X86_NAME_FILD) {
        fprintf(stderr, "FILD decode: size=%u error=%u name=%u\n",
            size, instruction.last_error_id, instruction.name_id);
        return 1;
    }
    return 0;
}
