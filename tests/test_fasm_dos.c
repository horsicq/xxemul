#include "xxemul/xxemul.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define CHECK(test) do { \
    if (!(test)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #test); \
        return 1; \
    } \
} while (0)

typedef struct output_buffer {
    char text[256];
    size_t length;
} output_buffer;

static void capture_output(void *context, uint8_t byte)
{
    output_buffer *output = (output_buffer *)context;

    if (output->length + 1u < sizeof(output->text)) {
        output->text[output->length++] = (char)byte;
        output->text[output->length] = '\0';
    }
}

int main(int argc, char **argv)
{
    static const uint8_t expected[] = {
        0xb4, 0x09, 0xba, 0x09, 0x01, 0xcd, 0x21, 0xcd,
        0x20, 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r',
        'l', 'd', '!', '$'
    };
    const char *guest_argv[3];
    xxemul_status status;
    xxemul *emulator;
    output_buffer output = {{0}, 0u};
    char output_path[1024];
    uint8_t bytes[sizeof(expected) + 1u];
    uint8_t exit_code;
    int path_length;
    FILE *file;

    CHECK(argc == 3);
    path_length = snprintf(output_path, sizeof(output_path),
        "%s/COMDEMO.COM", argv[2]);
    CHECK(path_length >= 0 && (size_t)path_length < sizeof(output_path));
    CHECK(remove(output_path) == 0 || errno == ENOENT);
    guest_argv[0] = argv[1];
    guest_argv[1] = "COMDEMO.ASM";
    guest_argv[2] = "COMDEMO.COM";
    emulator = xxemul_create_image_file(XXEMUL_IMAGE_MZ, argv[1], &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_MZ,
        argv[1], argv[2], 3, guest_argv) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 1000000u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code) == XXEMUL_STATUS_OK);
    CHECK(exit_code == 0u);
    xxemul_destroy(emulator);

    file = fopen(output_path, "rb");
    CHECK(file != NULL);
    CHECK(fread(bytes, 1u, sizeof(bytes), file) == sizeof(expected));
    CHECK(memcmp(bytes, expected, sizeof(expected)) == 0);
    CHECK(fclose(file) == 0);

    emulator = xxemul_create_image_file(XXEMUL_IMAGE_COM,
        output_path, &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_dos_set_output_callback(emulator,
        capture_output, &output) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 100u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code) == XXEMUL_STATUS_OK);
    CHECK(exit_code == 0u);
    CHECK(strcmp(output.text, "Hello world!") == 0);
    xxemul_destroy(emulator);

    path_length = snprintf(output_path, sizeof(output_path),
        "%s/EXEDEMO.EXE", argv[2]);
    CHECK(path_length >= 0 && (size_t)path_length < sizeof(output_path));
    CHECK(remove(output_path) == 0 || errno == ENOENT);
    guest_argv[1] = "EXEDEMO.ASM";
    guest_argv[2] = "EXEDEMO.EXE";
    emulator = xxemul_create_image_file(XXEMUL_IMAGE_MZ, argv[1], &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_start_process(emulator, XXEMUL_IMAGE_MZ,
        argv[1], argv[2], 3, guest_argv) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 1000000u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code) == XXEMUL_STATUS_OK);
    CHECK(exit_code == 0u);
    xxemul_destroy(emulator);

    file = fopen(output_path, "rb");
    CHECK(file != NULL);
    CHECK(fseek(file, 0, SEEK_END) == 0 && ftell(file) == 59L);
    CHECK(fseek(file, 0, SEEK_SET) == 0);
    CHECK(fread(bytes, 1u, 2u, file) == 2u);
    CHECK(bytes[0] == 'M' && bytes[1] == 'Z');
    CHECK(fclose(file) == 0);

    output.length = 0u;
    output.text[0] = '\0';
    emulator = xxemul_create_image_file(XXEMUL_IMAGE_MZ,
        output_path, &status);
    CHECK(emulator != NULL && status == XXEMUL_STATUS_OK);
    CHECK(xxemul_dos_set_output_callback(emulator,
        capture_output, &output) == XXEMUL_STATUS_OK);
    CHECK(xxemul_run(emulator, 100u, NULL) == XXEMUL_STATUS_HALTED);
    CHECK(xxemul_dos_get_exit_code(emulator, &exit_code) == XXEMUL_STATUS_OK);
    CHECK(exit_code == 0u);
    CHECK(strcmp(output.text, "Hello world!") == 0);
    xxemul_destroy(emulator);
    return 0;
}
