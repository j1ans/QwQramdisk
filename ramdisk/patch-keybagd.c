/* Patch the installed iOS 7 keybagd after /mnt1 is mounted. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const unsigned char get_system_result[] = {
    0xe8, 0xff, 0xa3, 0x12, 0x08, 0x5e, 0x80, 0x72,
    0x1f, 0x00, 0x08, 0x6b
};
static const unsigned char nop[] = {0x1f, 0x20, 0x03, 0xd5};
static const char old_path[] = "/private/var";
static const char new_path[] = "/mnt2//././.";

int main(int argc, char **argv)
{
    FILE *input = NULL, *output = NULL;
    unsigned char *data = NULL;
    long length;
    size_t size, i, branch = 0, branches = 0, paths = 0;
    uint32_t instruction;
    int result = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: patch-keybagd SOURCE DESTINATION\n");
        return 1;
    }
    input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END) != 0 ||
        (length = ftell(input)) < 0 || fseek(input, 0, SEEK_SET) != 0 ||
        length < 16 || length > 4 * 1024 * 1024) {
        fprintf(stderr, "patch-keybagd: cannot read source: %s\n", argv[1]);
        goto done;
    }
    size = (size_t)length;
    data = malloc(size);
    if (!data || fread(data, 1, size, input) != size) {
        fprintf(stderr, "patch-keybagd: short read or out of memory\n");
        goto done;
    }
    /* arm64 Mach-O, little endian. Never patch an unrecognized file. */
    if (memcmp(data, "\xcf\xfa\xed\xfe\x0c\0\0\x01", 8) != 0) {
        fprintf(stderr, "patch-keybagd: source is not arm64 Mach-O\n");
        goto done;
    }
    for (i = 0; i + sizeof(old_path) - 1 <= size; ++i) {
        if (memcmp(data + i, old_path, sizeof(old_path) - 1) == 0) {
            memcpy(data + i, new_path, sizeof(new_path) - 1);
            ++paths;
            i += sizeof(old_path) - 2;
        }
    }
    for (i = 0; i + sizeof(get_system_result) + 4 <= size; ++i) {
        if (memcmp(data + i, get_system_result,
                   sizeof(get_system_result)) == 0) {
            branch = i + sizeof(get_system_result);
            ++branches;
        }
    }
    if (!paths || branches != 1) {
        fprintf(stderr, "patch-keybagd: expected paths and one system-bag branch; "
                "found %zu paths, %zu branches\n", paths, branches);
        goto done;
    }
    instruction = (uint32_t)data[branch] |
        (uint32_t)data[branch + 1] << 8 |
        (uint32_t)data[branch + 2] << 16 |
        (uint32_t)data[branch + 3] << 24;
    if ((instruction & 0xff00001fU) != 0x54000001U) {
        fprintf(stderr, "patch-keybagd: unexpected conditional branch\n");
        goto done;
    }
    memcpy(data + branch, nop, sizeof(nop));
    output = fopen(argv[2], "wb");
    if (!output || fwrite(data, 1, size, output) != size ||
        fflush(output) != 0 || chmod(argv[2], 0755) != 0) {
        fprintf(stderr, "patch-keybagd: cannot write destination: %s\n", argv[2]);
        goto done;
    }
    fprintf(stderr, "patch-keybagd: relocated %zu paths; patched system-bag "
            "branch at 0x%zx\n", paths, branch);
    result = 0;
done:
    if (output)
        fclose(output);
    if (input)
        fclose(input);
    free(data);
    return result;
}
