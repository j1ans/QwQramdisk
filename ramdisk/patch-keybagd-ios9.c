/* Fixed, fail-closed iOS 9 system-keybag patcher for known source hashes.
 * Compile once for the ramdisk; no compiler or signing runs during create.
 */
#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct patch {
    size_t offset;
    unsigned char before[4];
    unsigned char after[4];
};

struct profile {
    const char *build;
    size_t size;
    unsigned paths;
    const char *source_sha256;
    const char *result_sha256;
    const struct patch *patches;
    size_t patch_count;
};

static const struct patch patches_13a405[] = {
    /* Always load Data's systembag, even if the restore ramdisk has a handle. */
    {0x4c38, {0xc1, 0x07, 0x00, 0x54}, {0x1f, 0x20, 0x03, 0xd5}},
    /* On failure, exit before the fatal handler changes auto-boot and reboots. */
    {0x4c74, {0x08, 0xff, 0xff, 0x97}, {0x55, 0x00, 0x00, 0x14}},
    {0x4e30, {0x99, 0xfe, 0xff, 0x97}, {0xe6, 0xff, 0xff, 0x17}},
    /* After the systembag and whitelist, exit --init before backup setup. */
    {0x4d30, {0x40, 0x81, 0x06, 0x10}, {0x26, 0x00, 0x00, 0x14}},
};

static const struct patch patches_13e238[] = {
    /* Fatal diagnostics must exit without changing NVRAM or rebooting. */
    {0x180fc, {0x8d, 0xff, 0xff, 0x97}, {0x1f, 0x20, 0x03, 0xd5}},
    {0x18110, {0x88, 0xff, 0xff, 0x97}, {0x1f, 0x20, 0x03, 0xd5}},
    {0x18178, {0xbc, 0x2f, 0x00, 0x94}, {0x1f, 0x20, 0x03, 0xd5}},
    /* Load Data's systembag and stop --init before user-session setup. */
    {0x18558, {0x41, 0x0d, 0x00, 0x54}, {0x1f, 0x20, 0x03, 0xd5}},
    {0x18700, {0xc3, 0x02, 0x40, 0xf9}, {0x47, 0x00, 0x00, 0x14}},
};

static const struct profile profiles[] = {
    {"13A405", 117424, 9,
     "d50181830555b9cf68a50a40af83cb0c3584b66fb6d0d4b272629e2c0322d7ae",
     "b1e45e6707d024f1b767f7e5606bbfdf371fcdfb6a3e99c2c61a513ae56e309e",
     patches_13a405, sizeof(patches_13a405) / sizeof(patches_13a405[0])},
    {"13E238", 274512, 27,
     "6d1cff20dcdd5a221395e7bcaa0b8064fd0c59f7db1ce020940e05a52b5a405a",
     "f070be9f01e4b372c20e3440b6d3a08fd4de4d7122a382c3f1afcce38f2ecf84",
     patches_13e238, sizeof(patches_13e238) / sizeof(patches_13e238[0])},
};

static int digest_matches(const unsigned char *data, size_t size, const char *hex)
{
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    char actual[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    size_t i;
    CC_SHA256(data, (CC_LONG)size, digest);
    for (i = 0; i < sizeof(digest); ++i)
        snprintf(actual + i * 2, 3, "%02x", digest[i]);
    return strcmp(actual, hex) == 0;
}

int main(int argc, char **argv)
{
    static const char old_path[] = "/private/var";
    static const char new_path[] = "/mnt2//././.";
    FILE *input = NULL, *output = NULL;
    unsigned char *data = NULL;
    const struct profile *profile = NULL;
    long length;
    size_t size, i, j, paths = 0;
    int result = 1;

    if (argc != 3 || !strcmp(argv[1], argv[2])) {
        fprintf(stderr, "usage: patch-keybagd-ios9 SOURCE DESTINATION\n");
        return 1;
    }
    input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END) ||
        (length = ftell(input)) < 0 || fseek(input, 0, SEEK_SET)) {
        fprintf(stderr, "patch-keybagd-ios9: cannot read source\n");
        goto done;
    }
    size = (size_t)length;
    for (i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
        if (size == profiles[i].size) profile = &profiles[i];
    if (!profile) {
        fprintf(stderr, "patch-keybagd-ios9: unsupported source size\n");
        goto done;
    }
    data = malloc(size);
    if (!data || fread(data, 1, size, input) != size ||
        memcmp(data, "\xcf\xfa\xed\xfe\x0c\0\0\x01", 8) ||
        !digest_matches(data, size, profile->source_sha256)) {
        fprintf(stderr, "patch-keybagd-ios9: unsupported source Mach-O or SHA-256\n");
        goto done;
    }
    for (i = 0; i + sizeof(old_path) - 1 <= size; ++i) {
        if (!memcmp(data + i, old_path, sizeof(old_path) - 1)) {
            memcpy(data + i, new_path, sizeof(new_path) - 1);
            ++paths;
            i += sizeof(old_path) - 2;
        }
    }
    if (paths != profile->paths) {
        fprintf(stderr, "patch-keybagd-ios9: unexpected Data path count %zu\n", paths);
        goto done;
    }
    for (j = 0; j < profile->patch_count; ++j) {
        const struct patch *p = &profile->patches[j];
        if (p->offset + 4 > size || memcmp(data + p->offset, p->before, 4)) {
            fprintf(stderr, "patch-keybagd-ios9: unexpected bytes at 0x%zx\n", p->offset);
            goto done;
        }
        memcpy(data + p->offset, p->after, 4);
    }
    if (!digest_matches(data, size, profile->result_sha256)) {
        fprintf(stderr, "patch-keybagd-ios9: output SHA-256 mismatch\n");
        goto done;
    }
    output = fopen(argv[2], "wb");
    if (!output || fwrite(data, 1, size, output) != size ||
        fflush(output) || chmod(argv[2], 0755)) {
        fprintf(stderr, "patch-keybagd-ios9: destination write failed\n");
        goto done;
    }
    fprintf(stderr, "patch-keybagd-ios9: %s relocated %zu paths and patched %zu instructions\n",
            profile->build, paths, profile->patch_count);
    result = 0;
done:
    if (output) fclose(output);
    if (input) fclose(input);
    free(data);
    return result;
}
