#include <CoreFoundation/CoreFoundation.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef mach_port_t io_object_t;
typedef io_object_t io_service_t;
typedef io_object_t io_connect_t;

extern CFMutableDictionaryRef IOServiceMatching(const char *name);
extern io_service_t IOServiceGetMatchingService(
    mach_port_t masterPort, CFDictionaryRef matching);
extern kern_return_t IOServiceOpen(
    io_service_t service, task_port_t owningTask, uint32_t type,
    io_connect_t *connect);
extern kern_return_t IOServiceClose(io_connect_t connect);
extern kern_return_t IOObjectRelease(io_object_t object);
extern io_object_t IORegistryEntryFromPath(
    mach_port_t masterPort, const char *path);
extern CFTypeRef IORegistryEntryCreateCFProperty(
    io_object_t entry, CFStringRef key, CFAllocatorRef allocator,
    uint32_t options);
extern kern_return_t IOConnectCallMethod(
    mach_port_t connection, uint32_t selector,
    const uint64_t *input, uint32_t inputCnt,
    const void *inputStruct, size_t inputStructCnt,
    uint64_t *output, uint32_t *outputCnt,
    void *outputStruct, size_t *outputStructCnt);
extern kern_return_t IOConnectCallStructMethod(
    mach_port_t connection, uint32_t selector,
    const void *inputStruct, size_t inputStructCnt,
    void *outputStruct, size_t *outputStructCnt);

/*
 * iOS 7 arm64 IOAESAcceleratorUserClient selector 1 accepts exactly 88 bytes
 * for the non-UIDPlus request.  These offsets were independently checked in
 * the 11D201 kernel: user pointers 0/8, size 16, IV 20, mode 36, bits 40,
 * key 44, mask 76 and optional-data length 80.
 */
struct ioaes_request64 {
    uint64_t cleartext;
    uint64_t ciphertext;
    uint32_t size;
    uint8_t iv[16];
    uint32_t mode;
    uint32_t bits;
    uint8_t key[32];
    uint32_t mask;
    uint32_t optional_length;
    uint32_t reserved;
} __attribute__((packed));

_Static_assert(sizeof(struct ioaes_request64) == 88,
               "iOS 7 arm64 IOAES request must be 88 bytes");

static void print_hex(const char *label, const uint8_t *bytes, size_t length)
{
    size_t i;
    printf("%s=", label);
    for (i = 0; i < length; i++)
        printf("%02x", bytes[i]);
    putchar('\n');
}

static void print_chosen_data(CFStringRef key, const char *label)
{
    io_object_t chosen = IORegistryEntryFromPath(
        MACH_PORT_NULL, "IODeviceTree:/chosen");
    CFTypeRef value;

    if (!chosen) {
        printf("%s_unavailable=chosen-not-found\n", label);
        return;
    }
    value = IORegistryEntryCreateCFProperty(
        chosen, key, kCFAllocatorDefault, 0);
    IOObjectRelease(chosen);
    if (!value || CFGetTypeID(value) != CFDataGetTypeID()) {
        printf("%s_unavailable=property-not-data\n", label);
        if (value)
            CFRelease(value);
        return;
    }
    print_hex(label, CFDataGetBytePtr((CFDataRef)value),
              (size_t)CFDataGetLength((CFDataRef)value));
    CFRelease(value);
}

static io_connect_t open_service(const char *name)
{
    CFMutableDictionaryRef matching = IOServiceMatching(name);
    io_service_t service;
    io_connect_t connection = MACH_PORT_NULL;
    kern_return_t kr;

    if (!matching) {
        fprintf(stderr, "%s: IOServiceMatching failed\n", name);
        return MACH_PORT_NULL;
    }
    service = IOServiceGetMatchingService(MACH_PORT_NULL, matching);
    if (!service) {
        fprintf(stderr, "%s: service not found\n", name);
        return MACH_PORT_NULL;
    }
    kr = IOServiceOpen(service, mach_task_self(), 0, &connection);
    IOObjectRelease(service);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "%s: IOServiceOpen=0x%x\n", name, kr);
        return MACH_PORT_NULL;
    }
    return connection;
}

static kern_return_t run_aes(uint32_t mask, uint32_t mode,
                             const void *input_bytes, void *output_bytes,
                             uint32_t length)
{
    struct ioaes_request64 request;
    size_t request_size = sizeof(request);
    io_connect_t connection = open_service("IOAESAccelerator");
    kern_return_t kr;

    if (!connection)
        return KERN_FAILURE;
    memset(&request, 0, sizeof(request));
    request.cleartext = (uint64_t)(uintptr_t)input_bytes;
    request.ciphertext = (uint64_t)(uintptr_t)output_bytes;
    request.size = length;
    request.mode = mode;
    request.bits = 128;
    request.mask = mask;
    kr = IOConnectCallStructMethod(connection, 1, &request, sizeof(request),
                                   &request, &request_size);
    IOServiceClose(connection);
    printf("ioaes_mask=0x%x\n", mask);
    printf("ioaes_return=0x%x\n", kr);
    printf("ioaes_output_size=%lu\n", (unsigned long)request_size);
    return kr;
}

static int read_key89b(uint8_t output[16])
{
    static const uint8_t nonce[16] = {
        0x18, 0x3e, 0x99, 0x67, 0x6b, 0xb0, 0x3c, 0x54,
        0x6f, 0xa4, 0x68, 0xf5, 0x1c, 0x0c, 0xbd, 0x49
    };
    uint8_t input[16] __attribute__((aligned(16)));
    kern_return_t kr;

    memcpy(input, nonce, sizeof(input));
    memset(output, 0, 16);
    kr = run_aes(0x7d0, 0, input, output, sizeof(input));
    if (kr != KERN_SUCCESS)
        return 1;
    print_hex("key89B", output, 16);
    return 0;
}

#define LWVM_LOCKER_MAX 0x1a0

static int read_lwvm_locker(uint8_t locker[LWVM_LOCKER_MAX],
                            size_t *locker_length)
{
    uint64_t tag = 0x4c77564d; /* LwVM */
    uint64_t scalar_output = 0;
    uint32_t scalar_output_count = 1;
    size_t locker_size = LWVM_LOCKER_MAX;
    io_connect_t connection = open_service("AppleEffaceableStorage");
    kern_return_t kr;

    if (!connection)
        return 1;
    memset(locker, 0, LWVM_LOCKER_MAX);
    kr = IOConnectCallMethod(connection, 5, &tag, 1, NULL, 0,
                             &scalar_output, &scalar_output_count,
                             locker, &locker_size);
    IOServiceClose(connection);
    printf("locker_return=0x%x\n", kr);
    printf("locker_size=%lu\n", (unsigned long)locker_size);
    printf("locker_scalar=0x%llx\n", scalar_output);
    if (kr != KERN_SUCCESS)
        return 1;
    print_hex("LwVM", locker, locker_size);
    *locker_length = locker_size;
    return 0;
}

static int decrypt_lwvm_with_89b(const uint8_t *locker, size_t locker_size)
{
    uint8_t plaintext[LWVM_LOCKER_MAX] __attribute__((aligned(16)));
    kern_return_t kr;

    if (locker_size > sizeof(plaintext) || locker_size < 0x20 ||
        (locker_size & 15) != 0)
        return 1;
    memcpy(plaintext, locker, locker_size);
    /* LwVM::_getEffaceableKeys uses one descriptor as both source and
     * destination.  Mirror that exact in-place request here. */
    kr = run_aes(0x89b, 1, plaintext, plaintext, (uint32_t)locker_size);
    if (kr != KERN_SUCCESS)
        return 1;
    print_hex("LwVM_plain_89B", plaintext, locker_size);
    print_hex("LwVM_plain_uuid", plaintext + 0x10, 16);
    return 0;
}

int main(void)
{
    uint8_t key89b[16];
    uint8_t locker[LWVM_LOCKER_MAX];
    size_t locker_size = 0;
    print_chosen_data(CFSTR("uid-aes-key"), "chosen_uid_aes_key");
    print_chosen_data(CFSTR("system-trusted"), "chosen_system_trusted");
    print_chosen_data(CFSTR("consistent-debug-root"),
                      "chosen_consistent_debug_root");
    int key_result = read_key89b(key89b);
    int locker_result = read_lwvm_locker(locker, &locker_size);
    int decrypt_result = locker_result ? 1 :
        decrypt_lwvm_with_89b(locker, locker_size);
    /* Direct UID use is intentionally denied to user clients on iOS 7.
     * The 0x89B system handle is the authoritative key-table check. */
    (void)key_result;
    return locker_result || decrypt_result;
}
