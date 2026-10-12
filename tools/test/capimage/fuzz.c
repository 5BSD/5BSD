/* SPDX-License-Identifier: BSD-2-Clause */
/* Structural fuzzing; crypto/trust success paths have deterministic ATF tests. */
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <capimage.h>

int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int image = -1, seal = -1;
    struct capimage_policy policy;
    char error[256];
    if (size > 2 * 1024 * 1024) return (0);
    if (image == -1) image = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
    if (seal == -1) seal = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
    if (image < 0 || seal < 0) __builtin_trap();
    if (ftruncate(image, size) != 0 || pwrite(image, data, size, 0) != (ssize_t)size)
        __builtin_trap();
    if (capimage_verify(image, "/nonexistent-capimage-fuzz-key", &policy,
        error, sizeof(error)) == 0)
        capimage_policy_free(&policy);
    size_t header = size < sizeof(struct capimage_header) ? size : sizeof(struct capimage_header);
    if (ftruncate(seal, header) != 0 || pwrite(seal, data, header, 0) != (ssize_t)header)
        __builtin_trap();
    (void)capimage_check_seal(image, seal, "org.5bsd.test.fuzz.v1",
        "/nonexistent-capimage-fuzz-key", error, sizeof(error));
    return (0);
}
