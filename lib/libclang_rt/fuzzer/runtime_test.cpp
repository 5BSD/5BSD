/* SPDX-License-Identifier: BSD-2-Clause */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned calls;
static volatile unsigned checksum;

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ++calls;
    for (size_t i = 0; i < size; ++i)
        checksum += data[i] == 42 ? 2 : 1;
    return 0;
}

__attribute__((destructor)) static void
verify_calls()
{
    if (calls < 100) {
        fprintf(stderr, "fuzzer invoked callback only %u times\n", calls);
        _Exit(1);
    }
    puts("native fuzzer completed at least 100 instrumented callbacks");
}

#ifdef CUSTOM_MAIN
extern "C" int LLVMFuzzerRunDriver(int *, char ***,
    int (*)(const uint8_t *, size_t));
int main(int argc, char **argv)
{
    return LLVMFuzzerRunDriver(&argc, &argv, LLVMFuzzerTestOneInput);
}
#endif
