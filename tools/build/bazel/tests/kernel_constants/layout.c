/* SPDX-License-Identifier: BSD-2-Clause */
/* Compile real ASSYM/OFFSYM encodings; never execute a target layout probe. */
#include <sys/param.h>
#include <sys/assym.h>
#include <stddef.h>

/* assym.h expects its caller to supply CTASSERT; retain real C assertions. */
#define CTASSERT(expr) _Static_assert(expr, #expr)

struct sample {
    char lead[8];
    u_int count;
    long value;
    u_char flag;
};
#ifdef OFFSET_TEST
#include "offset.inc"
#endif
OFFSYM(count, sample, u_int);
OFFSYM(value, sample, long);
OFFSYM(flag, sample, u_char);
ASSYM(TEST_ZERO, 0);
ASSYM(TEST_NEGATIVE, -12345);
ASSYM(TEST_WORD, 0x10000);
ASSYM(TEST_WIDE, 0x123456789abcdefLL);
ASSYM(TEST_COUNT_OFFSET, offsetof(struct sample, count));

#ifdef CHECK_CONSTANTS
#include "assym.inc"
_Static_assert(TEST_ZERO == 0, "zero constant");
_Static_assert(TEST_NEGATIVE == -12345, "signed constant");
_Static_assert(TEST_WORD == 0x10000, "word boundary");
_Static_assert(TEST_WIDE == 0x123456789abcdefLL, "64-bit constant");
_Static_assert(TEST_COUNT_OFFSET == offsetof(struct sample, count), "member offset");
int main(void) { return (0); }
#endif
