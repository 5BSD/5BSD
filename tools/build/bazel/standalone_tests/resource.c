/* SPDX-License-Identifier: BSD-2-Clause */
#include <stdckdint.h>
_Static_assert(__STDC_HOSTED__ == 0, "freestanding compilation required");
_Static_assert(sizeof(unsigned long) == 8, "64-bit target required");
int standalone_add(unsigned long *result, unsigned long x)
{
    return ckd_add(result, x, 1UL);
}
