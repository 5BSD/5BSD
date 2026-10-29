/* SPDX-License-Identifier: BSD-2-Clause */
#include <limits.h>

void
PROBE_NAME(int overflow)
{
    volatile int left = overflow ? INT_MAX : 1;
    volatile int right = 1;
    volatile int result = left + right;
    (void)result;
}
