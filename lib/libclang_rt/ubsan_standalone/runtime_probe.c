/* SPDX-License-Identifier: BSD-2-Clause */
#include <limits.h>
int main(int argc, char **argv)
{
    volatile int left = argc == 2 && argv[1][0] == '1' ? INT_MAX : 1;
    volatile int right = 1;
    volatile int result = left + right;
    (void)result;
    return (0);
}
