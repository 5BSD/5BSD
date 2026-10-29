/* SPDX-License-Identifier: BSD-2-Clause */
#include <Block.h>
typedef int (^counter_t)(void);
static counter_t
counter(int start)
{
    __block int value = start;
    counter_t stack = ^{ return ++value; };
    return Block_copy(stack);
}
int
main(void)
{
    counter_t first = counter(40);
    if (first == 0 || first() != 41) return 1;
    counter_t second = Block_copy(first);
    Block_release(first);
    if (second == 0 || second() != 42 || second() != 43) return 2;
    Block_release(second);
    int captured = 7;
    int (^constant)(int) = Block_copy(^(int n) { return captured + n; });
    captured = 99;
    if (constant == 0 || constant(5) != 12) return 3;
    Block_release(constant);
    return 0;
}
