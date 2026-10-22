/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include "hypertrace_elf.h"
int main(void)
{
    struct hypertrace_elf a = { 0 }, b = { 0 };
    int complete;
    assert(hypertrace_elf_append(&a, 1, 8, "ABCD", 4, 1, &complete) == 0 && !complete);
    assert(hypertrace_elf_append(&b, 2, 4, "WXYZ", 4, 0, &complete) == 0 && complete);
    assert(hypertrace_elf_append(&a, 1, 8, "EFGH", 4, 0, &complete) == 0 && complete);
    assert(memcmp(a.data, "ABCDEFGH", 8) == 0);
    assert(memcmp(b.data, "WXYZ", 4) == 0);
    hypertrace_elf_reset(&a); hypertrace_elf_reset(&b);
    assert(hypertrace_elf_append(&a, 1, SIZE_MAX, "x", 1, 1, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, HYPERTRACE_ELF_MAX + 1UL, "x", 1, 1, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, 2, "x", 1, 0, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, 1, "x", 1, 1, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, 1, "x", 1, 2, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, 0, "x", 0, 0, &complete) == EINVAL);
    assert(hypertrace_elf_append(&a, 1, 2, "x", 1, 1, &complete) == 0);
    assert(hypertrace_elf_append(&a, 2, 2, "y", 1, 0, &complete) == EINVAL);
    assert(a.data == NULL && a.received == 0 && a.total == 0);
    assert(hypertrace_elf_append(&a, 1, 2, "x", 1, 1, &complete) == 0);
    assert(hypertrace_elf_append(&a, 1, 2, "yz", 2, 0, &complete) == EINVAL);
    assert(a.data == NULL);
    return (0);
}
