/* SPDX-License-Identifier: BSD-2-Clause */
#include <cassert>
#include <cstdio>
#include "dt_elf_bounds.hh"
using namespace dtrace;
struct record { uint64_t size; uint64_t payload; };
struct data { void *d_buf; size_t d_size; };
int main() {
    alignas(record) unsigned char bytes[64] = {};
    for (size_t offset = 0; offset < alignof(record); offset++)
        for (size_t length = 0; length < sizeof(record) + 8; length++) {
            data d{bytes + offset, length};
            assert((elfBoundedRecord<record>(&d) != nullptr) ==
                (offset == 0 && length >= sizeof(record)));
        }
    data empty{nullptr, 64}; assert(elfBoundedRecord<record>(&empty) == nullptr);
    assert(!elfArrayFits(10, 11, 0, 1));
    assert(!elfArrayFits(SIZE_MAX, 1, UINT64_MAX, 8));
    assert(!elfArrayFits(100, 0, 1, 0));
    assert(elfArrayFits(24, 16, 1, 8) && !elfArrayFits(23, 16, 1, 8));
    const char text[] = "abc";
    assert(elfStringFits(text, sizeof(text), 0));
    assert(elfStringFits(text, sizeof(text), 3));
    assert(!elfStringFits(text, 3, 0) && !elfStringFits(text, sizeof(text), SIZE_MAX));
    assert(!elfStringFits(nullptr, sizeof(text), 0));
    size_t depth = 0;
    { ElfDepthGuard first(depth); { ElfDepthGuard second(depth); assert(depth == 2); } assert(depth == 1); }
    assert(depth == 0);
    puts("PASS: ELF alignment/record/array/string boundaries and depth cleanup under sanitizers");
}
