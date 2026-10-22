// SPDX-License-Identifier: BSD-2-Clause
// Offline libFuzzer target: production parsers, independently decoded oracle.
#include "dtraced_protocol.h"
#include <cassert>
#include <cstdint>
#include <vector>
#include <string>

static uint64_t little(const uint8_t *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i != 8; ++i) n |= uint64_t(p[i]) << (8 * i);
    return n;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;
    uint64_t count = little(data);
    const uint8_t *body = data + 8;
    size_t length = size - 8, cursor = 0;
    std::vector<std::string> expected;
    bool valid = count <= 4096;
    for (uint64_t i = 0; valid && i < count; ++i) {
        if (length - cursor < 8) { valid = false; break; }
        uint64_t n = little(body + cursor);
        cursor += 8;
        if (n == 0 || n > 4096 || n > length - cursor) {
            valid = false; break;
        }
        for (size_t j = 0; j < n; ++j)
            if ((body[cursor + j] == 0) != (j == n - 1)) valid = false;
        if (valid) expected.emplace_back((const char *)body + cursor, n - 1);
        cursor += n;
    }
    valid = valid && cursor == length;
    const std::vector<std::string> sentinel{"preserve", "caller output"};
    auto actual = sentinel;
    assert(dtraced::parse_cleanup(body, length, count, actual) == valid);
    assert(actual == (valid ? expected : sentinel));
    // Reuse the output across success/failure transitions.
    assert(!dtraced::parse_cleanup(nullptr, 1, count, actual));
    assert(actual == (valid ? expected : sentinel));
    assert(dtraced::parse_cleanup(nullptr, 0, 0, actual) && actual.empty());

    size_t offset = SIZE_MAX;
    bool accepted = dtraced::parse_guest_elf_envelope(data, size, 7, 9,
        "vm", offset);
    // Fixed peer identity; decode the public wire format independently.
    bool envelope = size >= 30 && data[0] == 'H' && data[1] == 'T' &&
        data[2] == 'V' && data[3] == '2' && data[4] == 2 && data[5] == 0 &&
        data[6] == 7 && data[7] == 0 && little(data + 8) == 9 &&
        little(data + 16) == 2 && data[24] == 'v' && data[25] == 'm' &&
        data[26] == 127 && data[27] == 'E' && data[28] == 'L' && data[29] == 'F';
    assert(accepted == envelope);
    assert(offset == (accepted ? 26 : SIZE_MAX));
    return 0;
}
