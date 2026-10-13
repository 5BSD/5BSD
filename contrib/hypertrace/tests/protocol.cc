// SPDX-License-Identifier: BSD-2-Clause
#include "dtraced_protocol.h"
#include <cassert>
#include <limits>
using namespace dtraced;
static void append(std::vector<unsigned char> &b, const char *p, size_t n) {
    auto h = reinterpret_cast<unsigned char *>(&n);
    b.insert(b.end(), h, h + sizeof(n)); b.insert(b.end(), p, p + n);
}
int main() {
    std::vector<unsigned char> b;
    append(b, "first", 6); append(b, "second", 7);
    std::vector<std::string> out {"unchanged"};
    assert(parse_cleanup(b.data(), b.size(), 2, out));
    assert((out == std::vector<std::string>{"first", "second"}));
    for (size_t n = 0; n < b.size(); ++n) {
        out = {"unchanged"}; assert(!parse_cleanup(b.data(), n, 2, out));
        assert(out == std::vector<std::string>{"unchanged"});
    }
    assert(!parse_cleanup(b.data(), b.size(), 1, out));
    assert(!parse_cleanup(b.data(), b.size(), max_cleanup_entries + 1, out));
    size_t bad = std::numeric_limits<size_t>::max(); memcpy(b.data(), &bad, sizeof(bad));
    assert(!parse_cleanup(b.data(), b.size(), 2, out));
    bad = 0; memcpy(b.data(), &bad, sizeof(bad));
    assert(!parse_cleanup(b.data(), b.size(), 2, out));
    b.clear(); append(b, "bad", 3); assert(!parse_cleanup(b.data(), b.size(), 1, out));
    b.clear(); append(b, "a\0b", 4); assert(!parse_cleanup(b.data(), b.size(), 1, out));
    b.clear(); assert(parse_cleanup(b.data(), 0, 0, out)); assert(out.empty());
    return 0;
}
