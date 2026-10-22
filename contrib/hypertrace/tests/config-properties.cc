// SPDX-License-Identifier: BSD-2-Clause
#include "dtraced_config.h"
#include <array>
#include <cassert>
#include <cstdio>
#include <string>
static unsigned checks;
template<size_t N> void paths() {
    for (const char *bad : std::array<const char *, 3>{nullptr, "", "relative"}) {
        char base[N], in[N], out[N], local[N];
        memset(base, 0xa5, N); memset(in, 0xa5, N);
        memset(out, 0xa5, N); memset(local, 0xa5, N);
        assert(!dtraced::directory_paths(bad, base, in, out, local));
        for (size_t i = 0; i < N; ++i)
            assert((unsigned char)base[i] == 0xa5 && (unsigned char)in[i] == 0xa5 &&
                (unsigned char)out[i] == 0xa5 && (unsigned char)local[i] == 0xa5);
        ++checks;
    }
    for (size_t length = 1; length <= N + 3; ++length)
        for (unsigned trailing = 0; trailing <= 4; ++trailing) {
            std::string input = "/" + std::string(length - 1, 'x') + std::string(trailing, '/');
            std::string normalized = input;
            while (normalized.size() > 1 && normalized.back() == '/') normalized.pop_back();
            std::string prefix = normalized == "/" ? "" : normalized;
            bool valid = input.size() < N && prefix.size() + 11 <= N;
            char base[N], in[N], out[N], local[N];
            memset(base, 0xa5, N); memset(in, 0xa5, N);
            memset(out, 0xa5, N); memset(local, 0xa5, N);
            assert(dtraced::directory_paths(input.c_str(), base, in, out, local) == valid);
            if (valid) {
                assert(base == normalized && in == prefix + "/inbound/");
                assert(out == prefix + "/outbound/" && local == prefix + "/base/");
            } else {
                for (size_t i = 0; i < N; ++i)
                    assert((unsigned char)base[i] == 0xa5 && (unsigned char)in[i] == 0xa5 &&
                        (unsigned char)out[i] == 0xa5 && (unsigned char)local[i] == 0xa5);
            }
            ++checks;
        }
}
int main() {
    paths<1>(); paths<2>(); paths<10>(); paths<11>(); paths<12>(); paths<32>(); paths<256>();
    for (unsigned n = 0; n <= 2048; ++n)
        for (unsigned zeros = 0; zeros < 4; ++zeros) {
            auto text = std::string(zeros, '0') + std::to_string(n);
            unsigned long count = 7777;
            bool valid = n >= 1 && n <= 1024;
            errno = ERANGE;
            assert(dtraced::parse_workers(text.c_str(), count) == valid);
            assert(count == (valid ? n : 7777)); ++checks;
        }
    for (const char *text : std::array<const char *, 9>{nullptr, "", "+1", "-1", " 1", "1 ", "1x", "1\n",
        "1844674407370955161600000"}) {
        unsigned long count = 7777;
        assert(!dtraced::parse_workers(text, count) && count == 7777); ++checks;
    }
    printf("PASS: %u daemon worker/path boundary properties\n", checks);
}
