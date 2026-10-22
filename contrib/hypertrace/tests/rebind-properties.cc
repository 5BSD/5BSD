// SPDX-License-Identifier: BSD-2-Clause
#include "dtraced_rebind_wire.h"
#include <cassert>
#include <cstdio>

using wire_type = std::array<uint8_t, DTRACED_REBIND_DECISION_V2_SIZE>;
static unsigned checks;
static void seal(wire_type &wire) {
    assert(SHA256(wire.data(), wire.size() - 32, wire.data() + wire.size() - 32));
}
static bool equal(const dtraced_rebind_decision_v2 &a,
    const dtraced_rebind_decision_v2 &b) {
    return a.intent == b.intent && a.plan_digest == b.plan_digest &&
        a.stage_digest == b.stage_digest && a.foreign == b.foreign;
}
static void rejected(const wire_type &wire, const uint8_t *token) {
    dtraced_rebind_decision_v2 output;
    output.intent.fill(0xa5); output.plan_digest.fill(0xb6);
    output.stage_digest.fill(0xc7); output.foreign = true;
    const auto before = output;
    errno = 0;
    assert(dtraced_rebind_decision_v2_decode(&output, wire.data(), token) == -1);
    assert(errno == EPROTO && equal(output, before));
    ++checks;
}
static void encode_rejected(const dtraced_rebind_decision_v2 &decision) {
    wire_type output; output.fill(0xa5);
    const auto before = output;
    errno = 0;
    assert(dtraced_rebind_decision_v2_encode(output.data(), decision) == -1);
    assert(errno == EINVAL && output == before);
    ++checks;
}
int main() {
    std::array<uint8_t, 16> token{};
    for (size_t i = 0; i < token.size(); ++i) token[i] = i + 1;
    for (bool foreign : {false, true}) {
        dtraced_rebind_decision_v2 decision;
        memcpy(decision.intent.data(), "HRI1", 4);
        decision.intent[4] = 1;
        memcpy(decision.intent.data() + 12, token.data(), token.size());
        decision.intent[160] = 7;
        assert(SHA256(decision.intent.data(), 196, decision.intent.data() + 196));
        decision.plan_digest.fill(0x37);
        decision.foreign = foreign;
        if (foreign) decision.stage_digest.fill(0x49);
        // Construct expected HRC2 bytes independently of the production encoder.
        wire_type expected{};
        memcpy(expected.data(), "HRC2", 4); expected[4] = 2;
        expected[8] = foreign;
        memcpy(expected.data() + 16, decision.intent.data(), 228);
        memcpy(expected.data() + 244, decision.plan_digest.data(), 32);
        memcpy(expected.data() + 276, decision.stage_digest.data(), 32);
        seal(expected);
        wire_type encoded{};
        assert(dtraced_rebind_decision_v2_encode(encoded.data(), decision) == 0);
        assert(encoded == expected);
        dtraced_rebind_decision_v2 decoded;
        assert(dtraced_rebind_decision_v2_decode(&decoded, expected.data(), token.data()) == 0);
        assert(equal(decoded, decision)); ++checks;
        // Every single-bit wire corruption must reject, preserving prior output.
        for (size_t i = 0; i < expected.size(); ++i)
            for (unsigned bit = 0; bit < 8; ++bit) {
                auto wire = expected; wire[i] ^= 1U << bit;
                rejected(wire, token.data());
            }
        for (size_t i = 0; i < token.size(); ++i)
            for (unsigned bit = 0; bit < 8; ++bit) {
                auto wrong = token; wrong[i] ^= 1U << bit;
                rejected(expected, wrong.data());
            }
        // Resealing removes the checksum as the reason for rejection.
        for (size_t i = 0; i < 16; ++i) {
            auto wire = expected;
            wire[i] ^= (i == 8 ? 2 : 1);
            seal(wire); rejected(wire, token.data());
        }
        for (size_t i : {size_t(0), size_t(4), size_t(194), size_t(195)}) {
            auto wire = expected; wire[16 + i] ^= 1;
            assert(SHA256(wire.data() + 16, 196, wire.data() + 212));
            seal(wire); rejected(wire, token.data());
        }
        auto wire = expected;
        memset(wire.data() + 244, 0, 32); seal(wire);
        rejected(wire, token.data());
        wire = expected; wire[8] = !foreign; seal(wire);
        rejected(wire, token.data());
        rejected(expected, nullptr);
        assert(dtraced_rebind_decision_v2_decode(nullptr, expected.data(), token.data()) == -1);
        ++checks;
        for (size_t i = 0; i < decision.intent.size(); ++i)
            for (unsigned bit = 0; bit < 8; ++bit) {
                auto bad = decision; bad.intent[i] ^= 1U << bit;
                encode_rejected(bad);
            }
        auto bad = decision; bad.plan_digest.fill(0); encode_rejected(bad);
        bad = decision; bad.foreign = !foreign; encode_rejected(bad);
    }
    printf("PASS: %u rebind integrity, identity, and output-preservation checks\n", checks);
}
