/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_REBIND_WIRE_H
#define DTRACED_REBIND_WIRE_H

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <openssl/sha.h>

#include "dtraced_wire.h"

/* HRC2 is a private nonempty rebind decision format. Encoding it grants no
 * execution authority: only a durable, replayable journal transaction can
 * turn this record into a commit. The embedded HRI1 retains the original
 * claimed HTH2 even after the claimed filename is replaced. */
static constexpr size_t DTRACED_REBIND_INTENT_WIRE_SIZE = 228;
static constexpr size_t DTRACED_REBIND_DECISION_V2_SIZE = 16 +
    DTRACED_REBIND_INTENT_WIRE_SIZE + 3 * SHA256_DIGEST_LENGTH;

struct dtraced_rebind_decision_v2 {
	std::array<uint8_t, DTRACED_REBIND_INTENT_WIRE_SIZE> intent{};
	std::array<uint8_t, SHA256_DIGEST_LENGTH> plan_digest{};
	std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
	bool foreign = false;
};

/*
 * HT-C BEGIN: trace continuity across VM restore or migration, a
 * disabled future feature under the fresh-session contract (bhyve
 * snapshot.c sets handoff_enabled = false). Behaviour is unchanged; the
 * code is excluded from the coverage target (COVERAGE-daemon.5BSD.md).
 */
static inline bool
dtraced_rebind_intent_wire_valid(const uint8_t *intent)
{
	uint8_t digest[SHA256_DIGEST_LENGTH];
	return (memcmp(intent, "HRI1", 4) == 0 &&
	    dtraced_wire_get_u32(intent + 4) == 1 &&
	    intent[194] == 0 && intent[195] == 0 &&
	    SHA256(intent, 196, digest) != nullptr &&
	    memcmp(digest, intent + 196, sizeof(digest)) == 0);
}

static inline int
dtraced_rebind_decision_v2_encode(
    uint8_t wire[DTRACED_REBIND_DECISION_V2_SIZE],
    const dtraced_rebind_decision_v2 &decision)
{
	const std::array<uint8_t, SHA256_DIGEST_LENGTH> zero{};
	if (!dtraced_rebind_intent_wire_valid(decision.intent.data()) ||
	    decision.plan_digest == zero ||
	    decision.foreign == (decision.stage_digest == zero)) {
		errno = EINVAL;
		return (-1);
	}
	std::array<uint8_t, DTRACED_REBIND_DECISION_V2_SIZE> candidate{};
	memcpy(candidate.data(), "HRC2", 4);
	dtraced_wire_put_u32(candidate.data() + 4, 2);
	candidate[8] = decision.foreign ? 1 : 0;
	memcpy(candidate.data() + 16, decision.intent.data(),
	    decision.intent.size());
	memcpy(candidate.data() + 16 + decision.intent.size(),
	    decision.plan_digest.data(), decision.plan_digest.size());
	memcpy(candidate.data() + 16 + decision.intent.size() +
	    decision.plan_digest.size(), decision.stage_digest.data(),
	    decision.stage_digest.size());
	if (SHA256(candidate.data(), candidate.size() - SHA256_DIGEST_LENGTH,
	    candidate.data() + candidate.size() - SHA256_DIGEST_LENGTH) ==
	    nullptr) {
		errno = EIO;
		return (-1);
	}
	memcpy(wire, candidate.data(), candidate.size());
	return (0);
}

static inline int
dtraced_rebind_decision_v2_decode(dtraced_rebind_decision_v2 *decision,
    const uint8_t wire[DTRACED_REBIND_DECISION_V2_SIZE],
    const uint8_t expected_token[16])
{
	const std::array<uint8_t, SHA256_DIGEST_LENGTH> zero{};
	const uint8_t padding[7] = {};
	uint8_t digest[SHA256_DIGEST_LENGTH];
	const size_t intent_offset = 16;
	const size_t plan_offset = intent_offset + DTRACED_REBIND_INTENT_WIRE_SIZE;
	const size_t stage_offset = plan_offset + SHA256_DIGEST_LENGTH;
	const size_t digest_offset = stage_offset + SHA256_DIGEST_LENGTH;
	if (decision == nullptr || expected_token == nullptr ||
	    memcmp(wire, "HRC2", 4) != 0 ||
	    dtraced_wire_get_u32(wire + 4) != 2 || wire[8] > 1 ||
	    memcmp(wire + 9, padding, sizeof(padding)) != 0 ||
	    !dtraced_rebind_intent_wire_valid(wire + intent_offset) ||
	    memcmp(wire + intent_offset + 12, expected_token, 16) != 0 ||
	    memcmp(wire + plan_offset, zero.data(), zero.size()) == 0 ||
	    (wire[8] == 1) ==
	    (memcmp(wire + stage_offset, zero.data(), zero.size()) == 0) ||
	    SHA256(wire, digest_offset, digest) == nullptr ||
	    memcmp(digest, wire + digest_offset, sizeof(digest)) != 0) {
		errno = EPROTO;
		return (-1);
	}
	dtraced_rebind_decision_v2 parsed;
	memcpy(parsed.intent.data(), wire + intent_offset,
	    parsed.intent.size());
	memcpy(parsed.plan_digest.data(), wire + plan_offset,
	    parsed.plan_digest.size());
	memcpy(parsed.stage_digest.data(), wire + stage_offset,
	    parsed.stage_digest.size());
	parsed.foreign = wire[8] == 1;
	*decision = parsed;
	return (0);
}

/* HT-C END */
#endif
