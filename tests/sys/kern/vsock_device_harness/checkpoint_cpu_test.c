/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <atf-c.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_cpu.c"

static struct checkpoint_cpu_contract
sample_contract(void)
{
	struct checkpoint_cpu_contract contract = {
		.version = CHECKPOINT_CPU_CONTRACT_VERSION,
		.architecture = CHECKPOINT_CPU_ARCH_AMD64,
		.record_count = 3,
		.records = {
			{
				.selector = 0,
				.parameter = 0,
				.values = { 0x20, 1, 2, 3 },
			},
			{
				.selector = 7,
				.parameter = 0,
				.values = { 0, 4, 5, 6 },
			},
			{
				.selector = 0xd,
				.parameter = 1,
				.values = { 1, 0, 0, 0 },
			},
		},
	};

	return (contract);
}

ATF_TC_WITHOUT_HEAD(canonical_round_trip);
ATF_TC_BODY(canonical_round_trip, tc)
{
	struct checkpoint_cpu_contract decoded, source;
	char *encoded, *second;

	source = sample_contract();
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_encode(&source, &encoded), 0);
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_decode(encoded, &decoded), 0);
	ATF_CHECK_EQ(checkpoint_cpu_contract_match(&source, &decoded), 0);
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_encode(&decoded, &second), 0);
	ATF_CHECK_STREQ(encoded, second);
	free(second);
	free(encoded);
}

ATF_TC_WITHOUT_HEAD(rejects_noncanonical_and_truncated);
ATF_TC_BODY(rejects_noncanonical_and_truncated, tc)
{
	struct checkpoint_cpu_contract decoded, source;
	char *encoded, *changed;
	char *upper;
	size_t length, offset;

	source = sample_contract();
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_encode(&source, &encoded), 0);
	length = strlen(encoded);

	changed = strdup(encoded);
	ATF_REQUIRE(changed != NULL);
	changed[0] = 'C';
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(changed, &decoded), EINVAL);
	free(changed);

	changed = strndup(encoded, length - 2);
	ATF_REQUIRE(changed != NULL);
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(changed, &decoded), EINVAL);
	free(changed);

	changed = malloc(length + 3);
	ATF_REQUIRE(changed != NULL);
	memcpy(changed, encoded, length);
	memcpy(changed + length, "00", 3);
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(changed, &decoded), EINVAL);
	free(changed);

	/*
	 * Hex characters 16..23 encode wire bytes 8..11: the independent
	 * little-endian architecture enum.
	 */
	changed = strdup(encoded);
	ATF_REQUIRE(changed != NULL);
	changed[CPU_CONTRACT_HEADER_SIZE] = '4';
	changed[CPU_CONTRACT_HEADER_SIZE + 1] = '0';
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(changed, &decoded), EINVAL);
	free(changed);
	free(encoded);

	/*
	 * The wire form is deliberately canonical lower-case hexadecimal.  An
	 * upper-case nibble in an otherwise intact record must not be accepted and
	 * then silently normalized on the next checkpoint generation.
	 */
	source = sample_contract();
	source.records[0].values[0] = UINT32_C(0xabcdef01);
	ATF_REQUIRE_EQ(checkpoint_cpu_contract_encode(&source, &encoded), 0);
	upper = strdup(encoded);
	ATF_REQUIRE(upper != NULL);
	offset = 0;
	while (upper[offset] != 'a') {
		ATF_REQUIRE_MSG(upper[offset] != '\0',
		    "canonical test vector lacks a lower-case hex nibble");
		offset++;
	}
	upper[offset] = 'A';
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(upper, &decoded), EINVAL);
	free(upper);
	free(encoded);
}

ATF_TC_WITHOUT_HEAD(rejects_ambiguous_record_order);
ATF_TC_BODY(rejects_ambiguous_record_order, tc)
{
	struct checkpoint_cpu_contract contract;

	contract = sample_contract();
	contract.records[2] = contract.records[1];
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), EINVAL);
	contract = sample_contract();
	contract.records[2].selector = 1;
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), EINVAL);
	contract = sample_contract();
	contract.record_count = 0;
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), EINVAL);
	contract = sample_contract();
	contract.version++;
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), EINVAL);
	contract = sample_contract();
	contract.architecture = UINT32_C(0xfeedbeef);
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(&contract), EINVAL);
	ATF_CHECK_EQ(checkpoint_cpu_contract_validate(NULL), EINVAL);
}

ATF_TC_WITHOUT_HEAD(rejects_oversized_text_before_decode);
ATF_TC_BODY(rejects_oversized_text_before_decode, tc)
{
	struct checkpoint_cpu_contract decoded, before;
	char *oversized;

	/* One byte beyond the format's fixed maximum must not be scanned or decoded. */
	oversized = malloc(CPU_CONTRACT_MAX_TEXT_LENGTH + 2);
	ATF_REQUIRE(oversized != NULL);
	memset(oversized, '0', CPU_CONTRACT_MAX_TEXT_LENGTH + 1);
	oversized[CPU_CONTRACT_MAX_TEXT_LENGTH + 1] = '\0';
	memset(&decoded, 0x5a, sizeof(decoded));
	before = decoded;
	ATF_CHECK_EQ(checkpoint_cpu_contract_decode(oversized, &decoded), E2BIG);
	ATF_CHECK_EQ(memcmp(&decoded, &before, sizeof(decoded)), 0);
	free(oversized);
}

ATF_TC_WITHOUT_HEAD(match_is_exact);
ATF_TC_BODY(match_is_exact, tc)
{
	struct checkpoint_cpu_contract destination, source;

	source = sample_contract();
	destination = source;
	ATF_CHECK_EQ(checkpoint_cpu_contract_match(&source, &destination), 0);
	destination.records[1].values[2] ^= 1;
	ATF_CHECK_EQ(checkpoint_cpu_contract_match(&source, &destination),
	    EXDEV);
	destination = source;
	destination.architecture = CHECKPOINT_CPU_ARCH_ARM64;
	ATF_CHECK_EQ(checkpoint_cpu_contract_match(&source, &destination),
	    EXDEV);
	destination = source;
	destination.record_count--;
	ATF_CHECK_EQ(checkpoint_cpu_contract_match(&source, &destination),
	    EXDEV);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, canonical_round_trip);
	ATF_TP_ADD_TC(tp, rejects_noncanonical_and_truncated);
	ATF_TP_ADD_TC(tp, rejects_ambiguous_record_order);
	ATF_TP_ADD_TC(tp, rejects_oversized_text_before_decode);
	ATF_TP_ADD_TC(tp, match_is_exact);
	return (atf_no_error());
}
