/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>

#include <atf-c.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "checkpoint_topology.c"
#include "checkpoint_numa.c"

ATF_TC_WITHOUT_HEAD(canonical_round_trip);
ATF_TC_BODY(canonical_round_trip, tc)
{
	const uint64_t source_sizes[] = { 3ULL << 30, 1ULL << 30 };
	const uint16_t source_mapping[] = { 0, 1, 0, 1 };
	uint64_t decoded_sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t decoded_mapping[nitems(source_mapping)];
	char *mapping_text, *sizes_text;
	size_t domain_count;

	ATF_REQUIRE_EQ(checkpoint_numa_encode(source_sizes,
	    nitems(source_sizes), source_mapping, nitems(source_mapping),
	    &sizes_text, &mapping_text), 0);
	ATF_CHECK_STREQ(sizes_text,
	    "00000000c0000000,0000000040000000");
	ATF_CHECK_STREQ(mapping_text, "0000,0001,0000,0001");

	ATF_REQUIRE_EQ(checkpoint_numa_decode(sizes_text, mapping_text,
	    nitems(source_mapping), 4ULL << 30, decoded_sizes, &domain_count,
	    decoded_mapping), 0);
	ATF_CHECK_EQ(domain_count, nitems(source_sizes));
	ATF_CHECK(memcmp(source_sizes, decoded_sizes,
	    sizeof(source_sizes)) == 0);
	ATF_CHECK(memcmp(source_mapping, decoded_mapping,
	    sizeof(source_mapping)) == 0);
	for (size_t i = nitems(source_sizes);
	    i < CHECKPOINT_NUMA_MAX_DOMAINS; i++)
		ATF_CHECK_EQ(decoded_sizes[i], 0);
	free(sizes_text);
	free(mapping_text);
}

ATF_TC_WITHOUT_HEAD(rejects_malformed_and_noncanonical);
ATF_TC_BODY(rejects_malformed_and_noncanonical, tc)
{
	uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t mapping[4];
	size_t domain_count;

#define	REJECT(SIZES, MAP, MEMORY)					\
	ATF_CHECK(checkpoint_numa_decode((SIZES), (MAP), 4, (MEMORY),	\
	    sizes, &domain_count, mapping) != 0)

	REJECT("00000000c0000000,0000000040000000",
	    "0000,0001,0000", 4ULL << 30);
	REJECT("00000000C0000000,0000000040000000",
	    "0000,0001,0000,0001", 4ULL << 30);
	REJECT("00000000c0000000;0000000040000000",
	    "0000,0001,0000,0001", 4ULL << 30);
	REJECT("00000000c000000,0000000040000000",
	    "0000,0001,0000,0001", 4ULL << 30);
	REJECT("00000000c0000000,0000000000000000",
	    "0000,0001,0000,0001", 3ULL << 30);
	REJECT("00000000c0000000,0000000040000000",
	    "0000,0002,0000,0001", 4ULL << 30);
	REJECT("00000000c0000000,0000000040000000",
	    "0000,0000,0000,0000", 4ULL << 30);
	REJECT("00000000c0000000,0000000040000000",
	    "0000,0001,0000,0001", (4ULL << 30) - 1);
	REJECT("", "0000,0001,0000,0001", 4ULL << 30);
#undef REJECT
}

ATF_TC_WITHOUT_HEAD(decode_failure_is_transactional);
ATF_TC_BODY(decode_failure_is_transactional, tc)
{
	uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t mapping[4];
	size_t domain_count;

	for (size_t i = 0; i < nitems(sizes); i++)
		sizes[i] = UINT64_C(0xaaaaaaaaaaaaaaaa);
	for (size_t i = 0; i < nitems(mapping); i++)
		mapping[i] = UINT16_C(0xbbbb);
	domain_count = 99;

	ATF_CHECK(checkpoint_numa_decode(
	    "00000000c0000000,0000000040000000",
	    "0000,0001,0000,0002", nitems(mapping), 4ULL << 30,
	    sizes, &domain_count, mapping) != 0);
	for (size_t i = 0; i < nitems(sizes); i++)
		ATF_CHECK_EQ(sizes[i], UINT64_C(0xaaaaaaaaaaaaaaaa));
	for (size_t i = 0; i < nitems(mapping); i++)
		ATF_CHECK_EQ(mapping[i], UINT16_C(0xbbbb));
	ATF_CHECK_EQ(domain_count, 99);
}

ATF_TC_WITHOUT_HEAD(encode_rejects_invalid_topology);
ATF_TC_BODY(encode_rejects_invalid_topology, tc)
{
	const uint64_t sizes[] = { 3ULL << 30, 1ULL << 30 };
	const uint64_t zero[] = { 4ULL << 30, 0 };
	const uint16_t mapping[] = { 0, 1, 0, 1 };
	const uint16_t absent[] = { 0, 0, 0, 0 };
	char *mapping_text, *sizes_text;

	ATF_CHECK_EQ(checkpoint_numa_encode(zero, nitems(zero), mapping,
	    nitems(mapping), &sizes_text, &mapping_text), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_encode(sizes, nitems(sizes), absent,
	    nitems(absent), &sizes_text, &mapping_text), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_encode(NULL, nitems(sizes), mapping,
	    nitems(mapping), &sizes_text, &mapping_text), EINVAL);
	ATF_CHECK_EQ(checkpoint_numa_encode(sizes, nitems(sizes), NULL,
	    nitems(mapping), &sizes_text, &mapping_text), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, canonical_round_trip);
	ATF_TP_ADD_TC(tp, rejects_malformed_and_noncanonical);
	ATF_TP_ADD_TC(tp, decode_failure_is_transactional);
	ATF_TP_ADD_TC(tp, encode_rejects_invalid_topology);
	return (atf_no_error());
}
