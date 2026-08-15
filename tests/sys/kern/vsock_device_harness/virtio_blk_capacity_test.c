/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Boundary tests for the shared VirtIO block capacity conversion.
 */

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/types.h>

#include <stdint.h>

#include <atf-c.h>

#include <dev/virtio/block/virtio_blk_capacity.h>

ATF_TC_WITHOUT_HEAD(capacity_boundaries);
ATF_TC_BODY(capacity_boundaries, tc)
{
	uint64_t bytes;

	/* Independent boundary values: 512-byte sectors and OFF_MAX. */
	bytes = UINT64_MAX;
	ATF_REQUIRE(virtio_blk_capacity_to_bytes(0, (uint64_t)OFF_MAX,
	    &bytes));
	ATF_CHECK_EQ(bytes, 0);

	ATF_REQUIRE(virtio_blk_capacity_to_bytes(
	    (uint64_t)OFF_MAX / 512, (uint64_t)OFF_MAX, &bytes));
	ATF_CHECK_EQ(bytes, ((uint64_t)OFF_MAX / 512) * 512);

	/* Failure must not wrap or publish a partially converted capacity. */
	bytes = UINT64_C(0x0123456789abcdef);
	ATF_CHECK(!virtio_blk_capacity_to_bytes(
	    (uint64_t)OFF_MAX / 512 + 1, (uint64_t)OFF_MAX, &bytes));
	ATF_CHECK_EQ(bytes, UINT64_C(0x0123456789abcdef));
}

ATF_TC_WITHOUT_HEAD(capacity_arbitrary_consumer_limit);
ATF_TC_BODY(capacity_arbitrary_consumer_limit, tc)
{
	uint64_t bytes;

	/* The helper's bound belongs to its caller, not to host word size. */
	bytes = UINT64_MAX;
	ATF_REQUIRE(virtio_blk_capacity_to_bytes(3, 2047, &bytes));
	ATF_CHECK_EQ(bytes, 1536);
	ATF_CHECK(!virtio_blk_capacity_to_bytes(4, 2047, &bytes));
	ATF_CHECK_EQ(bytes, 1536);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, capacity_boundaries);
	ATF_TP_ADD_TC(tp, capacity_arbitrary_consumer_limit);
	return (atf_no_error());
}
