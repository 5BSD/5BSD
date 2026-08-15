/* Independent descriptor-shape tests for VirtIO 1.4 PMEM section 5.19.7. */
#include <sys/uio.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_pmem_host.c"
#include "virtio_pmem_queue.c"

ATF_TC_WITHOUT_HEAD(fragmented_request_and_response);
ATF_TC_BODY(fragmented_request_and_response, tc)
{
	struct virtio_pmem_chain chain;
	uint8_t request[4] = { 0, 0, 0, 0 };
	uint8_t response[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct iovec iov[] = {
		{ .iov_base = &request[0], .iov_len = 1 },
		{ .iov_base = &request[1], .iov_len = 3 },
		{ .iov_base = &response[0], .iov_len = 1 },
		{ .iov_base = &response[1], .iov_len = 1 },
		{ .iov_base = &response[2], .iov_len = 2 },
	};
	size_t written;

	ATF_REQUIRE_EQ(virtio_pmem_chain_prepare(iov, 5, 2, 3, &chain), 0);
	ATF_CHECK_EQ(memcmp(chain.request, request, sizeof(request)), 0);
	ATF_CHECK_EQ(chain.response_count, 3);
	ATF_REQUIRE_EQ(virtio_pmem_chain_complete(&chain, 0, &written), 0);
	ATF_CHECK_EQ(written, 4);
	ATF_CHECK_EQ(memcmp(response, (uint8_t[4]) { 0, 0, 0, 0 }, 4), 0);
	ATF_REQUIRE_EQ(virtio_pmem_chain_complete(&chain, EIO, &written), 0);
	ATF_CHECK_EQ(memcmp(response,
	    (uint8_t[4]) { 0xff, 0xff, 0xff, 0xff }, 4), 0);
}

ATF_TC_WITHOUT_HEAD(malformed_chains_fail_closed);
ATF_TC_BODY(malformed_chains_fail_closed, tc)
{
	struct virtio_pmem_chain chain;
	uint8_t request[4] = { 0 };
	uint8_t response[4] = { 0 };
	struct iovec valid[] = {
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = response, .iov_len = sizeof(response) },
	};
	struct iovec zero[] = {
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = response, .iov_len = 0 },
	};
	struct iovec short_request[] = {
		{ .iov_base = request, .iov_len = 3 },
		{ .iov_base = response, .iov_len = sizeof(response) },
	};
	struct iovec short_response[] = {
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = response, .iov_len = 3 },
	};
	struct iovec overflow[] = {
		{ .iov_base = request, .iov_len = SIZE_MAX },
		{ .iov_base = request, .iov_len = 1 },
		{ .iov_base = response, .iov_len = sizeof(response) },
	};

	ATF_CHECK_EQ(virtio_pmem_chain_prepare(NULL, 2, 1, 1, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(valid, 2, 0, 2, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(valid, 2, 2, 0, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(valid, 2, 1, 2, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(zero, 2, 1, 1, &chain),
	    EMSGSIZE);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(overflow, 3, 2, 1, &chain),
	    EINVAL);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(short_request, 2, 1, 1,
	    &chain), EMSGSIZE);
	ATF_CHECK_EQ(virtio_pmem_chain_prepare(short_response, 2, 1, 1,
	    &chain), EMSGSIZE);
}

ATF_TC_WITHOUT_HEAD(zero_length_descriptors_are_ignored);
ATF_TC_BODY(zero_length_descriptors_are_ignored, tc)
{
	struct virtio_pmem_chain chain;
	uint8_t request[4] = { 0 };
	uint8_t response[4] = { 0xaa, 0xaa, 0xaa, 0xaa };
	struct iovec iov[] = {
		{ .iov_base = NULL, .iov_len = 0 },
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = NULL, .iov_len = 0 },
		{ .iov_base = NULL, .iov_len = 0 },
		{ .iov_base = response, .iov_len = sizeof(response) },
		{ .iov_base = NULL, .iov_len = 0 },
	};
	size_t written;

	ATF_REQUIRE_EQ(virtio_pmem_chain_prepare(iov, nitems(iov), 3, 3,
	    &chain), 0);
	ATF_CHECK_EQ(chain.response_count, 1);
	ATF_REQUIRE_EQ(virtio_pmem_chain_complete(&chain, 0, &written), 0);
	ATF_CHECK_EQ(written, sizeof(response));
	ATF_CHECK_EQ(memcmp(response, (uint8_t[4]) { 0, 0, 0, 0 },
	    sizeof(response)), 0);
}

ATF_TC_WITHOUT_HEAD(completion_shape_is_revalidated);
ATF_TC_BODY(completion_shape_is_revalidated, tc)
{
	struct virtio_pmem_chain chain;
	uint8_t request[4] = { 0 };
	uint8_t response[4] = { 0 };
	struct iovec iov[] = {
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = response, .iov_len = sizeof(response) },
	};
	size_t written;

	ATF_REQUIRE_EQ(virtio_pmem_chain_prepare(iov, 2, 1, 1, &chain), 0);
	chain.response[0].iov_len = 3;
	ATF_CHECK_EQ(virtio_pmem_chain_complete(&chain, 0, &written), EINVAL);
	chain.response[0].iov_len = 5;
	ATF_CHECK_EQ(virtio_pmem_chain_complete(&chain, 0, &written), EINVAL);
	chain.response[0].iov_len = 4;
	chain.response[0].iov_base = NULL;
	ATF_CHECK_EQ(virtio_pmem_chain_complete(&chain, 0, &written), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fragmented_request_and_response);
	ATF_TP_ADD_TC(tp, malformed_chains_fail_closed);
	ATF_TP_ADD_TC(tp, zero_length_descriptors_are_ignored);
	ATF_TP_ADD_TC(tp, completion_shape_is_revalidated);
	return (atf_no_error());
}
