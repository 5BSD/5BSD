/*
 * Independent scatter/gather boundary tests for VirtIO filesystem queues.
 */
#include <sys/uio.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_fs_chain.c"

#define	DOC_MAX_MESSAGE	64U

ATF_TC_WITHOUT_HEAD(fragmented_round_trip);
ATF_TC_BODY(fragmented_round_trip, tc)
{
	struct virtio_fs_chain chain;
	uint8_t in0[] = { 1, 2 }, in1[] = { 3, 4, 5 };
	uint8_t out0[1] = { 0 }, out1[4] = { 0 };
	const uint8_t response[] = { 9, 8, 7, 6, 5 };
	uint8_t request[5];
	struct iovec iov[] = {
		{ in0, sizeof(in0) },
		{ in1, sizeof(in1) },
		{ out0, sizeof(out0) },
		{ out1, sizeof(out1) },
	};

	ATF_REQUIRE_EQ(virtio_fs_chain_validate(iov, 4, 2, 2, true,
	    DOC_MAX_MESSAGE, &chain), 0);
	ATF_CHECK_EQ(chain.request_length, sizeof(request));
	ATF_CHECK_EQ(chain.response_capacity, sizeof(response));
	ATF_REQUIRE_EQ(virtio_fs_chain_gather(&chain, request,
	    sizeof(request)), 0);
	ATF_CHECK(memcmp(request, "\1\2\3\4\5", sizeof(request)) == 0);
	ATF_REQUIRE_EQ(virtio_fs_chain_scatter(&chain, response,
	    sizeof(response)), 0);
	ATF_CHECK_EQ(out0[0], 9);
	ATF_CHECK(memcmp(out1, response + 1, sizeof(out1)) == 0);
}

ATF_TC_WITHOUT_HEAD(invalid_layouts_and_bounds);
ATF_TC_BODY(invalid_layouts_and_bounds, tc)
{
	struct virtio_fs_chain chain;
	uint8_t byte;
	struct iovec iov[] = {
		{ &byte, 1 },
		{ &byte, 1 },
		{ &byte, 1 },
	};

	ATF_CHECK_EQ(virtio_fs_chain_validate(NULL, 2, 1, 1, true,
	    DOC_MAX_MESSAGE, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 2, 0, 2, true,
	    DOC_MAX_MESSAGE, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 2, 1, 1, false,
	    DOC_MAX_MESSAGE, &chain), EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 2, 1, 0, true,
	    DOC_MAX_MESSAGE, &chain), EINVAL);
	iov[0].iov_base = NULL;
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 2, 1, 1, true,
	    DOC_MAX_MESSAGE, &chain), EFAULT);
	iov[0].iov_base = &byte;
	iov[0].iov_len = DOC_MAX_MESSAGE + 1;
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 2, 1, 1, true,
	    DOC_MAX_MESSAGE, &chain), EMSGSIZE);
	iov[0].iov_len = DOC_MAX_MESSAGE;
	iov[1].iov_len = DOC_MAX_MESSAGE + 1;
	ATF_REQUIRE_EQ(virtio_fs_chain_validate(iov, 2, 1, 1, true,
	    DOC_MAX_MESSAGE, &chain), 0);
	ATF_CHECK_EQ(chain.response_capacity, DOC_MAX_MESSAGE + 1);
	ATF_CHECK_EQ(virtio_fs_chain_scatter(&chain, &byte,
	    DOC_MAX_MESSAGE + 2), EMSGSIZE);
	iov[1].iov_len = SIZE_MAX;
	iov[0].iov_len = 1;
	iov[2].iov_len = 1;
	ATF_CHECK_EQ(virtio_fs_chain_validate(iov, 3, 1, 2, true,
	    DOC_MAX_MESSAGE, &chain), EOVERFLOW);
}

ATF_TC_WITHOUT_HEAD(copy_api_rejects_inconsistent_callers);
ATF_TC_BODY(copy_api_rejects_inconsistent_callers, tc)
{
	struct virtio_fs_chain chain;
	uint8_t in[] = { 1, 2 }, out[2], buffer[3];
	struct iovec iov[] = {
		{ in, sizeof(in) },
		{ out, sizeof(out) },
	};

	ATF_REQUIRE_EQ(virtio_fs_chain_validate(iov, 2, 1, 1, true,
	    DOC_MAX_MESSAGE, &chain), 0);
	ATF_CHECK_EQ(virtio_fs_chain_gather(&chain, buffer, sizeof(buffer)),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_gather(NULL, buffer, sizeof(buffer)),
	    EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_scatter(NULL, buffer, 1), EINVAL);
	ATF_CHECK_EQ(virtio_fs_chain_scatter(&chain, NULL, 1), EINVAL);
	ATF_REQUIRE_EQ(virtio_fs_chain_scatter(&chain, NULL, 0), 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, fragmented_round_trip);
	ATF_TP_ADD_TC(tp, invalid_layouts_and_bounds);
	ATF_TP_ADD_TC(tp, copy_api_rejects_inconsistent_callers);
	return (atf_no_error());
}
