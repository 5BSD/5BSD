/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/uio.h>

#include <atf-c.h>
#include <stdint.h>

#include "iov.c"

ATF_TC_WITHOUT_HEAD(split_preserves_tail);
ATF_TC_BODY(split_preserves_tail, tc)
{
	uint8_t a[10], b[20], c[30];
	struct iovec iov[4] = {
		{ .iov_base = a, .iov_len = sizeof(a) },
		{ .iov_base = b, .iov_len = sizeof(b) },
		{ .iov_base = c, .iov_len = sizeof(c) },
	};
	struct iovec *tail;
	size_t head_count, tail_count;

	head_count = 3;
	tail = split_iov(iov, &head_count, 4, &tail_count);

	ATF_CHECK(head_count == 1);
	ATF_CHECK(tail_count == 3);
	ATF_CHECK(tail == &iov[1]);
	ATF_CHECK(iov[0].iov_base == a);
	ATF_CHECK(iov[0].iov_len == 4);
	ATF_CHECK(iov[1].iov_base == a + 4);
	ATF_CHECK(iov[1].iov_len == sizeof(a) - 4);
	ATF_CHECK(iov[2].iov_base == b);
	ATF_CHECK(iov[2].iov_len == sizeof(b));
	ATF_CHECK(iov[3].iov_base == c);
	ATF_CHECK(iov[3].iov_len == sizeof(c));

	iov[0] = (struct iovec){ .iov_base = a, .iov_len = sizeof(a) };
	iov[1] = (struct iovec){ .iov_base = b, .iov_len = sizeof(b) };
	iov[2] = (struct iovec){ .iov_base = c, .iov_len = sizeof(c) };
	head_count = 3;
	tail = split_iov(iov, &head_count, sizeof(a) + 5, &tail_count);

	ATF_CHECK(head_count == 2);
	ATF_CHECK(tail_count == 2);
	ATF_CHECK(tail == &iov[2]);
	ATF_CHECK(iov[1].iov_base == b);
	ATF_CHECK(iov[1].iov_len == 5);
	ATF_CHECK(iov[2].iov_base == b + 5);
	ATF_CHECK(iov[2].iov_len == sizeof(b) - 5);
	ATF_CHECK(iov[3].iov_base == c);
	ATF_CHECK(iov[3].iov_len == sizeof(c));
}

ATF_TC_WITHOUT_HEAD(scsi_packed_data_descriptor);
ATF_TC_BODY(scsi_packed_data_descriptor, tc)
{
	uint8_t request[51 + 4096], response[108];
	struct iovec iov[4] = {
		{ .iov_base = request, .iov_len = sizeof(request) },
		{ .iov_base = response, .iov_len = sizeof(response) },
	};
	struct iovec *data_in, *data_out;
	struct iovec *iov_out;
	size_t data_in_count, data_out_count, in_count, out_count;

	/* Match virtio-scsi's packed request+dataout and response layout. */
	in_count = 1;
	out_count = 1;
	iov_out = &iov[in_count];
	data_out = split_iov(iov_out, &out_count, sizeof(response),
	    &data_out_count);
	ATF_CHECK(data_out == NULL);
	ATF_CHECK(out_count == 1);
	ATF_CHECK(data_out_count == 0);

	in_count += out_count + data_out_count;
	data_in = split_iov(iov, &in_count, 51, &data_in_count);
	data_in_count -= out_count + data_out_count;
	/* The input split moved the output entry; recompute its pointer. */
	iov_out = &iov[in_count + data_in_count];

	ATF_CHECK(in_count == 1);
	ATF_CHECK(data_in_count == 1);
	ATF_CHECK(data_in == &iov[1]);
	ATF_CHECK(data_in->iov_base == request + 51);
	ATF_CHECK(data_in->iov_len == 4096);
	ATF_CHECK(iov_out == &iov[2]);
	ATF_CHECK(iov_out->iov_base == response);
	ATF_CHECK(iov_out->iov_len == sizeof(response));
}

ATF_TC_WITHOUT_HEAD(length_overflow_saturates);
ATF_TC_BODY(length_overflow_saturates, tc)
{
	uint8_t byte;
	struct iovec iov[2] = {
		{ .iov_base = &byte, .iov_len = SIZE_MAX },
		{ .iov_base = &byte, .iov_len = 1 },
	};

	ATF_CHECK_EQ(count_iov(iov, 1), SIZE_MAX);
	ATF_CHECK_EQ(count_iov(iov, 2), SIZE_MAX);
	ATF_CHECK(check_iov_len(iov, 2, SIZE_MAX));

	iov[0].iov_len = SIZE_MAX - 4;
	iov[1].iov_len = 8;
	ATF_CHECK_EQ(count_iov(iov, 2), SIZE_MAX);
	ATF_CHECK(check_iov_len(iov, 2, SIZE_MAX));

	iov[0].iov_len = 3;
	iov[1].iov_len = 4;
	ATF_CHECK_EQ(count_iov(iov, 2), 7);
	ATF_CHECK(check_iov_len(iov, 2, 7));
	ATF_CHECK(!check_iov_len(iov, 2, 8));
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, split_preserves_tail);
	ATF_TP_ADD_TC(tp, scsi_packed_data_descriptor);
	ATF_TP_ADD_TC(tp, length_overflow_saturates);
	return (atf_no_error());
}
