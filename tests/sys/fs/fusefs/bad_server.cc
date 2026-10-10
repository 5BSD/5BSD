/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Axcient
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;

class BadServer: public FuseTest {};

/*
 * Starnix fuse_test.cc HeaderLengthUnderflow/OverlongHeaderLength,
 * revision 8a938a3224e768f6254ee12d240b6492361ebccf: declared length must
 * agree with the write size.  Our native policy terminates the session on
 * malformed framing; Starnix's overlong test instead retries a valid reply.
 */
class BadHeaderLength: public BadServer,
	public WithParamInterface<uint32_t> {};

TEST_P(BadHeaderLength, Reject)
{
	struct fuse_out_header header = {};
	int fd;

	header.len = GetParam();
	header.unique = 99999;
	fd = m_mock->dup_dev_fuse();
	ASSERT_GE(fd, 0);
	m_mock->m_expect_unmount = true;
	errno = 0;
	ssize_t written = write(fd, &header, sizeof(header));
	int saved_errno = errno;
	close(fd);
	ASSERT_EQ(-1, written);
	ASSERT_EQ(EINVAL, saved_errno);
	ASSERT_EQ(-1, access("mountpoint/no_file", F_OK));
	/* A new LOOKUP on a dead native session fails before dispatch. */
	ASSERT_EQ(ENXIO, errno);
}

INSTANTIATE_TEST_SUITE_P(Starnix, BadHeaderLength,
	Values(0U, (uint32_t)sizeof(struct fuse_out_header) - 1,
	    (uint32_t)sizeof(struct fuse_out_header) + 1024));

/* Local follow-up to the framing audit: never negate an unchecked errno. */
class BadReplyErrno: public BadServer,
	public WithParamInterface<std::tuple<bool, int32_t>> {
public:
void SetUp() override
{
	m_linux_errnos = std::get<0>(GetParam());
	BadServer::SetUp();
}
};

TEST_P(BadReplyErrno, Reject)
{
	const int32_t wire_error = std::get<1>(GetParam());

	EXPECT_LOOKUP(FUSE_ROOT_ID, "bad_errno")
	.WillOnce(Invoke([&](auto in, auto &out) {
		auto bad = std::make_unique<mockfs_buf_out>();
		bad->header.len = sizeof(bad->header);
		bad->header.unique = in.header.unique;
		bad->header.error = wire_error;
		bad->expected_errno = EINVAL;
		out.push_back(std::move(bad));
		if (m_linux_errnos && wire_error < 0) {
			/* Invalid Linux errno leaves this request outstanding. */
			auto valid = std::make_unique<mockfs_buf_out>();
			valid->header.len = sizeof(valid->header);
			valid->header.unique = in.header.unique;
			valid->header.error = -ENOENT;
			out.push_back(std::move(valid));
		}
	}));

	ASSERT_EQ(-1, access("mountpoint/bad_errno", F_OK));
	ASSERT_EQ(m_linux_errnos && wire_error < 0 ? ENOENT : EIO, errno);
}

INSTANTIATE_TEST_SUITE_P(ErrnoBounds, BadReplyErrno,
	Combine(Bool(), Values(INT32_MIN, -4096, 1)));

/*
 * If the server sends a response for an unknown request, the kernel should
 * gracefully return EINVAL.
 */
TEST_F(BadServer, UnknownUnique)
{
	mockfs_buf_out out;

	out.header.len = sizeof(out.header);
	out.header.error = 0;
	out.header.unique = 99999;		// Invalid!
	out.expected_errno = EINVAL;
	m_mock->write_response(out);
}

/*
 * If the server sends less than a header's worth of data, the kernel should
 * gracefully return EINVAL.
 */
TEST_F(BadServer, ShortWrite)
{
	mockfs_buf_out out;

	out.header.len = sizeof(out.header) - 1;
	out.header.error = 0;
	out.header.unique = 0;			// Asynchronous notification
	out.expected_errno = EINVAL;
	/*
	 * Tell the event loop to quit.  The kernel will disconnect us
	 * because of the short write.
	 */
	m_mock->m_expect_unmount = true;
	m_mock->write_response(out);
}

/*
 * It is illegal to report an error, and also send back a payload.
 */
TEST_F(BadServer, ErrorWithPayload)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";

	EXPECT_LOOKUP(FUSE_ROOT_ID, RELPATH)
	.WillOnce(Invoke([&](auto in, auto &out) {
		// First send an invalid response
		std::unique_ptr<mockfs_buf_out> out0(new mockfs_buf_out);
		out0->header.unique = in.header.unique;
		out0->header.error = -ENOENT;
		SET_OUT_HEADER_LEN(*out0, entry);	// Invalid!
		out0->expected_errno = EINVAL;
		out.push_back(std::move(out0));

		// The invalid header terminates the session and wakes the
		// outstanding lookup without requiring another daemon reply.
		m_mock->m_quit = true;
	}));

	EXPECT_NE(0, access(FULLPATH, F_OK));

	EXPECT_EQ(ENOTCONN, errno);
}
