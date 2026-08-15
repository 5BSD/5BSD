/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the shared bhyve OSS byte-stream boundary with injected short,
 * interrupted, and zero-progress system calls.  The production implementation
 * is included so the tests cover its exact retry loop.
 */

#include <sys/types.h>
#include <sys/param.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

#include "audio.c"

static ssize_t io_results[8];
static int io_errors[8];
static size_t io_result_count;
static size_t io_result_index;
static size_t io_calls;
static size_t io_requested[8];
static uint8_t write_first[8];
static int close_calls;
static int closed_fd;

ssize_t __wrap_write(int, const void *, size_t);
ssize_t __wrap_read(int, void *, size_t);
int __wrap_close(int);

static void
io_reset(void)
{

	memset(io_results, 0, sizeof(io_results));
	memset(io_errors, 0, sizeof(io_errors));
	memset(io_requested, 0, sizeof(io_requested));
	memset(write_first, 0, sizeof(write_first));
	io_result_count = 0;
	io_result_index = 0;
	io_calls = 0;
	close_calls = 0;
	closed_fd = -1;
}

static void
io_add(ssize_t result, int error)
{

	ATF_REQUIRE(io_result_count < nitems(io_results));
	io_results[io_result_count] = result;
	io_errors[io_result_count] = error;
	io_result_count++;
}

static ssize_t
io_next(size_t length)
{
	ssize_t result;

	ATF_REQUIRE(io_result_index < io_result_count);
	io_requested[io_calls++] = length;
	result = io_results[io_result_index];
	errno = io_errors[io_result_index++];
	ATF_REQUIRE(result < 0 || (size_t)result <= length);
	return (result);
}

ssize_t
__wrap_write(int fd __unused, const void *buffer, size_t length)
{

	if (length != 0)
		write_first[io_calls] = *(const uint8_t *)buffer;
	return (io_next(length));
}

ssize_t
__wrap_read(int fd __unused, void *buffer, size_t length)
{
	ssize_t result;

	result = io_next(length);
	if (result > 0)
		memset(buffer, (int)(0x40 + io_calls), (size_t)result);
	return (result);
}

int
__wrap_close(int fd)
{

	close_calls++;
	closed_fd = fd;
	return (0);
}

ATF_TC_WITHOUT_HEAD(playback_retries_interrupt_and_short_write);
ATF_TC_BODY(playback_retries_interrupt_and_short_write, tc __unused)
{
	struct audio aud = { .fd = 17, .dir = 1 };
	const uint8_t payload[] = { 1, 2, 3, 4 };

	io_reset();
	io_add(-1, EINTR);
	io_add(2, 0);
	io_add(2, 0);
	ATF_REQUIRE_EQ(audio_playback(&aud, payload, sizeof(payload)), 0);
	ATF_CHECK_EQ(io_calls, 3);
	ATF_CHECK_EQ(io_requested[0], 4);
	ATF_CHECK_EQ(io_requested[1], 4);
	ATF_CHECK_EQ(io_requested[2], 2);
	ATF_CHECK_EQ(write_first[0], 1);
	ATF_CHECK_EQ(write_first[1], 1);
	ATF_CHECK_EQ(write_first[2], 3);
}

ATF_TC_WITHOUT_HEAD(playback_zero_progress_fails);
ATF_TC_BODY(playback_zero_progress_fails, tc __unused)
{
	struct audio aud = { .fd = 18, .dir = 1 };
	const uint8_t payload[] = { 1, 2 };

	io_reset();
	io_add(0, 0);
	errno = 0;
	ATF_CHECK_EQ(audio_playback(&aud, payload, sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, EIO);
	ATF_CHECK_EQ(io_calls, 1);
}

ATF_TC_WITHOUT_HEAD(record_retries_interrupt_and_short_read);
ATF_TC_BODY(record_retries_interrupt_and_short_read, tc __unused)
{
	struct audio aud = { .fd = 19, .dir = 0 };
	uint8_t payload[4] = { 0 };

	io_reset();
	io_add(-1, EINTR);
	io_add(1, 0);
	io_add(3, 0);
	ATF_REQUIRE_EQ(audio_record(&aud, payload, sizeof(payload)), 0);
	ATF_CHECK_EQ(io_requested[0], 4);
	ATF_CHECK_EQ(io_requested[1], 4);
	ATF_CHECK_EQ(io_requested[2], 3);
	ATF_CHECK(payload[0] != 0);
	ATF_CHECK(payload[1] != 0);
}

ATF_TC_WITHOUT_HEAD(record_zero_progress_fails);
ATF_TC_BODY(record_zero_progress_fails, tc __unused)
{
	struct audio aud = { .fd = 20, .dir = 0 };
	uint8_t payload[2];

	io_reset();
	io_add(0, 0);
	errno = 0;
	ATF_CHECK_EQ(audio_record(&aud, payload, sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, EIO);
	ATF_CHECK_EQ(io_calls, 1);
}

ATF_TC_WITHOUT_HEAD(noninterrupt_errors_are_not_retried);
ATF_TC_BODY(noninterrupt_errors_are_not_retried, tc __unused)
{
	struct audio playback = { .fd = 22, .dir = 1 };
	struct audio capture = { .fd = 23, .dir = 0 };
	uint8_t payload[2] = { 1, 2 };

	io_reset();
	io_add(-1, EPIPE);
	errno = 0;
	ATF_CHECK_EQ(audio_playback(&playback, payload, sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, EPIPE);
	ATF_CHECK_EQ(io_calls, 1);

	io_reset();
	io_add(-1, ENXIO);
	errno = 0;
	ATF_CHECK_EQ(audio_record(&capture, payload, sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, ENXIO);
	ATF_CHECK_EQ(io_calls, 1);
}

ATF_TC_WITHOUT_HEAD(partial_io_reports_progress_and_would_block);
ATF_TC_BODY(partial_io_reports_progress_and_would_block, tc __unused)
{
	struct audio playback = { .fd = 26, .dir = 1 };
	struct audio capture = { .fd = 27, .dir = 0 };
	uint8_t payload[4] = { 1, 2, 3, 4 };

	io_reset();
	io_add(2, 0);
	ATF_CHECK_EQ(audio_playback_some(&playback, payload,
	    sizeof(payload)), 2);
	ATF_CHECK_EQ(io_calls, 1);
	ATF_CHECK_EQ(io_requested[0], sizeof(payload));

	io_reset();
	io_add(-1, EAGAIN);
	errno = 0;
	ATF_CHECK_EQ(audio_playback_some(&playback, payload,
	    sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, EAGAIN);
	ATF_CHECK_EQ(io_calls, 1);

	io_reset();
	io_add(3, 0);
	ATF_CHECK_EQ(audio_record_some(&capture, payload, sizeof(payload)), 3);
	ATF_CHECK_EQ(io_calls, 1);

	io_reset();
	io_add(-1, EWOULDBLOCK);
	errno = 0;
	ATF_CHECK_EQ(audio_record_some(&capture, payload,
	    sizeof(payload)), -1);
	ATF_CHECK_EQ(errno, EWOULDBLOCK);
	ATF_CHECK_EQ(io_calls, 1);
}

ATF_TC_WITHOUT_HEAD(zero_length_io_is_a_noop);
ATF_TC_BODY(zero_length_io_is_a_noop, tc __unused)
{
	struct audio playback = { .fd = 24, .dir = 1 };
	struct audio capture = { .fd = 25, .dir = 0 };
	uint8_t byte = 0;

	io_reset();
	ATF_CHECK_EQ(audio_playback(&playback, &byte, 0), 0);
	ATF_CHECK_EQ(audio_record(&capture, &byte, 0), 0);
	ATF_CHECK_EQ(audio_playback_some(&playback, &byte, 0), 0);
	ATF_CHECK_EQ(audio_record_some(&capture, &byte, 0), 0);
	ATF_CHECK_EQ(io_calls, 0);
}

ATF_TC_WITHOUT_HEAD(descriptor_accessor_is_exact);
ATF_TC_BODY(descriptor_accessor_is_exact, tc __unused)
{
	struct audio aud = { .fd = 28, .dir = 1 };

	ATF_CHECK_EQ(audio_fd(&aud), 28);
}

ATF_TC_WITHOUT_HEAD(destroy_closes_descriptor);
ATF_TC_BODY(destroy_closes_descriptor, tc __unused)
{
	struct audio *aud;

	io_reset();
	aud = calloc(1, sizeof(*aud));
	ATF_REQUIRE(aud != NULL);
	aud->fd = 21;
	audio_destroy(aud);
	ATF_CHECK_EQ(close_calls, 1);
	ATF_CHECK_EQ(closed_fd, 21);
	audio_destroy(NULL);
	ATF_CHECK_EQ(close_calls, 1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, playback_retries_interrupt_and_short_write);
	ATF_TP_ADD_TC(tp, playback_zero_progress_fails);
	ATF_TP_ADD_TC(tp, record_retries_interrupt_and_short_read);
	ATF_TP_ADD_TC(tp, record_zero_progress_fails);
	ATF_TP_ADD_TC(tp, noninterrupt_errors_are_not_retried);
	ATF_TP_ADD_TC(tp, partial_io_reports_progress_and_would_block);
	ATF_TP_ADD_TC(tp, zero_length_io_is_a_noop);
	ATF_TP_ADD_TC(tp, descriptor_accessor_is_exact);
	ATF_TP_ADD_TC(tp, destroy_closes_descriptor);
	return (atf_no_error());
}
