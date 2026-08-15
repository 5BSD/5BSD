/*
 * Independent VirtIO 1.4 section 5.23 request/response tests.
 */
#include <sys/endian.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "virtio_rtc_alarm.c"
#include "virtio_rtc_host.c"
#include "virtio_1_4_spec.h"

/*
 * Establish the post-DUT oracle boundary expected of device protocol tests.
 * The host engine itself uses only RTC message names, outside the common
 * feature/device-name alias inventory.
 */
#undef VIRTIO_ID_CLOCK
#define	VIRTIO_ID_CLOCK		VIRTIO14_RTC_DEVICE_ID

struct clock_state {
	uint64_t reading;
	int error;
	unsigned int calls;
};

static int
test_clock(void *arg, uint64_t *reading)
{
	struct clock_state *state;

	state = arg;
	state->calls++;
	if (state->error != 0)
		return (state->error);
	*reading = state->reading;
	return (0);
}

static size_t
process(const void *request, size_t request_len, uint8_t *response,
    size_t response_capacity, struct clock_state *clock)
{
	size_t written;

	memset(response, 0xa5, response_capacity);
	ATF_REQUIRE_EQ(virtio_rtc_process_request(request, request_len,
	    response, response_capacity, test_clock, clock, &written), 0);
	return (written);
}

ATF_TC_WITHOUT_HEAD(virtio_1_4_wire_layout);
ATF_TC_BODY(virtio_1_4_wire_layout, tc)
{

	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_head),
	    VIRTIO14_RTC_REQ_HEAD_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_head),
	    VIRTIO14_RTC_RESP_HEAD_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_cfg),
	    VIRTIO14_RTC_REQ_CFG_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_cfg),
	    VIRTIO14_RTC_RESP_CFG_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_clock_cap),
	    VIRTIO14_RTC_REQ_CLOCK_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_clock_cap),
	    VIRTIO14_RTC_RESP_CLOCK_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_cross_cap),
	    VIRTIO14_RTC_REQ_CROSS_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_cross_cap),
	    VIRTIO14_RTC_RESP_CROSS_CAP_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_req_read),
	    VIRTIO14_RTC_REQ_READ_SIZE);
	ATF_CHECK_EQ(sizeof(struct virtio_rtc_resp_read),
	    VIRTIO14_RTC_RESP_READ_SIZE);
}

ATF_TC_WITHOUT_HEAD(cfg_and_capabilities);
ATF_TC_BODY(cfg_and_capabilities, tc)
{
	static const uint8_t cfg_request[8] = {
		0x00, 0x10, 0, 0, 0, 0, 0, 0,
	};
	static const uint8_t cfg_response[16] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
	};
	static const uint8_t clock_request[16] = {
		0x01, 0x10, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	};
	static const uint8_t clock_response[16] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		4, 0, 0, 0, 0, 0, 0, 0,
	};
	static const uint8_t cross_request[16] = {
		0x02, 0x10, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 0, 0,
	};
	uint8_t response[24];
	struct clock_state clock;
	size_t written;

	memset(&clock, 0, sizeof(clock));
	written = process(cfg_request, sizeof(cfg_request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, sizeof(cfg_response));
	ATF_CHECK(memcmp(response, cfg_response, sizeof(cfg_response)) == 0);

	written = process(clock_request, sizeof(clock_request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, sizeof(clock_response));
	ATF_CHECK(memcmp(response, clock_response,
	    sizeof(clock_response)) == 0);

	written = process(cross_request, sizeof(cross_request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ(response[0], 0);
	for (size_t i = 1; i < written; i++)
		ATF_CHECK_EQ(response[i], 0);
	ATF_CHECK_EQ(clock.calls, 0);
}

ATF_TC_WITHOUT_HEAD(read_utc);
ATF_TC_BODY(read_utc, tc)
{
	static const uint8_t request[16] = {
		0x01, 0x00, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	};
	static const uint8_t expected[16] = {
		0, 0, 0, 0, 0, 0, 0, 0,
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
	};
	struct clock_state clock;
	uint8_t response[24];
	size_t written;

	memset(&clock, 0, sizeof(clock));
	clock.reading = UINT64_C(0x0102030405060708);
	written = process(request, sizeof(request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, sizeof(expected));
	ATF_CHECK(memcmp(response, expected, sizeof(expected)) == 0);
	ATF_CHECK_EQ(clock.calls, 1);

	clock.error = EIO;
	written = process(request, sizeof(request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 5);
	for (size_t i = 1; i < written; i++)
		ATF_CHECK_EQ(response[i], 0);
}

ATF_TC_WITHOUT_HEAD(validation_and_precedence);
ATF_TC_BODY(validation_and_precedence, tc)
{
	uint8_t request[24], response[24];
	struct clock_state clock;
	size_t written;

	memset(&clock, 0, sizeof(clock));
	memset(request, 0, sizeof(request));

	/* Unknown message types are explicitly unsupported. */
	request[0] = 0xad;
	request[1] = 0xde;
	written = process(request, 8, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 2);

	/* Alarm messages take ENODEV when the alarm feature is absent. */
	request[0] = 0x03;
	request[1] = 0x10;
	written = process(request, 8, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 3);

	/* Explicit semantic errors take precedence when the status byte fits. */
	request[0] = 0xad;
	request[1] = 0xde;
	written = process(request, 8, response, 1, &clock);
	ATF_CHECK_EQ(written, 1);
	ATF_CHECK_EQ(response[0], 2);

	/* A non-zero common reserved byte makes a known request invalid. */
	request[0] = 0x00;
	request[1] = 0x10;
	request[2] = 1;
	written = process(request, 8, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 4);

	/* A nonexistent dense clock identifier takes ENODEV. */
	memset(request, 0, sizeof(request));
	request[0] = 0x01;
	request[1] = 0x10;
	request[8] = 1;
	written = process(request, 16, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 3);

	/* Unknown counters take EOPNOTSUPP as required by section 5.23.6.2. */
	request[0] = 0x02;
	request[10] = 0x80;
	written = process(request, 16, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 2);
	written = process(request, 16, response, 1, &clock);
	ATF_CHECK_EQ(written, 1);
	ATF_CHECK_EQ(response[0], 2);

	/*
	 * Implementation-specific IDs are not supported merely because their
	 * numeric range is reserved for implementations.
	 */
	request[10] = 0xf0;
	written = process(request, 16, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 2);

	/*
	 * ENODEV precedes malformed reserved fields and response sizing once
	 * a complete request identifies a nonexistent clock.
	 */
	memset(request, 0, sizeof(request));
	request[0] = 0x01;
	request[1] = 0x10;
	request[2] = 1;
	request[8] = 1;
	request[10] = 1;
	written = process(request, 16, response, 1, &clock);
	ATF_CHECK_EQ(written, 1);
	ATF_CHECK_EQ(response[0], 3);

	/* Extra request bytes are ignored. */
	memset(request, 0, sizeof(request));
	request[0] = 0x00;
	request[1] = 0x10;
	memset(request + 8, 0xcc, 16);
	written = process(request, sizeof(request), response,
	    sizeof(response), &clock);
	ATF_CHECK_EQ(written, 16);
	ATF_CHECK_EQ(response[0], 0);
}

ATF_TC_WITHOUT_HEAD(short_buffers);
ATF_TC_BODY(short_buffers, tc)
{
	uint8_t request[16] = { 0x00, 0x10 };
	uint8_t response[24];
	struct clock_state clock;
	size_t written;

	memset(&clock, 0, sizeof(clock));
	written = process(request, 7, response, sizeof(response), &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 4);

	written = process(request, 8, response, 0, &clock);
	ATF_CHECK_EQ(written, 0);
	written = process(request, 8, response, 1, &clock);
	ATF_CHECK_EQ(written, 1);
	ATF_CHECK_EQ(response[0], 4);
	written = process(request, 8, response, 7, &clock);
	ATF_CHECK_EQ(written, 7);
	ATF_CHECK_EQ(response[0], 4);
	for (size_t i = 1; i < written; i++)
		ATF_CHECK_EQ(response[i], 0);
	written = process(request, 8, response, 8, &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 4);
	written = process(request, 8, response, 15, &clock);
	ATF_CHECK_EQ(written, 8);
	ATF_CHECK_EQ(response[0], 4);
}

ATF_TC_WITHOUT_HEAD(api_validation);
ATF_TC_BODY(api_validation, tc)
{
	uint8_t request[8] = { 0 };
	uint8_t response[8];
	struct clock_state clock;
	size_t written;

	memset(&clock, 0, sizeof(clock));
	ATF_CHECK_EQ(virtio_rtc_process_request(NULL, 1, response,
	    sizeof(response), test_clock, &clock, &written), EINVAL);
	ATF_CHECK_EQ(virtio_rtc_process_request(request, sizeof(request), NULL,
	    1, test_clock, &clock, &written), EINVAL);
	ATF_CHECK_EQ(virtio_rtc_process_request(request, sizeof(request),
	    response, sizeof(response), NULL, &clock, &written), EINVAL);
	ATF_CHECK_EQ(virtio_rtc_process_request(request, sizeof(request),
	    response, sizeof(response), test_clock, &clock, NULL), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, virtio_1_4_wire_layout);
	ATF_TP_ADD_TC(tp, cfg_and_capabilities);
	ATF_TP_ADD_TC(tp, read_utc);
	ATF_TP_ADD_TC(tp, validation_and_precedence);
	ATF_TP_ADD_TC(tp, short_buffers);
	ATF_TP_ADD_TC(tp, api_validation);
	return (atf_no_error());
}
