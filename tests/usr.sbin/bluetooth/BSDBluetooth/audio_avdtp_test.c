/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 * Copyright 2018 The Fuchsia Authors. All rights reserved.
 * Fuchsia-derived tests: timeout, stream transitions and configuration queries.
 * Upstream attribution and BSD license: FUCHSIA-TESTS.txt.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <signal.h>
#include <unistd.h>

/* Exercise the production parser and transaction implementation. */
#define AVDTP_TIMEOUT_MS 150
#include "avdtp.c"

static void
pair(int fd[2])
{
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd));
}

static void
packet(int fd, const uint8_t *data, size_t size)
{
	ATF_REQUIRE_EQ((ssize_t)size, send(fd, data, size, MSG_NOSIGNAL | MSG_EOR));
}

static void
reap(pid_t pid)
{
	int status;

	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
}

ATF_TC_WITHOUT_HEAD(single_payload);
ATF_TC_BODY(single_payload, tc)
{
	int fd[2];
	struct avdtpGetPacketInfo info;
	const uint8_t data[] = {0x32, AVDTP_DISCOVER, 0x20, 0x08};

	(void)tc;
	pair(fd);
	packet(fd[0], data, sizeof(data));
	ATF_REQUIRE_EQ(RESPONSEACCEPT, avdtpGetPacket(fd[1], &info));
	ATF_REQUIRE_EQ(3, info.trans);
	ATF_REQUIRE_EQ(AVDTP_DISCOVER, info.signalID);
	ATF_REQUIRE_EQ(2, info.buffer_len);
	ATF_REQUIRE_EQ(0, memcmp(info.buffer_data, data + 2, 2));
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(empty_accept);
ATF_TC_BODY(empty_accept, tc)
{
	int fd[2];
	struct avdtpGetPacketInfo info;
	const uint8_t data[] = {0x12, AVDTP_OPEN};

	(void)tc;
	pair(fd);
	packet(fd[0], data, sizeof(data));
	ATF_REQUIRE_EQ(RESPONSEACCEPT, avdtpGetPacket(fd[1], &info));
	ATF_REQUIRE_EQ(0, info.buffer_len);
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(fragment_reassembly);
ATF_TC_BODY(fragment_reassembly, tc)
{
	int fd[2];
	struct avdtpGetPacketInfo info;
	const uint8_t start[] = {0x56, 3, AVDTP_DISCOVER, 0xee};
	const uint8_t middle[] = {0x5a, 0x04, 0x08};
	const uint8_t end[] = {0x5e, 0xdd};
	const uint8_t payload[] = {0xee, 0x04, 0x08, 0xdd};

	(void)tc;
	pair(fd);
	packet(fd[0], start, sizeof(start));
	packet(fd[0], middle, sizeof(middle));
	packet(fd[0], end, sizeof(end));
	ATF_REQUIRE_EQ(RESPONSEACCEPT, avdtpGetPacket(fd[1], &info));
	ATF_REQUIRE_EQ(sizeof(payload), info.buffer_len);
	ATF_REQUIRE_EQ(0, memcmp(payload, info.buffer_data, sizeof(payload)));
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(header_only_fragments);
ATF_TC_BODY(header_only_fragments, tc)
{
	int fd[2];
	struct avdtpGetPacketInfo info;
	const uint8_t start[] = {0x26, 3, AVDTP_OPEN};
	const uint8_t middle[] = {0x2a};
	const uint8_t end[] = {0x2e};

	(void)tc;
	pair(fd);
	packet(fd[0], start, sizeof(start));
	packet(fd[0], middle, sizeof(middle));
	packet(fd[0], end, sizeof(end));
	ATF_REQUIRE_EQ(RESPONSEACCEPT, avdtpGetPacket(fd[1], &info));
	ATF_REQUIRE_EQ(0, info.buffer_len);
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(malformed_headers);
ATF_TC_BODY(malformed_headers, tc)
{
	const uint8_t data[][3] = {
	    {0x02}, {0x06, 2}, {0x06, 0, 1}, {0x06, 1, 1}, {0x0a, 1}, {0x0e, 1}
	};
	const size_t sizes[] = {1, 2, 3, 3, 2, 2};

	(void)tc;
	for (unsigned i = 0; i != sizeof(sizes) / sizeof(sizes[0]); i++) {
		int fd[2];
		struct avdtpGetPacketInfo info;
		pair(fd);
		packet(fd[0], data[i], sizes[i]);
		ATF_REQUIRE_EQ(-EPROTO, avdtpGetPacket(fd[1], &info));
		close(fd[0]); close(fd[1]);
	}
}

ATF_TC_WITHOUT_HEAD(fragment_mismatch);
ATF_TC_BODY(fragment_mismatch, tc)
{
	const uint8_t invalid[] = {0x3e, 0x2f, 0x2a, 0x22};

	(void)tc;
	for (unsigned i = 0; i != sizeof(invalid); i++) {
		int fd[2];
		struct avdtpGetPacketInfo info;
		const uint8_t start[] = {0x26, 2, AVDTP_OPEN, 0xa0};
		const uint8_t end[] = {invalid[i], 0xb0};
		pair(fd);
		packet(fd[0], start, sizeof(start));
		packet(fd[0], end, sizeof(end));
		ATF_REQUIRE_EQ(-EPROTO, avdtpGetPacket(fd[1], &info));
		close(fd[0]); close(fd[1]);
	}
}

ATF_TC_WITHOUT_HEAD(payload_bounds);
ATF_TC_BODY(payload_bounds, tc)
{
	(void)tc;
	for (unsigned size = 514; size <= 516; size++) {
		int fd[2];
		uint8_t data[516] = {RESPONSEACCEPT, AVDTP_DISCOVER};
		struct avdtpGetPacketInfo info;
		pair(fd);
		packet(fd[0], data, size);
		ATF_REQUIRE_EQ(size == 514 ? RESPONSEACCEPT : -EMSGSIZE,
		    avdtpGetPacket(fd[1], &info));
		if (size == 514)
			ATF_REQUIRE_EQ(512, info.buffer_len);
		close(fd[0]); close(fd[1]);
	}
}

ATF_TC_WITHOUT_HEAD(fragment_overflow);
ATF_TC_BODY(fragment_overflow, tc)
{
	int fd[2];
	uint8_t start[515] = {0x06, 2, AVDTP_DISCOVER};
	const uint8_t end[] = {0x0e, 0x01};
	struct avdtpGetPacketInfo info;

	(void)tc;
	pair(fd);
	packet(fd[0], start, sizeof(start));
	packet(fd[0], end, sizeof(end));
	ATF_REQUIRE_EQ(-EMSGSIZE, avdtpGetPacket(fd[1], &info));
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(fragment_timeout);
ATF_TC_BODY(fragment_timeout, tc)
{
	int fd[2];
	const uint8_t start[] = {0x06, 2, AVDTP_DISCOVER};
	struct avdtpGetPacketInfo info;

	(void)tc;
	pair(fd);
	packet(fd[0], start, sizeof(start));
	ATF_REQUIRE_EQ(-ETIMEDOUT, avdtpGetPacket(fd[1], &info));
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(transaction_correlation);
ATF_TC_BODY(transaction_correlation, tc)
{
	int fd[2];
	pid_t child;

	(void)tc;
	pair(fd);
	ATF_REQUIRE((child = fork()) >= 0);
	if (child == 0) {
		uint8_t request[10], response[2];
		close(fd[0]);
		ATF_REQUIRE_EQ(3, recv(fd[1], request, sizeof(request), 0));
		response[0] = (request[0] & 0xf0) | RESPONSEACCEPT;
		response[1] = AVDTP_CLOSE;
		packet(fd[1], response, sizeof(response));
		response[1] = AVDTP_OPEN;
		response[0] ^= 0x10;
		packet(fd[1], response, sizeof(response));
		response[0] ^= 0x10;
		packet(fd[1], response, sizeof(response));
		_exit(0);
	}
	close(fd[1]);
	ATF_REQUIRE_EQ(0, avdtpOpen(fd[0], 8));
	close(fd[0]);
	reap(child);
}

ATF_TC_WITHOUT_HEAD(timeout_preserves_alarm);
ATF_TC_BODY(timeout_preserves_alarm, tc)
{
	int fd[2];

	(void)tc;
	pair(fd);
	alarm(30);
	ATF_REQUIRE_EQ(-ETIMEDOUT, avdtpOpen(fd[0], 8));
	ATF_REQUIRE(alarm(0) >= 28);
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(closed_peer);
ATF_TC_BODY(closed_peer, tc)
{
	int fd[2];
	struct avdtpGetPacketInfo info;

	(void)tc;
	pair(fd);
	close(fd[1]);
	ATF_REQUIRE_EQ(-ECONNRESET, avdtpGetPacket(fd[0], &info));
	/* The default SIGPIPE disposition must not terminate the process. */
	signal(SIGPIPE, SIG_DFL);
	ATF_REQUIRE(avdtpOpen(fd[0], 8) < 0);
	close(fd[0]);
}

static void
headset_reply(int fd, uint8_t command, const uint8_t *body, size_t len,
    bool check_config)
{
	uint8_t request[64], response[64];
	ssize_t size = recv(fd, request, sizeof(request), 0);

	ATF_REQUIRE(size >= 2);
	ATF_REQUIRE_EQ(command, request[1]);
	if (check_config) {
		const uint8_t expected[] = {
		    0x20, 0x20, 1, 0, 7, 6, 0, 0, 0x11, 0x15, 2, 53
		};
		ATF_REQUIRE_EQ(sizeof(expected) + 2, (size_t)size);
		ATF_REQUIRE_EQ(0, memcmp(request + 2, expected, sizeof(expected)));
	}
	response[0] = (request[0] & 0xf0) | RESPONSEACCEPT;
	response[1] = command;
	if (len != 0)
		memcpy(response + 2, body, len);
	packet(fd, response, len + 2);
}

static int
negotiate(const uint8_t *capabilities, size_t size, bool success)
{
	struct bt_config cfg = { .freq = FREQ_48K, .bands = BANDS_8,
	    .chmode = MODE_STEREO, .bitpool = 53, .allocm = ALLOC_LOUDNESS };
	int fd[2], result;
	pid_t child;

	pair(fd);
	ATF_REQUIRE((child = fork()) >= 0);
	if (child == 0) {
		const uint8_t endpoint[] = {0x20, 0x08};
		close(fd[0]);
		headset_reply(fd[1], AVDTP_DISCOVER, endpoint, sizeof(endpoint), false);
		headset_reply(fd[1], AVDTP_GET_CAPABILITIES, capabilities, size, false);
		if (success) {
			headset_reply(fd[1], AVDTP_SET_CONFIGURATION, NULL, 0, true);
			headset_reply(fd[1], AVDTP_OPEN, NULL, 0, false);
			headset_reply(fd[1], AVDTP_START, NULL, 0, false);
			headset_reply(fd[1], AVDTP_SUSPEND, NULL, 0, false);
			headset_reply(fd[1], AVDTP_START, NULL, 0, false);
			headset_reply(fd[1], AVDTP_CLOSE, NULL, 0, false);
		}
		_exit(0);
	}
	close(fd[1]);
	cfg.hc = fd[0];
	result = avdtpDiscoverAndConfig(&cfg, true);
	if (success) {
		ATF_REQUIRE_EQ(0, result);
		ATF_REQUIRE_EQ(MODE_JOINT, cfg.chmode);
		ATF_REQUIRE_EQ(53, cfg.bitpool);
		ATF_REQUIRE_EQ(0, avdtpOpen(fd[0], cfg.sep));
		ATF_REQUIRE_EQ(0, avdtpStart(fd[0], cfg.sep));
		ATF_REQUIRE_EQ(0, avdtpSuspend(fd[0], cfg.sep));
		ATF_REQUIRE_EQ(0, avdtpStart(fd[0], cfg.sep));
		ATF_REQUIRE_EQ(0, avdtpClose(fd[0], cfg.sep));
	}
	close(fd[0]);
	reap(child);
	return (result);
}

ATF_TC_WITHOUT_HEAD(headset_lifecycle);
ATF_TC_BODY(headset_lifecycle, tc)
{
	/* Peer offers joint stereo but not ordinary stereo. */
	const uint8_t capabilities[] = {1, 0, 7, 6, 0, 0, 0x11, 0x15, 2, 53};
	(void)tc;
	ATF_REQUIRE_EQ(0, negotiate(capabilities, sizeof(capabilities), true));
}

ATF_TC_WITHOUT_HEAD(malformed_capabilities);
ATF_TC_BODY(malformed_capabilities, tc)
{
	const uint8_t trailing[] = {1, 0, 7, 6, 0, 0, 0x11, 0x15, 2, 53, 7};
	const uint8_t truncated[] = {1, 0, 7, 7, 0, 0, 0x11, 0x15, 2, 53};
	const uint8_t reversed[] = {1, 0, 7, 6, 0, 0, 0x11, 0x15, 53, 2};
	const uint8_t no_transport[] = {7, 6, 0, 0, 0x11, 0x15, 2, 53};
	(void)tc;
	ATF_REQUIRE_EQ(-EPROTO, negotiate(trailing, sizeof(trailing), false));
	ATF_REQUIRE_EQ(-EPROTO, negotiate(truncated, sizeof(truncated), false));
	ATF_REQUIRE_EQ(-EINVAL, negotiate(reversed, sizeof(reversed), false));
	ATF_REQUIRE_EQ(-EPROTO, negotiate(no_transport, sizeof(no_transport), false));
}

/* Adapted from bt-avdtp command_timeout: late replies cannot finish a new call. */
ATF_TC_WITHOUT_HEAD(fuchsia_timeout_late_response);
ATF_TC_BODY(fuchsia_timeout_late_response, tc)
{
	int fd[2];
	pid_t child;
	struct avdtpGetPacketInfo info;

	(void)tc;
	pair(fd);
	ATF_REQUIRE((child = fork()) >= 0);
	if (child == 0) {
		uint8_t first[2], second[2];
		uint8_t response[] = {0, 0x01, 0xf8, 0x08};
		close(fd[0]);
		ATF_REQUIRE_EQ(2, recv(fd[1], first, sizeof(first), 0));
		ATF_REQUIRE_EQ(2, recv(fd[1], second, sizeof(second), 0));
		ATF_REQUIRE_EQ(AVDTP_DISCOVER, first[1]);
		ATF_REQUIRE_EQ(AVDTP_DISCOVER, second[1]);
		ATF_REQUIRE(first[0] != second[0]);
		response[0] = first[0] | RESPONSEACCEPT;
		packet(fd[1], response, sizeof(response));
		response[0] = second[0] | RESPONSEACCEPT;
		response[2] = 0x20;
		packet(fd[1], response, sizeof(response));
		_exit(0);
	}
	close(fd[1]);
	ATF_REQUIRE_EQ(-ETIMEDOUT, avdtpSendSyncCommand(fd[0], &info,
	    AVDTP_DISCOVER, COMMAND, NULL, 0, NULL, 0));
	ATF_REQUIRE_EQ(0, avdtpSendSyncCommand(fd[0], &info,
	    AVDTP_DISCOVER, COMMAND, NULL, 0, NULL, 0));
	ATF_REQUIRE_EQ(2, info.buffer_len);
	ATF_REQUIRE_EQ(0x20, info.buffer_data[0]);
	close(fd[0]);
	reap(child);
}

static int
acceptor_command(struct bt_config *cfg, int peer, uint8_t signal,
    const uint8_t *data, int len, struct avdtpGetPacketInfo *response)
{
	int result;
	uint8_t copy[512];
	ATF_REQUIRE(len >= 0 && len <= (int)sizeof(copy));
	if (len != 0)
		memcpy(copy, data, len);
	ATF_REQUIRE_EQ(0, avdtpSendPacket(peer, signal, 5, COMMAND, copy, len, NULL, 0));
	result = avdtpACPHandlePacket(cfg);
	ATF_REQUIRE_EQ(result >= 0 ? RESPONSEACCEPT : RESPONSEREJECT,
	    avdtpGetPacket(peer, response));
	ATF_CHECK_EQ(5, response->trans);
	ATF_CHECK_EQ(signal, response->signalID);
	return (result);
}

static const uint8_t valid_configuration[] = {
	ACPSEP << 2, 9 << 2, 1, 0, 7, 6, 0, 0, 0x11, 0x15, 2, 53
};

ATF_TC_WITHOUT_HEAD(acceptor_truncated_configuration);
ATF_TC_BODY(acceptor_truncated_configuration, tc)
{
	struct bt_config cfg = {.acceptor_state = acpInitial};
	struct avdtpGetPacketInfo response;
	int fd[2];
	pair(fd);
	cfg.hc = fd[0];
	for (size_t n = 0; n < sizeof(valid_configuration); n++) {
		ATF_CHECK_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
		    AVDTP_SET_CONFIGURATION, valid_configuration, n, &response));
		ATF_CHECK_EQ(acpInitial, cfg.acceptor_state);
		ATF_CHECK_EQ(0, cfg.sep);
		ATF_CHECK(cfg.handle.sbc_enc == NULL);
		ATF_CHECK_EQ(2, response.buffer_len);
	}
}

ATF_TC_WITHOUT_HEAD(acceptor_invalid_codec_configuration);
ATF_TC_BODY(acceptor_invalid_codec_configuration, tc)
{
	struct bt_config cfg = {.acceptor_state = acpInitial};
	struct avdtpGetPacketInfo response;
	uint8_t data[sizeof(valid_configuration) + 2];
	int fd[2];
	const uint8_t mutations[][2] = {
	    {8, 0x31}, {9, 0x35}, {10, 0}, {11, 251},
	    {11, 1}, {6, 0x10}, {7, 2}, {5, 5}
	};
	pair(fd);
	cfg.hc = fd[0];
	for (size_t i = 0; i < sizeof(mutations) / sizeof(mutations[0]); i++) {
		memcpy(data, valid_configuration, sizeof(valid_configuration));
		data[mutations[i][0]] = mutations[i][1];
		ATF_CHECK_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
		    AVDTP_SET_CONFIGURATION, data, sizeof(valid_configuration), &response));
		ATF_CHECK_EQ(acpInitial, cfg.acceptor_state);
		ATF_CHECK_EQ(0, cfg.sep);
	}
	memcpy(data, valid_configuration, sizeof(valid_configuration));
	data[12] = 1; data[13] = 0; /* duplicate transport */
	ATF_CHECK_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_SET_CONFIGURATION, data, sizeof(data), &response));
}

/* Fuchsia stream_endpoint::start_and_suspend supplies the state oracle. */
ATF_TC_WITHOUT_HEAD(fuchsia_acceptor_start_suspend_abort);
ATF_TC_BODY(fuchsia_acceptor_start_suspend_abort, tc)
{
	struct bt_config cfg = {.acceptor_state = acpInitial};
	struct avdtpGetPacketInfo response;
	const uint8_t endpoint = ACPSEP << 2;
	int fd[2];
	pair(fd);
	cfg.hc = fd[0];
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1], AVDTP_START,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(AVDTP_SET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_SET_CONFIGURATION, valid_configuration, sizeof(valid_configuration), &response));
	ATF_REQUIRE_EQ(AVDTP_OPEN, acceptor_command(&cfg, fd[1], AVDTP_OPEN,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1], AVDTP_SUSPEND,
	    &endpoint, 1, &response)); /* Open is not Streaming. */
	ATF_CHECK_EQ(2, response.buffer_len);
	ATF_CHECK_EQ(BAD_STATE, response.buffer_data[1]);
	ATF_REQUIRE_EQ(AVDTP_START, acceptor_command(&cfg, fd[1], AVDTP_START,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1], AVDTP_START,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(AVDTP_SUSPEND, acceptor_command(&cfg, fd[1], AVDTP_SUSPEND,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(AVDTP_START, acceptor_command(&cfg, fd[1], AVDTP_START,
	    &endpoint, 1, &response));
	ATF_REQUIRE_EQ(AVDTP_ABORT, acceptor_command(&cfg, fd[1], AVDTP_ABORT,
	    &endpoint, 1, &response));
	ATF_CHECK_EQ(acpInitial, cfg.acceptor_state);
	ATF_REQUIRE_EQ(AVDTP_SET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_SET_CONFIGURATION, valid_configuration, sizeof(valid_configuration), &response));
	free(cfg.handle.sbc_enc);
}

ATF_TC_WITHOUT_HEAD(acceptor_wrong_endpoint);
ATF_TC_BODY(acceptor_wrong_endpoint, tc)
{
	struct bt_config cfg = {.acceptor_state = acpConfigurationSet};
	struct avdtpGetPacketInfo response;
	uint8_t endpoint = 4;
	int fd[2];
	pair(fd); cfg.hc = fd[0];
	ATF_CHECK_EQ(-ENXIO, acceptor_command(&cfg, fd[1], AVDTP_OPEN,
	    &endpoint, 1, &response));
	ATF_CHECK_EQ(BAD_ACP_SEID, response.buffer_data[0]);
	ATF_CHECK_EQ(acpConfigurationSet, cfg.acceptor_state);
	ATF_CHECK_EQ(-ENXIO, acceptor_command(&cfg, fd[1], AVDTP_OPEN,
	    NULL, 0, &response));
	ATF_CHECK_EQ(BAD_LENGTH, response.buffer_data[0]);
}

/* Fuchsia stream_endpoint::get_configuration: none, exact config, none. */
ATF_TC_WITHOUT_HEAD(fuchsia_acceptor_get_configuration);
ATF_TC_BODY(fuchsia_acceptor_get_configuration, tc)
{
	struct bt_config cfg = {.acceptor_state = acpInitial};
	struct avdtpGetPacketInfo response;
	uint8_t configuration[sizeof(valid_configuration)];
	const uint8_t endpoint = ACPSEP << 2;
	int fd[2];
	pair(fd); cfg.hc = fd[0];
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, &endpoint, 1, &response));
	ATF_CHECK_EQ(BAD_STATE, response.buffer_data[0]);
	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[10] = 10; /* Preserve the negotiated minimum, not just max. */
	ATF_REQUIRE_EQ(AVDTP_SET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_SET_CONFIGURATION, configuration, sizeof(configuration), &response));
	ATF_REQUIRE_EQ(AVDTP_GET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, &endpoint, 1, &response));
	ATF_REQUIRE_EQ(sizeof(configuration) - 2, response.buffer_len);
	ATF_CHECK_EQ(0, memcmp(configuration + 2, response.buffer_data,
	    sizeof(configuration) - 2));
	ATF_REQUIRE_EQ(AVDTP_OPEN, acceptor_command(&cfg, fd[1],
	    AVDTP_OPEN, &endpoint, 1, &response));
	ATF_REQUIRE_EQ(AVDTP_START, acceptor_command(&cfg, fd[1],
	    AVDTP_START, &endpoint, 1, &response));
	cfg.bitpool = 35; /* Decoder's current frame need not use the maximum. */
	ATF_REQUIRE_EQ(AVDTP_GET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, &endpoint, 1, &response));
	ATF_CHECK_EQ(0, memcmp(configuration + 2, response.buffer_data,
	    sizeof(configuration) - 2));
	ATF_REQUIRE_EQ(AVDTP_ABORT, acceptor_command(&cfg, fd[1],
	    AVDTP_ABORT, &endpoint, 1, &response));
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, &endpoint, 1, &response));
	ATF_CHECK_EQ(BAD_STATE, response.buffer_data[0]);
	free(cfg.handle.sbc_enc);
	close(fd[0]); close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(unsolicited_command_reject_shape);
ATF_TC_BODY(unsolicited_command_reject_shape, tc)
{
	const uint8_t signals[] = {AVDTP_START, AVDTP_SUSPEND,
	    AVDTP_SET_CONFIGURATION, AVDTP_RECONFIGURE};
	for (size_t i = 0; i < sizeof(signals); i++) {
		int fd[2];
		pid_t child;
		pair(fd);
		ATF_REQUIRE((child = fork()) >= 0);
		if (child == 0) {
			uint8_t request[3], response[2];
			const uint8_t command[] = {0xa0, signals[i], ACPSEP << 2};
			struct avdtpGetPacketInfo reject;
			close(fd[0]);
			ATF_REQUIRE_EQ(3, recv(fd[1], request, sizeof(request), 0));
			packet(fd[1], command, sizeof(command));
			ATF_REQUIRE_EQ(RESPONSEREJECT, avdtpGetPacket(fd[1], &reject));
			ATF_REQUIRE_EQ(0xa, reject.trans);
			ATF_REQUIRE_EQ(signals[i], reject.signalID);
			ATF_REQUIRE_EQ(2, reject.buffer_len);
			ATF_REQUIRE_EQ(i < 2 ? ACPSEP << 2 : 0, reject.buffer_data[0]);
			ATF_REQUIRE_EQ(BAD_STATE, reject.buffer_data[1]);
			response[0] = (request[0] & 0xf0) | RESPONSEACCEPT;
			response[1] = AVDTP_OPEN;
			packet(fd[1], response, sizeof(response));
			_exit(0);
		}
		close(fd[1]);
		ATF_REQUIRE_EQ(0, avdtpOpen(fd[0], ACPSEP));
		close(fd[0]);
		reap(child);
	}
}

ATF_TC_WITHOUT_HEAD(configuration_query_bad_endpoint_and_length);
ATF_TC_BODY(configuration_query_bad_endpoint_and_length, tc)
{
	struct bt_config cfg = {.acceptor_state = acpInitial};
	struct avdtpGetPacketInfo response;
	const uint8_t endpoints[] = {4, ACPSEP << 2};
	int fd[2];
	pair(fd); cfg.hc = fd[0];
	ATF_REQUIRE_EQ(AVDTP_SET_CONFIGURATION, acceptor_command(&cfg, fd[1],
	    AVDTP_SET_CONFIGURATION, valid_configuration, sizeof(valid_configuration), &response));
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, endpoints, 1, &response));
	ATF_CHECK_EQ(BAD_ACP_SEID, response.buffer_data[0]);
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, endpoints, 2, &response));
	ATF_CHECK_EQ(BAD_LENGTH, response.buffer_data[0]);
	ATF_REQUIRE_EQ(-ENXIO, acceptor_command(&cfg, fd[1],
	    AVDTP_GET_CONFIGURATION, NULL, 0, &response));
	ATF_CHECK_EQ(BAD_LENGTH, response.buffer_data[0]);
	ATF_CHECK_EQ(acpConfigurationSet, cfg.acceptor_state);
	free(cfg.handle.sbc_enc);
	close(fd[0]); close(fd[1]);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, fuchsia_acceptor_get_configuration);
	ATF_TP_ADD_TC(tp, configuration_query_bad_endpoint_and_length);
	ATF_TP_ADD_TC(tp, unsolicited_command_reject_shape);
	ATF_TP_ADD_TC(tp, single_payload);
	ATF_TP_ADD_TC(tp, empty_accept);
	ATF_TP_ADD_TC(tp, fragment_reassembly);
	ATF_TP_ADD_TC(tp, header_only_fragments);
	ATF_TP_ADD_TC(tp, malformed_headers);
	ATF_TP_ADD_TC(tp, fragment_mismatch);
	ATF_TP_ADD_TC(tp, payload_bounds);
	ATF_TP_ADD_TC(tp, fragment_overflow);
	ATF_TP_ADD_TC(tp, fragment_timeout);
	ATF_TP_ADD_TC(tp, transaction_correlation);
	ATF_TP_ADD_TC(tp, timeout_preserves_alarm);
	ATF_TP_ADD_TC(tp, closed_peer);
	ATF_TP_ADD_TC(tp, headset_lifecycle);
	ATF_TP_ADD_TC(tp, malformed_capabilities);
	ATF_TP_ADD_TC(tp, fuchsia_timeout_late_response);
	ATF_TP_ADD_TC(tp, acceptor_truncated_configuration);
	ATF_TP_ADD_TC(tp, acceptor_invalid_codec_configuration);
	ATF_TP_ADD_TC(tp, fuchsia_acceptor_start_suspend_abort);
	ATF_TP_ADD_TC(tp, acceptor_wrong_endpoint);
	return (atf_no_error());
}
