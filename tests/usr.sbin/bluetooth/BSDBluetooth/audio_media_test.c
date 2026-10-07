/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 */
#include <atf-c.h>
#include <signal.h>

#define BT_MEDIA_TIMEOUT_MS 100
#include "bt.c"

void
virtual_oss_wait(void)
{
}

static void
setup(struct bt_config *cfg, int fd[2])
{
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fd));
	bt_init_cfg(cfg);
	cfg->fd = fd[0];
	cfg->freq = FREQ_48K;
	cfg->bands = BANDS_8;
	cfg->blocks = BLOCKS_16;
	cfg->chmode = MODE_JOINT;
	cfg->allocm = ALLOC_LOUDNESS;
	cfg->bitpool = 53;
	cfg->mtu = 8192;
	cfg->handle.sbc_enc = calloc(1, sizeof(*cfg->handle.sbc_enc));
	ATF_REQUIRE(cfg->handle.sbc_enc != NULL);
}

static uint32_t
timestamp(const uint8_t *p)
{
	return ((uint32_t)p[4] << 24 | (uint32_t)p[5] << 16 |
	    (uint32_t)p[6] << 8 | p[7]);
}

ATF_TC_WITHOUT_HEAD(packetization);
ATF_TC_BODY(packetization, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	int16_t pcm[20 * 256] = {0};
	uint8_t packet[8192];
	ssize_t size;

	(void)tc;
	setup(&cfg, fd);
	ATF_REQUIRE_EQ(sizeof(pcm), bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	size = recv(fd[1], packet, sizeof(packet), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(13 + 15 * 119, size);
	ATF_REQUIRE_EQ(0x80, packet[0]);
	ATF_REQUIRE_EQ(15, packet[12]);
	ATF_REQUIRE_EQ(0, packet[2]);
	ATF_REQUIRE_EQ(0, packet[3]);
	ATF_REQUIRE_EQ(0, timestamp(packet));
	for (int i = 0; i != 15; i++)
		ATF_REQUIRE_EQ(0x9c, packet[13 + i * 119]);
	size = recv(fd[1], packet, sizeof(packet), MSG_DONTWAIT);
	ATF_REQUIRE_EQ(13 + 5 * 119, size);
	ATF_REQUIRE_EQ(5, packet[12]);
	ATF_REQUIRE_EQ(1, packet[3]);
	ATF_REQUIRE_EQ(15 * 128, timestamp(packet));
	ATF_REQUIRE_EQ(0, cfg.mtu_offset);
	bt_play_close(&backend);
	close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(partial_pcm_and_small_mtu);
ATF_TC_BODY(partial_pcm_and_small_mtu, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	uint8_t pcm[512] = {0}, packet[256];

	(void)tc;
	setup(&cfg, fd);
	cfg.mtu = 132;
	ATF_REQUIRE_EQ(3, bt_play_sbc_transfer(&backend, pcm, 3));
	ATF_REQUIRE_EQ(-1, recv(fd[1], packet, sizeof(packet), MSG_DONTWAIT));
	ATF_REQUIRE_EQ(EAGAIN, errno);
	ATF_REQUIRE_EQ(509, bt_play_sbc_transfer(&backend, pcm + 3, 509));
	ATF_REQUIRE_EQ(132, recv(fd[1], packet, sizeof(packet), MSG_DONTWAIT));
	ATF_REQUIRE_EQ(1, packet[12]);
	ATF_REQUIRE_EQ(128, cfg.mtu_timestamp);
	bt_play_close(&backend);
	close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(undersized_mtu);
ATF_TC_BODY(undersized_mtu, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	int16_t pcm[256] = {0};

	(void)tc;
	setup(&cfg, fd);
	cfg.mtu = 8;
	ATF_REQUIRE_EQ(-1, bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	ATF_REQUIRE_EQ(EMSGSIZE, errno);
	bt_play_close(&backend);
	close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(media_disconnect);
ATF_TC_BODY(media_disconnect, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	int16_t pcm[256] = {0};

	(void)tc;
	setup(&cfg, fd);
	close(fd[1]);
	signal(SIGPIPE, SIG_DFL);
	ATF_REQUIRE_EQ(-1, bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	bt_play_close(&backend);
	ATF_REQUIRE_EQ(-1, cfg.fd);
	ATF_REQUIRE_EQ(-1, cfg.hc);
	ATF_REQUIRE_EQ(NULL, cfg.handle.sbc_enc);
}

ATF_TC_WITHOUT_HEAD(descriptor_zero_cleanup);
ATF_TC_BODY(descriptor_zero_cleanup, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];

	(void)tc;
	setup(&cfg, fd);
	if (fd[0] != 0) {
		ATF_REQUIRE_EQ(0, dup2(fd[0], 0));
		close(fd[0]);
	}
	cfg.fd = 0;
	bt_play_close(&backend);
	ATF_REQUIRE_EQ(-1, fcntl(0, F_GETFD));
	ATF_REQUIRE_EQ(EBADF, errno);
	close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(partial_receive_offset);
ATF_TC_BODY(partial_receive_offset, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	int16_t first[2], second[2];

	(void)tc;
	setup(&cfg, fd);
	cfg.handle.sbc_enc->music_data[0] = 0x1234;
	cfg.handle.sbc_enc->music_data[1] = 0x2345;
	cfg.handle.sbc_enc->music_data[2] = 0x3456;
	cfg.handle.sbc_enc->music_data[3] = 0x4567;
	cfg.handle.sbc_enc->rem_len = 4;
	ATF_REQUIRE_EQ(sizeof(first), bt_receive(&cfg, first, sizeof(first), 0));
	ATF_REQUIRE_EQ(sizeof(second), bt_receive(&cfg, second, sizeof(second), 0));
	ATF_REQUIRE_EQ(0x1234, first[0]);
	ATF_REQUIRE_EQ(0x2345, first[1]);
	ATF_REQUIRE_EQ(0x3456, second[0]);
	ATF_REQUIRE_EQ(0x4567, second[1]);
	bt_play_close(&backend);
	close(fd[1]);
}

ATF_TC_WITHOUT_HEAD(stalled_media_output);
ATF_TC_BODY(stalled_media_output, tc)
{
	struct bt_config cfg;
	int fd[2], size = 4096;
	uint8_t data[512] = {0};
	struct timespec before, after;
	int64_t elapsed;

	setup(&cfg, fd);
	ATF_REQUIRE_EQ(0, setsockopt(fd[0], SOL_SOCKET, SO_SNDBUF,
	    &size, sizeof(size)));
	while (send(fd[0], data, sizeof(data), MSG_DONTWAIT | MSG_EOR) >= 0)
		;
	ATF_REQUIRE(errno == EAGAIN || errno == EWOULDBLOCK);
	cfg.mtu_offset = sizeof(data);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &before));
	ATF_CHECK_EQ(-1, bt_send_media(&cfg));
	ATF_CHECK_EQ(ETIMEDOUT, errno);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &after));
	elapsed = (after.tv_sec - before.tv_sec) * 1000 +
	    (after.tv_nsec - before.tv_nsec) / 1000000;
	ATF_CHECK(elapsed >= 80 && elapsed < 2000);
}

static size_t
encoded_frame(struct bt_config *cfg, uint8_t *frame, size_t capacity)
{
	struct voss_backend backend = {.arg = cfg};
	int fd[2];
	int16_t pcm[256] = {0};
	uint8_t packet[1024];
	ssize_t n;

	setup(cfg, fd);
	ATF_REQUIRE_EQ(sizeof(pcm), bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	n = recv(fd[1], packet, sizeof(packet), 0);
	ATF_REQUIRE_EQ(132, n); /* RTP(12), SBC payload header(1), frame(119) */
	ATF_REQUIRE(capacity >= 119);
	memcpy(frame, packet + 13, 119);
	close(fd[1]);
	return (119);
}

ATF_TC_WITHOUT_HEAD(sbc_receive_crc_and_truncation);
ATF_TC_BODY(sbc_receive_crc_and_truncation, tc)
{
	struct bt_config cfg;
	uint8_t frame[1024];
	size_t n = encoded_frame(&cfg, frame, sizeof(frame));
	struct sbc_encode *sbc = cfg.handle.sbc_enc;

	sbc->rem_data_ptr = frame;
	for (size_t len = 0; len < n; len++) {
		ATF_CHECK_EQ_MSG(0, sbc_decode_frame(&cfg, len * 8),
		    "accepted truncated frame of %zu bytes", len);
		ATF_CHECK_EQ(0, sbc->rem_len);
	}
	ATF_REQUIRE_EQ(n, sbc_decode_frame(&cfg, n * 8));
	ATF_CHECK_EQ(256, sbc->rem_len);
	frame[3] ^= 1;
	ATF_CHECK_EQ(0, sbc_decode_frame(&cfg, n * 8));
	ATF_CHECK_EQ(0, sbc->rem_len);
	frame[3] ^= 1;
	frame[2] = 251;
	ATF_CHECK_EQ(0, sbc_decode_frame(&cfg, n * 8));
	frame[2] = 0;
	ATF_CHECK_EQ(0, sbc_decode_frame(&cfg, n * 8));
}

ATF_TC_WITHOUT_HEAD(receive_malformed_rtp);
ATF_TC_BODY(receive_malformed_rtp, tc)
{
	struct bt_config cfg;
	int fd[2];
	int16_t pcm[256];
	uint8_t packet[14] = {0x80, 96};

	setup(&cfg, fd);
	for (unsigned frames = 0; frames < 256; frames++) {
		if (frames > 0 && frames < 16)
			continue;
		packet[12] = frames;
		ATF_REQUIRE_EQ(sizeof(packet), send(fd[1], packet, sizeof(packet), MSG_EOR));
		ATF_CHECK_EQ(-1, bt_receive(&cfg, pcm, sizeof(pcm), 0));
		ATF_CHECK_EQ(EPROTO, errno);
	}
	ATF_CHECK_EQ(-1, bt_receive(&cfg, pcm, 1, 0));
	ATF_CHECK_EQ(EINVAL, errno);
}

ATF_TC_WITHOUT_HEAD(receive_recovery_after_bad_frame);
ATF_TC_BODY(receive_recovery_after_bad_frame, tc)
{
	struct bt_config cfg, encoder, fresh;
	int fd[2], cleanfd[2];
	uint8_t packet[132] = {0x80, 96};
	int16_t pcm[256], expected[256];

	ATF_REQUIRE_EQ(119, encoded_frame(&encoder, packet + 13, 119));
	setup(&cfg, fd);
	setup(&fresh, cleanfd);
	packet[12] = 1;
	ATF_REQUIRE_EQ(sizeof(packet), send(cleanfd[1], packet, sizeof(packet), MSG_EOR));
	ATF_REQUIRE_EQ(sizeof(expected), bt_receive(&fresh, expected, sizeof(expected), 0));
	packet[16] ^= 1;
	ATF_REQUIRE_EQ(sizeof(packet), send(fd[1], packet, sizeof(packet), MSG_EOR));
	ATF_CHECK_EQ(-1, bt_receive(&cfg, pcm, sizeof(pcm), 0));
	ATF_CHECK_EQ(EPROTO, errno);
	packet[16] ^= 1;
	ATF_REQUIRE_EQ(sizeof(packet), send(fd[1], packet, sizeof(packet), MSG_EOR));
	ATF_REQUIRE_EQ(sizeof(pcm), bt_receive(&cfg, pcm, sizeof(pcm), 0));
	/* Rejecting the bad frame must leave the decoder's history untouched. */
	ATF_CHECK_EQ(0, memcmp(expected, pcm, sizeof(pcm)));
}

ATF_TC_WITHOUT_HEAD(media_reopen_resets_state);
ATF_TC_BODY(media_reopen_resets_state, tc)
{
	struct bt_config cfg;
	struct voss_backend backend = {.arg = &cfg};
	int fd[2];
	uint8_t packet[1024];
	int16_t pcm[256] = {0};

	setup(&cfg, fd);
	ATF_REQUIRE_EQ(sizeof(pcm), bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	ATF_REQUIRE(recv(fd[1], packet, sizeof(packet), 0) > 0);
	bt_play_close(&backend);
	close(fd[1]);
	setup(&cfg, fd);
	ATF_REQUIRE_EQ(sizeof(pcm), bt_play_sbc_transfer(&backend, pcm, sizeof(pcm)));
	ATF_REQUIRE(recv(fd[1], packet, sizeof(packet), 0) > 0);
	ATF_CHECK_EQ(0, packet[2]);
	ATF_CHECK_EQ(0, packet[3]);
	ATF_CHECK_EQ(0, timestamp(packet));
}

ATF_TC_WITHOUT_HEAD(sbc_decode_configuration_matrix);
ATF_TC_BODY(sbc_decode_configuration_matrix, tc)
{
	struct bt_config cfg, decoder;
	struct voss_backend backend = {.arg = &cfg};
	struct sbc_encode decoded;
	int fd[2];
	int16_t pcm[256] = {0};
	uint8_t packet[1024];
	size_t bytes;
	ssize_t n;

	for (unsigned mode = 0; mode < 4; mode++)
	for (unsigned bands = 0; bands < 2; bands++)
	for (unsigned blocks = 0; blocks < 4; blocks++) {
		setup(&cfg, fd);
		cfg.chmode = mode; cfg.bands = bands; cfg.blocks = blocks;
		bytes = 2 * (mode == MODE_MONO ? 1 : 2) *
		    (4 << bands) * (4 * (blocks + 1));
		ATF_REQUIRE_EQ((int)bytes, bt_play_sbc_transfer(&backend, pcm, bytes));
		n = recv(fd[1], packet, sizeof(packet), 0);
		ATF_REQUIRE(n > 13);
		decoder = cfg;
		memset(&decoded, 0, sizeof(decoded));
		decoder.handle.sbc_enc = &decoded;
		decoded.rem_data_ptr = packet + 13;
		ATF_REQUIRE_EQ_MSG((size_t)n - 13, sbc_decode_frame(&decoder, (n - 13) * 8),
		    "mode=%u bands=%u blocks=%u", mode, bands, blocks);
		ATF_CHECK_EQ(bytes / 2, decoded.rem_len);
		bt_play_close(&backend);
		close(fd[1]);
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, sbc_decode_configuration_matrix);
	ATF_TP_ADD_TC(tp, packetization);
	ATF_TP_ADD_TC(tp, partial_pcm_and_small_mtu);
	ATF_TP_ADD_TC(tp, undersized_mtu);
	ATF_TP_ADD_TC(tp, media_disconnect);
	ATF_TP_ADD_TC(tp, descriptor_zero_cleanup);
	ATF_TP_ADD_TC(tp, partial_receive_offset);
	ATF_TP_ADD_TC(tp, stalled_media_output);
	ATF_TP_ADD_TC(tp, sbc_receive_crc_and_truncation);
	ATF_TP_ADD_TC(tp, receive_malformed_rtp);
	ATF_TP_ADD_TC(tp, receive_recovery_after_bad_frame);
	ATF_TP_ADD_TC(tp, media_reopen_resets_state);
	return (atf_no_error());
}
