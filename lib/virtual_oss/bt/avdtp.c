/* $NetBSD$ */

/*-
 * Copyright (c) 2015-2016 Nathanial Sloss <nathanialsloss@yahoo.com.au>
 * Copyright (c) 2016-2019 Hans Petter Selasky <hps@selasky.org>
 * Copyright (c) 2019 Google LLC, written by Richard Kralovic <riso@google.com>
 *
 *		This software is dedicated to the memory of -
 *	   Baron James Anlezark (Barry) - 1 Jan 1949 - 13 May 2012.
 *
 *		Barry was a man who loved his music.
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
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/uio.h>
#include <sys/socket.h>

#include <stdio.h>
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "avdtp_signal.h"
#include "bt.h"

#define	DPRINTF(...) printf("backend_bt: " __VA_ARGS__)

struct avdtpGetPacketInfo {
	uint8_t buffer_data[512];
	uint16_t buffer_len;
	uint8_t trans;
	uint8_t signalID;
};

static int avdtpAutoConfig(struct bt_config *);

#ifndef AVDTP_TIMEOUT_MS
#define AVDTP_TIMEOUT_MS 8000
#endif

static int64_t
avdtpNow(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return (-1);
	return ((int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000);
}

/* One deadline covers the entire transaction, including all fragments. */
static int
avdtpWait(int fd, short events, int64_t deadline)
{
	struct pollfd pfd = { .fd = fd, .events = events };
	int64_t now;
	int result;

	if (fd < 0)
		return (-EBADF);
	for (;;) {
		now = avdtpNow();
		if (now < 0)
			return (-errno);
		if (now >= deadline)
			return (-ETIMEDOUT);
		result = poll(&pfd, 1, (int)(deadline - now));
		if (result < 0 && errno == EINTR)
			continue;
		if (result < 0)
			return (-errno);
		if (result == 0)
			continue;
		if (pfd.revents & POLLNVAL)
			return (-EBADF);
		/* Let recvmsg drain a final packet before reporting hangup. */
		return (0);
	}
}

/* Return received message type if success, < 0 if failure. */
static int
avdtpGetPacketUntil(int fd, struct avdtpGetPacketInfo *info, int64_t deadline)
{
	uint8_t packet[sizeof(info->buffer_data) + 3];
	uint8_t message_type = 0;
	unsigned remaining = 1;
	bool first = true;
	ssize_t len;
	int result;

	memset(info, 0, sizeof(*info));

	/* Handle fragmented packets */
	while (remaining != 0) {
		struct iovec iov = { .iov_base = packet, .iov_len = sizeof(packet) };
		struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };

		result = avdtpWait(fd, POLLIN, deadline);
		if (result != 0)
			return (result);
		len = recvmsg(fd, &msg, MSG_DONTWAIT);
		if (len < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (len < 0)
			return (-errno);
		if (len == 0)
			return (-ECONNRESET);
		if (msg.msg_flags & MSG_TRUNC)
			return (-EMSGSIZE);

		uint8_t trans = (packet[0] & TRANSACTIONLABEL) >> TRANSACTIONLABEL_S;
		uint8_t packet_type = (packet[0] & PACKETTYPE) >> PACKETTYPE_S;
		uint8_t current_message_type = packet[0] & MESSAGETYPE;
		size_t shift;
		if (first) {
			info->trans = trans;
			message_type = current_message_type;
			if (packet_type == singlePacket) {
				shift = 2;
			} else {
				if (packet_type != startPacket || len < 3 || packet[1] < 2)
					return (-EPROTO);
				remaining = packet[1];
				shift = 3;
			}
			if ((size_t)len < shift)
				return (-EPROTO);
			info->signalID = packet[shift - 1] & SIGNALID_MASK;
			first = false;
		} else {
			if (info->trans != trans ||
			    message_type != current_message_type ||
			    (remaining == 1 && packet_type != endPacket) ||
			    (remaining > 1 && packet_type != continuePacket)) {
				return (-EPROTO);
			}
			shift = 1;
		}
		if ((size_t)len - shift > sizeof(info->buffer_data) - info->buffer_len)
			return (-EMSGSIZE);
		memcpy(info->buffer_data + info->buffer_len, packet + shift, len - shift);
		info->buffer_len += len - shift;
		remaining--;
	}
	return (message_type);
}

static int
avdtpGetPacket(int fd, struct avdtpGetPacketInfo *info)
{
	return (avdtpGetPacketUntil(fd, info, avdtpNow() + AVDTP_TIMEOUT_MS));
}

/* Returns 0 on success, < 0 on failure. */
static int
avdtpSendPacketUntil(int fd, uint8_t command, uint8_t trans, uint8_t type,
    uint8_t * data0, int datasize0, uint8_t * data1,
    int datasize1, int64_t deadline)
{
	struct iovec iov[3];
	uint8_t header[2];
	ssize_t sent;
	int retval;

	if (datasize0 < 0 || datasize1 < 0 || datasize0 > 512 || datasize1 > 512 ||
	    (datasize0 != 0 && data0 == NULL) || (datasize1 != 0 && data1 == NULL))
		return (-EINVAL);

	/* fill out command header */
	header[0] = (trans << 4) | (type & 3);
	if (command != 0)
		header[1] = command & 0x3f;
	else
		header[1] = 3;

	iov[0].iov_base = header;
	iov[0].iov_len = 2;
	iov[1].iov_base = data0;
	iov[1].iov_len = datasize0;
	iov[2].iov_base = data1;
	iov[2].iov_len = datasize1;

	struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 3 };
	for (;;) {
		retval = avdtpWait(fd, POLLOUT, deadline);
		if (retval != 0)
			return (retval);
		sent = sendmsg(fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_EOR);
		if (sent < 0 && (errno == EINTR || errno == EAGAIN))
			continue;
		if (sent < 0)
			return (-errno);
		return (sent == 2 + datasize0 + datasize1 ? 0 : -EIO);
	}
}

static int
avdtpSendPacket(int fd, uint8_t command, uint8_t trans, uint8_t type,
    uint8_t *data0, int datasize0, uint8_t *data1, int datasize1)
{
	return (avdtpSendPacketUntil(fd, command, trans, type, data0, datasize0,
	    data1, datasize1, avdtpNow() + AVDTP_TIMEOUT_MS));
}

/* Returns 0 on success, < 0 on failure. */
static int
avdtpSendSyncCommand(int fd, struct avdtpGetPacketInfo *info,
    uint8_t command, uint8_t type, uint8_t * data0,
    int datasize0, uint8_t * data1, int datasize1)
{
	static atomic_uint transLabel;
	int64_t deadline = avdtpNow() + AVDTP_TIMEOUT_MS;
	uint8_t trans;
	int retval;

	trans = atomic_fetch_add_explicit(&transLabel, 1, memory_order_relaxed) & 0xF;

	retval = avdtpSendPacketUntil(fd, command, trans, type,
	    data0, datasize0, data1, datasize1, deadline);
	if (retval)
		goto done;
retry:
	retval = avdtpGetPacketUntil(fd, info, deadline);
	switch (retval) {
	case RESPONSEACCEPT:
		if (info->trans != trans || info->signalID != command)
			goto retry;
		switch (command) {
		case AVDTP_SET_CONFIGURATION:
		case AVDTP_OPEN:
		case AVDTP_START:
		case AVDTP_CLOSE:
		case AVDTP_SUSPEND:
		case AVDTP_ABORT:
			if (info->buffer_len != 0)
				return (-EPROTO);
			break;
		default:
			break;
		}
		retval = 0;
		break;
	case RESPONSEREJECT:
		if (info->trans != trans || info->signalID != command)
			goto retry;
		retval = -EINVAL;
		break;
	case COMMAND: {
		uint8_t error[2] = {0, BAD_STATE};
		int len = 1;

		if (info->signalID == AVDTP_START || info->signalID == AVDTP_SUSPEND) {
			error[0] = info->buffer_len != 0 ? info->buffer_data[0] : 0;
			len = 2;
		} else if (info->signalID == AVDTP_SET_CONFIGURATION ||
		    info->signalID == AVDTP_RECONFIGURE)
			len = 2;
		retval = avdtpSendPacketUntil(fd, info->signalID, info->trans,
		    RESPONSEREJECT, error + 2 - len, len, NULL, 0, deadline);
		if (retval == 0)
			goto retry;
		break;
	}
	default:
		if (retval >= 0)
			retval = -ENXIO;
		break;
	}
done:
	return (retval);
}

/*
 * Variant for acceptor role: We support any frequency, blocks, bands, and
 * allocation. Returns 0 on success, < 0 on failure.
 */
static int
avdtpSendCapabilitiesResponseSBCForACP(int fd, int trans)
{
	uint8_t data[10];

	data[0] = mediaTransport;
	data[1] = 0;
	data[2] = mediaCodec;
	data[3] = 0x6;
	data[4] = mediaTypeAudio;
	data[5] = SBC_CODEC_ID;
	data[6] =
	    (1 << (3 - MODE_STEREO)) |
	    (1 << (3 - MODE_JOINT)) |
	    (1 << (3 - MODE_DUAL)) |
	    (1 << (3 - MODE_MONO)) |
	    (1 << (7 - FREQ_44_1K)) |
	    (1 << (7 - FREQ_48K)) |
	    (1 << (7 - FREQ_32K)) |
	    (1 << (7 - FREQ_16K));
	data[7] =
	    (1 << (7 - BLOCKS_4)) |
	    (1 << (7 - BLOCKS_8)) |
	    (1 << (7 - BLOCKS_12)) |
	    (1 << (7 - BLOCKS_16)) |
	    (1 << (3 - BANDS_4)) |
	    (1 << (3 - BANDS_8)) | (1 << ALLOC_LOUDNESS) | (1 << ALLOC_SNR);
	data[8] = MIN_BITPOOL;
	data[9] = DEFAULT_MAXBPOOL;

	return (avdtpSendPacket(fd, AVDTP_GET_CAPABILITIES, trans,
	    RESPONSEACCEPT, data, sizeof(data), NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpSendAccept(int fd, uint8_t trans, uint8_t myCommand)
{
	return (avdtpSendPacket(fd, myCommand, trans, RESPONSEACCEPT,
	    NULL, 0, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpSendReject(int fd, uint8_t trans, uint8_t myCommand)
{
	uint8_t value[2] = {0, BAD_STATE};
	int length = 1;

	if (myCommand == AVDTP_START || myCommand == AVDTP_SUSPEND) {
		value[0] = ACPSEP << 2;
		length = 2;
	} else if (myCommand == AVDTP_SET_CONFIGURATION ||
	    myCommand == AVDTP_RECONFIGURE)
		length = 2;

	return (avdtpSendPacket(fd, myCommand, trans, RESPONSEREJECT,
	    value + 2 - length, length, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpSendDiscResponseAudio(int fd, uint8_t trans,
    uint8_t mySep, uint8_t is_sink)
{
	uint8_t data[2];

	data[0] = mySep << 2;
	data[1] = mediaTypeAudio << 4 | (is_sink ? (1 << 3) : 0);

	return (avdtpSendPacket(fd, AVDTP_DISCOVER, trans, RESPONSEACCEPT,
	    data, 2, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpDiscoverAndConfig(struct bt_config *cfg, bool isSink)
{
	struct avdtpGetPacketInfo info;
	uint16_t offset;
	uint8_t chmode = cfg->chmode;
	uint8_t bitpool = cfg->bitpool;
	uint8_t aacMode1 = cfg->aacMode1;
	uint8_t aacMode2 = cfg->aacMode2;
	int retval;

	retval = avdtpSendSyncCommand(cfg->hc, &info, AVDTP_DISCOVER, 0,
	    NULL, 0, NULL, 0);
	if (retval)
		return (retval);
	if ((info.buffer_len & 1) != 0)
		return (-EPROTO);

	retval = -EBUSY;
	for (offset = 0; offset + 2 <= info.buffer_len; offset += 2) {
		cfg->sep = info.buffer_data[offset] >> 2;
		cfg->media_Type = info.buffer_data[offset + 1] >> 4;
		cfg->chmode = chmode;
		cfg->bitpool = bitpool;
		cfg->aacMode1 = aacMode1;
		cfg->aacMode2 = aacMode2;
		if (cfg->sep == 0 || cfg->sep > 62 || cfg->media_Type != mediaTypeAudio)
			continue;
		if (info.buffer_data[offset] & DISCOVER_SEP_IN_USE)
			continue;
		if (info.buffer_data[offset + 1] & DISCOVER_IS_SINK) {
			if (!isSink)
				continue;
		} else {
			if (isSink)
				continue;
		}
		/* try to configure SBC */
		retval = avdtpAutoConfig(cfg);
		if (retval == 0)
			return (0);
	}
	return (retval);
}

/* Returns 0 on success, < 0 on failure. */
static int
avdtpGetCapabilities(int fd, uint8_t sep, struct avdtpGetPacketInfo *info)
{
	uint8_t address = (sep << 2);

	return (avdtpSendSyncCommand(fd, info,
	    AVDTP_GET_CAPABILITIES, 0, &address, 1,
	    NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpSetConfiguration(int fd, uint8_t sep, uint8_t * data, int datasize)
{
	struct avdtpGetPacketInfo info;
	uint8_t configAddresses[2];

	configAddresses[0] = sep << 2;
	configAddresses[1] = INTSEP << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_SET_CONFIGURATION, 0,
	    configAddresses, 2, data, datasize));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpOpen(int fd, uint8_t sep)
{
	struct avdtpGetPacketInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_OPEN, 0,
	    &address, 1, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpStart(int fd, uint8_t sep)
{
	struct avdtpGetPacketInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_START, 0,
	    &address, 1, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpClose(int fd, uint8_t sep)
{
	struct avdtpGetPacketInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_CLOSE, 0,
	    &address, 1, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpSuspend(int fd, uint8_t sep)
{
	struct avdtpGetPacketInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_SUSPEND, 0,
	    &address, 1, NULL, 0));
}

/* Returns 0 on success, < 0 on failure. */
int
avdtpAbort(int fd, uint8_t sep)
{
	struct avdtpGetPacketInfo info;
	uint8_t address = sep << 2;

	return (avdtpSendSyncCommand(fd, &info, AVDTP_ABORT, 0,
	    &address, 1, NULL, 0));
}

static int
avdtpAutoConfig(struct bt_config *cfg)
{
	struct avdtpGetPacketInfo info;
	uint8_t freqmode;
	uint8_t blk_len_sb_alloc;
	uint8_t availFreqMode = 0;
	uint8_t availConfig = 0;
	uint8_t supBitpoolMin = 0;
	uint8_t supBitpoolMax = 0;
	uint8_t aacMode1 = 0;
	uint8_t aacMode2 = 0;
#ifdef HAVE_LIBAV
	uint8_t aacBitrate3 = 0;
	uint8_t aacBitrate4 = 0;
	uint8_t aacBitrate5 = 0;
#endif
	int retval;
	int i;
	bool transport = false, sbc = false;

	retval = avdtpGetCapabilities(cfg->hc, cfg->sep, &info);
	if (retval) {
		DPRINTF("Cannot get capabilities\n");
		return (retval);
	}
retry:
	for (i = 0; (i + 1) < info.buffer_len;) {
#if 0
		DPRINTF("0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
		    info.buffer_data[i + 0],
		    info.buffer_data[i + 1],
		    info.buffer_data[i + 2],
		    info.buffer_data[i + 3],
		    info.buffer_data[i + 4], info.buffer_data[i + 5]);
#endif
		if (i + 2 + info.buffer_data[i + 1] > info.buffer_len)
			return (-EPROTO);
		switch (info.buffer_data[i]) {
		case mediaTransport:
			if (transport || info.buffer_data[i + 1] != 0)
				return (-EPROTO);
			transport = true;
			break;
		case mediaCodec:
			if (info.buffer_data[i + 1] < 2)
				return (-EPROTO);
			if ((info.buffer_data[i + 2] >> 4) != mediaTypeAudio)
				break;
			/* check codec */
			switch (info.buffer_data[i + 3]) {
			case 0:			/* SBC */
				if (sbc || info.buffer_data[i + 1] != 6)
					return (-EPROTO);
				sbc = true;
				availFreqMode = info.buffer_data[i + 4];
				availConfig = info.buffer_data[i + 5];
				supBitpoolMin = info.buffer_data[i + 6];
				supBitpoolMax = info.buffer_data[i + 7];
				break;
			case 2:			/* MPEG2/4 AAC */
				if (info.buffer_data[i + 1] < 8)
					break;
				aacMode1 = info.buffer_data[i + 5];
				aacMode2 = info.buffer_data[i + 6];
#ifdef HAVE_LIBAV
				aacBitrate3 = info.buffer_data[i + 7];
				aacBitrate4 = info.buffer_data[i + 8];
				aacBitrate5 = info.buffer_data[i + 9];
#endif
				break;
			default:
				break;
			}
		}
		/* jump to next information element */
		i += 2 + info.buffer_data[i + 1];
	}
	if (i != info.buffer_len || !transport)
		return (-EPROTO);
	aacMode1 &= cfg->aacMode1;
	aacMode2 &= cfg->aacMode2;

	/* Try AAC first */
	if (aacMode1 == cfg->aacMode1 && aacMode2 == cfg->aacMode2) {
#ifdef HAVE_LIBAV
		uint8_t config[12] = { mediaTransport, 0x0, mediaCodec,
			0x8, 0x0, 0x02, 0x80, aacMode1, aacMode2, aacBitrate3,
			aacBitrate4, aacBitrate5
		};

		if (avdtpSetConfiguration
		    (cfg->hc, cfg->sep, config, sizeof(config)) == 0) {
			cfg->codec = CODEC_AAC;
			return (0);
		}
#endif
	}
	/* Try SBC second */
	if (!sbc || cfg->freq > FREQ_48K || cfg->chmode > MODE_JOINT ||
	    cfg->bands > BANDS_8 || cfg->allocm > ALLOC_SNR ||
	    supBitpoolMin < MIN_BITPOOL || supBitpoolMax > DEFAULT_MAXBPOOL ||
	    supBitpoolMin > supBitpoolMax)
		goto auto_config_failed;

	freqmode = (1 << (3 - cfg->freq + 4)) | (1 << (3 - cfg->chmode));

	if ((availFreqMode & freqmode) != freqmode) {
		DPRINTF("No frequency and mode match\n");
		goto auto_config_failed;
	}
	for (i = 0; i != 4; i++) {
		blk_len_sb_alloc = (1 << (i + 4)) |
		    (1 << (1 - cfg->bands + 2)) | (1 << cfg->allocm);

		if ((availConfig & blk_len_sb_alloc) == blk_len_sb_alloc)
			break;
	}
	if (i == 4) {
		DPRINTF("No bands available\n");
		goto auto_config_failed;
	}
	cfg->blocks = (3 - i);

	/* The peer advertises an absolute bitpool range, not a stereo ratio. */
	unsigned limit = (cfg->bands == BANDS_8 ? 8 : 4) *
	    (cfg->chmode == MODE_MONO || cfg->chmode == MODE_DUAL ? 16 : 32);
	if (supBitpoolMax > limit)
		supBitpoolMax = limit;
	if (supBitpoolMin > supBitpoolMax)
		goto auto_config_failed;
	if (cfg->bitpool > supBitpoolMax)
		cfg->bitpool = supBitpoolMax;
	if (cfg->bitpool < supBitpoolMin)
		cfg->bitpool = supBitpoolMin;

	do {
		uint8_t config[10] = { mediaTransport, 0x0, mediaCodec, 0x6,
			0x0, 0x0, freqmode, blk_len_sb_alloc, supBitpoolMin,
			supBitpoolMax
		};

		if (avdtpSetConfiguration
		    (cfg->hc, cfg->sep, config, sizeof(config)) == 0) {
			cfg->codec = CODEC_SBC;
			return (0);
		}
	} while (0);

auto_config_failed:
	if (cfg->chmode == MODE_STEREO) {
		cfg->chmode = MODE_JOINT;
	} else if (cfg->chmode == MODE_JOINT) {
		cfg->chmode = MODE_MONO;
		cfg->aacMode2 ^= 0x0C;
	} else {
		return (-EINVAL);
	}
	transport = sbc = false;
	goto retry;
}

void
avdtpACPFree(struct bt_config *cfg)
{
	if (cfg->handle.sbc_enc) {
		free(cfg->handle.sbc_enc);
		cfg->handle.sbc_enc = NULL;
	}
}

/* Returns 0 on success, < 0 on failure. */
static int
avdtpParseSBCConfig(uint8_t * data, struct bt_config *cfg)
{
	unsigned fields[] = {data[0] >> 4, data[0] & 15,
	    data[1] >> 4, (data[1] >> 2) & 3, data[1] & 3};
	unsigned maxpool;

	/* A configuration selects exactly one value from every capability set. */
	for (unsigned i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
		if (fields[i] == 0 || (fields[i] & (fields[i] - 1)) != 0)
			return (-EINVAL);
	maxpool = (data[0] & 0x0c ? 16 : 32) * (data[1] & 4 ? 8 : 4);
	if (data[2] < 2 || data[3] > 250 || data[2] > data[3] ||
	    data[3] > maxpool)
		return (-EINVAL);
	if (data[0] & (1 << (7 - FREQ_48K))) {
		cfg->freq = FREQ_48K;
	} else if (data[0] & (1 << (7 - FREQ_44_1K))) {
		cfg->freq = FREQ_44_1K;
	} else if (data[0] & (1 << (7 - FREQ_32K))) {
		cfg->freq = FREQ_32K;
	} else if (data[0] & (1 << (7 - FREQ_16K))) {
		cfg->freq = FREQ_16K;
	} else {
		return -EINVAL;
	}

	if (data[0] & (1 << (3 - MODE_STEREO))) {
		cfg->chmode = MODE_STEREO;
	} else if (data[0] & (1 << (3 - MODE_JOINT))) {
		cfg->chmode = MODE_JOINT;
	} else if (data[0] & (1 << (3 - MODE_DUAL))) {
		cfg->chmode = MODE_DUAL;
	} else if (data[0] & (1 << (3 - MODE_MONO))) {
		cfg->chmode = MODE_MONO;
	} else {
		return -EINVAL;
	}

	if (data[1] & (1 << (7 - BLOCKS_16))) {
		cfg->blocks = BLOCKS_16;
	} else if (data[1] & (1 << (7 - BLOCKS_12))) {
		cfg->blocks = BLOCKS_12;
	} else if (data[1] & (1 << (7 - BLOCKS_8))) {
		cfg->blocks = BLOCKS_8;
	} else if (data[1] & (1 << (7 - BLOCKS_4))) {
		cfg->blocks = BLOCKS_4;
	} else {
		return -EINVAL;
	}

	if (data[1] & (1 << (3 - BANDS_8))) {
		cfg->bands = BANDS_8;
	} else if (data[1] & (1 << (3 - BANDS_4))) {
		cfg->bands = BANDS_4;
	} else {
		return -EINVAL;
	}

	if (data[1] & (1 << ALLOC_LOUDNESS)) {
		cfg->allocm = ALLOC_LOUDNESS;
	} else if (data[1] & (1 << ALLOC_SNR)) {
		cfg->allocm = ALLOC_SNR;
	} else {
		return -EINVAL;
	}
	cfg->bitpool = data[3];
	return 0;
}

int
avdtpACPHandlePacket(struct bt_config *cfg)
{
	struct avdtpGetPacketInfo info;
	struct bt_config pending;
	uint8_t error = BAD_STATE;
	int retval;

	if (avdtpGetPacket(cfg->hc, &info) != COMMAND)
		return (-ENXIO);
	if (info.signalID < AVDTP_DISCOVER || info.signalID > AVDTP_SECUURITY_CONTROL) {
		(void)avdtpSendPacket(cfg->hc, info.signalID, info.trans,
		    1 /* General Reject */, NULL, 0, NULL, 0);
		return (-ENXIO);
	}
	/* Validate the complete command before reading fields or changing state. */
	error = BAD_LENGTH;
	if (info.signalID == AVDTP_DISCOVER) {
		if (info.buffer_len != 0)
			goto err;
	} else if (info.signalID == AVDTP_SET_CONFIGURATION) {
		if (info.buffer_len < 2)
			goto err;
		error = BAD_ACP_SEID;
		if (info.buffer_data[0] != (ACPSEP << 2) ||
		    (info.buffer_data[1] & 3) != 0 ||
		    (info.buffer_data[1] >> 2) == 0 ||
		    (info.buffer_data[1] >> 2) > 62)
			goto err;
	} else {
		if (info.buffer_len != 1)
			goto err;
		error = BAD_ACP_SEID;
		if (info.buffer_data[0] != (ACPSEP << 2))
			goto err;
	}
	error = BAD_STATE;

	switch (info.signalID) {
	case AVDTP_DISCOVER: {
		uint8_t endpoint[2] = {ACPSEP << 2, 1 << 3};
		if (cfg->acceptor_state != acpInitial)
			endpoint[0] |= DISCOVER_SEP_IN_USE;
		retval = avdtpSendPacket(cfg->hc, AVDTP_DISCOVER, info.trans,
		    RESPONSEACCEPT, endpoint, sizeof(endpoint), NULL, 0);
		if (!retval)
			retval = AVDTP_DISCOVER;
		break;
	}
	case AVDTP_GET_CAPABILITIES:
		retval =
		    avdtpSendCapabilitiesResponseSBCForACP(cfg->hc, info.trans);
		if (!retval)
			retval = AVDTP_GET_CAPABILITIES;
		break;
	case AVDTP_SET_CONFIGURATION: {
		bool transport = false, codec = false, allocated = false;
		int i;

		if (cfg->acceptor_state != acpInitial)
			goto err;
		error = UNSUPPORTED_CONFIGURATION;
		pending = *cfg;
		pending.sep = info.buffer_data[1] >> 2;
		for (i = 2; (i + 1) < info.buffer_len;) {
			if (i + 2 + info.buffer_data[i + 1] > info.buffer_len)
				goto err;
			switch (info.buffer_data[i]) {
			case mediaTransport:
				if (transport || info.buffer_data[i + 1] != 0)
					goto err;
				transport = true;
				break;
			case mediaCodec:
				if (codec || info.buffer_data[i + 1] != 6 ||
				    info.buffer_data[i + 2] != 0 ||
				    info.buffer_data[i + 3] != 0 ||
				    avdtpParseSBCConfig(info.buffer_data + i + 4,
				    &pending) != 0)
					goto err;
				memcpy(pending.acceptor_sbc, info.buffer_data + i + 4,
				    sizeof(pending.acceptor_sbc));
				codec = true;
				break;
			default:
				goto err;
			}
			/* jump to next information element */
			i += 2 + info.buffer_data[i + 1];
		}
		if (i != info.buffer_len || !transport || !codec)
			goto err;
		if (pending.handle.sbc_enc == NULL) {
			pending.handle.sbc_enc = calloc(1, sizeof(*pending.handle.sbc_enc));
			if (pending.handle.sbc_enc == NULL)
				goto err;
			allocated = true;
		}

		retval =
		    avdtpSendAccept(cfg->hc, info.trans, AVDTP_SET_CONFIGURATION);
		if (retval) {
			if (allocated)
				free(pending.handle.sbc_enc);
			return (retval);
		}
		*cfg = pending;
		memset(cfg->handle.sbc_enc, 0, sizeof(*cfg->handle.sbc_enc));

		retval = AVDTP_SET_CONFIGURATION;
		cfg->acceptor_state = acpConfigurationSet;
		break;
	}
	case AVDTP_OPEN:
		if (cfg->acceptor_state != acpConfigurationSet)
			goto err;
		retval = avdtpSendAccept(cfg->hc, info.trans, info.signalID);
		if (retval)
			return (retval);
		retval = info.signalID;
		cfg->acceptor_state = acpStreamOpened;
		break;
	case AVDTP_START:
		if (cfg->acceptor_state != acpStreamOpened &&
		    cfg->acceptor_state != acpStreamSuspended) {
			goto err;
		}
		retval = avdtpSendAccept(cfg->hc, info.trans, info.signalID);
		if (retval)
			return retval;
		retval = info.signalID;
		cfg->acceptor_state = acpStreamStarted;
		break;
	case AVDTP_CLOSE:
		if (cfg->acceptor_state != acpStreamOpened &&
		    cfg->acceptor_state != acpStreamStarted &&
		    cfg->acceptor_state != acpStreamSuspended) {
			goto err;
		}
		retval = avdtpSendAccept(cfg->hc, info.trans, info.signalID);
		if (retval)
			return (retval);
		retval = info.signalID;
		cfg->acceptor_state = acpStreamClosed;
		break;
	case AVDTP_SUSPEND:
		if (cfg->acceptor_state != acpStreamStarted) {
			goto err;
		}
		retval = avdtpSendAccept(cfg->hc, info.trans, info.signalID);
		if (retval)
			return (retval);
		retval = info.signalID;
		cfg->acceptor_state = acpStreamSuspended;
		break;
	case AVDTP_ABORT:
		retval = avdtpSendAccept(cfg->hc, info.trans, info.signalID);
		if (retval)
			return (retval);
		cfg->acceptor_state = acpInitial;
		cfg->sep = 0;
		memset(cfg->acceptor_sbc, 0, sizeof(cfg->acceptor_sbc));
		if (cfg->handle.sbc_enc != NULL)
			memset(cfg->handle.sbc_enc, 0, sizeof(*cfg->handle.sbc_enc));
		return (AVDTP_ABORT);
	case AVDTP_GET_CONFIGURATION: {
		uint8_t configuration[] = {mediaTransport, 0, mediaCodec, 6,
		    0, CODEC_SBC, 0, 0, 0, 0};

		if (cfg->acceptor_state != acpConfigurationSet &&
		    cfg->acceptor_state != acpStreamOpened &&
		    cfg->acceptor_state != acpStreamStarted &&
		    cfg->acceptor_state != acpStreamSuspended)
			goto err;
		memcpy(configuration + 6, cfg->acceptor_sbc,
		    sizeof(cfg->acceptor_sbc));
		retval = avdtpSendPacket(cfg->hc, info.signalID, info.trans,
		    RESPONSEACCEPT, configuration, sizeof(configuration), NULL, 0);
		return (retval != 0 ? retval : AVDTP_GET_CONFIGURATION);
	}
	case AVDTP_RECONFIGURE:
		/* TODO: Implement this. */
		error = NOT_SUPPORTED_COMMAND;
	default:
		goto err;
	}
	return (retval);
err: {
		uint8_t body[2] = {0, error};
		int len = 1;
		if (info.signalID == AVDTP_START || info.signalID == AVDTP_SUSPEND) {
			body[0] = info.buffer_len != 0 ? info.buffer_data[0] : 0;
			len = 2;
		} else if (info.signalID == AVDTP_SET_CONFIGURATION ||
		    info.signalID == AVDTP_RECONFIGURE) {
			body[0] = error == UNSUPPORTED_CONFIGURATION ? mediaCodec : 0;
			len = 2;
		}
		(void)avdtpSendPacket(cfg->hc, info.signalID, info.trans,
		    RESPONSEREJECT, body + 2 - len, len, NULL, 0);
		return (-ENXIO);
	}
}
