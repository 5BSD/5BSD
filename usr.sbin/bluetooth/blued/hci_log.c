/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * HCI packet logger -- writes BTSnoop format for Wireshark.
 *
 * BTSnoop file format:
 *   File header: "btsnoop\0" (8) + version_be32 (4) + datalink_be32 (4)
 *   Each record: orig_len_be32 (4) + incl_len_be32 (4) + flags_be32 (4)
 *                + drops_be32 (4) + timestamp_us_be64 (8) + data
 *
 * Datalink type 1002 = HCI UART (H4) with packet type indicator.
 * Flags: bit 0 = direction (0=sent, 1=received), bit 1 = type
 *        (0=data, 1=command/event).
 */

#include <sys/endian.h>
#include <sys/uio.h>

#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hci_log.h"

static int log_fd = -1;

/* BTSnoop epoch: Jan 1, 0000 AD.  Offset from Unix epoch in microseconds. */
#define BTSNOOP_EPOCH_DELTA	0x00dcddb30f2f8000ULL

static void
put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (v >> 24) & 0xFF;
	p[1] = (v >> 16) & 0xFF;
	p[2] = (v >> 8) & 0xFF;
	p[3] = v & 0xFF;
}

static void
put_be64(uint8_t *p, uint64_t v)
{
	put_be32(p, (uint32_t)(v >> 32));
	put_be32(p + 4, (uint32_t)v);
}

static uint64_t
btsnoop_timestamp(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ((uint64_t)ts.tv_sec * 1000000ULL + ts.tv_nsec / 1000 +
	    BTSNOOP_EPOCH_DELTA);
}

void
hci_log_open(const char *path)
{
	uint8_t hdr[16];

	log_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_CLOFORK,
	    0600);
	if (log_fd < 0) {
		warn("cannot open HCI log file %s", path);
		return;
	}

	/* BTSnoop file header */
	memcpy(hdr, "btsnoop\0", 8);
	put_be32(hdr + 8, 1);		/* version */
	put_be32(hdr + 12, 1002);	/* H4 datalink */
	if (write(log_fd, hdr, sizeof(hdr)) != sizeof(hdr)) {
		close(log_fd);
		log_fd = -1;
	}
}

void
hci_log_close(void)
{
	if (log_fd >= 0) {
		close(log_fd);
		log_fd = -1;
	}
}

bool
hci_log_enabled(void)
{
	return (log_fd >= 0);
}

void
hci_log_packet(uint8_t type, const uint8_t *data, uint16_t len,
    bool incoming)
{
	uint8_t rec[24];
	uint32_t flags;
	uint32_t total;
	struct iovec iov[3];
	ssize_t expected, ret;

	if (log_fd < 0)
		return;

	/*
	 * BTSnoop flags:
	 *   bit 0 = direction: 0=host-to-controller, 1=controller-to-host
	 *   bit 1 = type: 0=data (ACL/SCO), 1=command/event
	 */
	flags = incoming ? 1 : 0;
	if (type == HCI_LOG_CMD || type == HCI_LOG_EVT)
		flags |= 2;

	/* Include the H4 packet type indicator byte */
	total = len + 1;

	put_be32(rec + 0, total);	/* original length */
	put_be32(rec + 4, total);	/* included length */
	put_be32(rec + 8, flags);
	put_be32(rec + 12, 0);		/* drops */
	put_be64(rec + 16, btsnoop_timestamp());

	/* Write header + type byte + payload */
	iov[0].iov_base = rec;
	iov[0].iov_len = sizeof(rec);
	iov[1].iov_base = &type;
	iov[1].iov_len = 1;
	iov[2].iov_base = __DECONST(void *, data);
	iov[2].iov_len = len;
	expected = (ssize_t)(sizeof(rec) + 1 + len);
	ret = writev(log_fd, iov, 3);
	if (ret < expected) {
		warn("BTSnoop log write failed, closing");
		close(log_fd);
		log_fd = -1;
	}
}

/*
 * Log an L2CAP PDU as an HCI ACL packet in BTSnoop format.
 *
 * Wraps the payload with an HCI ACL header and L2CAP basic header
 * so that Wireshark can fully decode the PDU.  Use CID 0x0004 for
 * ATT and CID 0x0006 for SMP.
 */
void
hci_log_l2cap(uint16_t con_handle, uint16_t cid,
    const uint8_t *data, uint16_t len, bool incoming)
{
	uint8_t rec[24];
	uint8_t hdr[8];		/* ACL header(4) + L2CAP header(4) */
	uint8_t type;
	uint32_t flags;
	uint16_t l2cap_len;
	uint32_t total;
	struct iovec iov[4];
	ssize_t expected, ret;

	if (log_fd < 0)
		return;

	if (len > UINT16_MAX - 4)
		return;

	l2cap_len = 4 + len;	/* L2CAP header + payload */

	/* HCI ACL header: handle(2) + total_length(2) */
	hdr[0] = con_handle & 0xFF;
	hdr[1] = ((con_handle >> 8) & 0x0F) | 0x20; /* PB=10 (first auto-flush) */
	hdr[2] = l2cap_len & 0xFF;
	hdr[3] = (l2cap_len >> 8) & 0xFF;

	/* L2CAP basic header: length(2) + CID(2) */
	hdr[4] = len & 0xFF;
	hdr[5] = (len >> 8) & 0xFF;
	hdr[6] = cid & 0xFF;
	hdr[7] = (cid >> 8) & 0xFF;

	type = HCI_LOG_ACL;

	/* BTSnoop flags: bit 0 = direction, bit 1 = 0 for data */
	flags = incoming ? 1 : 0;

	/* total = H4 type(1) + ACL header(4) + L2CAP header(4) + payload */
	total = 1 + 8 + len;

	put_be32(rec + 0, total);
	put_be32(rec + 4, total);
	put_be32(rec + 8, flags);
	put_be32(rec + 12, 0);		/* drops */
	put_be64(rec + 16, btsnoop_timestamp());

	iov[0].iov_base = rec;
	iov[0].iov_len = sizeof(rec);
	iov[1].iov_base = &type;
	iov[1].iov_len = 1;
	iov[2].iov_base = hdr;
	iov[2].iov_len = sizeof(hdr);
	iov[3].iov_base = __DECONST(void *, data);
	iov[3].iov_len = len;
	expected = (ssize_t)(sizeof(rec) + 1 + sizeof(hdr) + len);
	ret = writev(log_fd, iov, 4);
	if (ret < expected) {
		warn("BTSnoop log write failed, closing");
		close(log_fd);
		log_fd = -1;
	}
}
