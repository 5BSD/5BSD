/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT (Attribute Protocol) client implementation.
 *
 * Operates over a connected L2CAP socket on CID 0x0004 (ATT fixed channel).
 * All PDU formats per Core Spec v6.0 Vol 3 Part F.
 */

#include <sys/types.h>
#include <sys/socket.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"

/*
 * Open an ATT connection to a BLE device.
 */
int
att_open(struct att_conn *ac, const uint8_t *addr, uint8_t addr_type)
{
	struct sockaddr_l2cap sa;
	int fd;

	memset(ac, 0, sizeof(*ac));
	ac->fd = -1;
	ac->bearer_fd = -1;
	ac->eatt_count = 0;
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		return (-1);

	/* Bind to local adapter (BDADDR_ANY) */
	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	/* l2cap_bdaddr = all zeros for any adapter */

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return (-1);
	}

	/* Connect to remote BLE device on ATT CID */
	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = htole16(NG_L2CAP_ATT_CID);
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return (-1);
	}

	/* BLE supervision timeout is max 32s; use 30s for ATT requests */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
	}

	ac->fd = fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		close(fd);
		ac->fd = -1;
		return (-1);
	}

	LOG_ATT(1, "connect to %02x:%02x:%02x:%02x:%02x:%02x type=%d",
	    addr[5], addr[4], addr[3], addr[2], addr[1], addr[0], addr_type);

	return (0);
}

/*
 * Open ATT using a pre-created, pre-bound socket fd.
 * For use inside Capsicum capability mode with cap_connect().
 */
int
att_open_fd(struct att_conn *ac, int fd, const uint8_t *addr,
    uint8_t addr_type)
{
	struct sockaddr_l2cap sa;

	memset(ac, 0, sizeof(*ac));
	ac->fd = -1;
	ac->bearer_fd = -1;
	ac->eatt_count = 0;
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = htole16(NG_L2CAP_ATT_CID);
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return (-1);

	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
	}

	ac->fd = fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		ac->fd = -1;
		return (-1);
	}

	LOG_ATT(1, "connect via pool fd=%d", fd);

	return (0);
}

void
att_close(struct att_conn *ac)
{
	att_close_eatt(ac);
	if (ac->fd >= 0) {
		close(ac->fd);
		ac->fd = -1;
	}
	free(ac->buf);
	ac->buf = NULL;
	ac->prep_queue.count = 0;
}

/*
 * Send a PDU and wait for a response.
 * Returns bytes received, or -1 on error.
 * Sets errno to EPROTO and fills *ae on ATT error response.
 */
static ssize_t
att_request(struct att_conn *ac, const void *req, size_t reqlen,
    void *rsp, size_t rsplen, struct att_error *ae)
{
	ssize_t n;
	int max_skip = 16;
	int fd;
	uint8_t opcode;

	/*
	 * Select the best available bearer.  Prefer EATT bearers when
	 * available — they allow ATT multiplexing (Core Spec Vol 3
	 * Part G §5.3).  Fall back to the primary bearer on CID 0x0004.
	 */
	if (ac->eatt_count > 0) {
		fd = att_eatt_select_bearer(ac);
		if (fd < 0)
			fd = ac->fd;
	} else {
		fd = ac->fd;
	}

	n = send(fd, req, reqlen, MSG_EOR);
	if (n < 0)
		return (-1);

	BLUED_PROBE_ATT_SEND(((const uint8_t *)req)[0], (int)reqlen);

	/* Log outgoing ATT PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    req, reqlen, false);

	/*
	 * Loop until we get the actual response.  Per Core Spec Vol 3
	 * Part F 3.4.7, Handle Value Notifications can arrive at any
	 * time, including between a request and its response.  Discard
	 * notifications and send confirmations for indications.
	 *
	 * Limit iterations to prevent a malicious peer from keeping us
	 * spinning indefinitely by sending unsolicited PDUs (the
	 * SO_RCVTIMEO resets on each recv).
	 */
	for (;;) {
		do {
			n = recv(fd, rsp, rsplen, 0);
		} while (n < 0 && errno == EINTR);
		if (n < 0)
			return (-1);

		if (n == 0) {
			warnx("ATT: connection closed by peer");
			errno = ECONNRESET;
			return (-1);
		}

		opcode = ((uint8_t *)rsp)[0];

		/* Skip notifications -- they are unsolicited */
		if (opcode == ATT_OP_HANDLE_NOTIFY ||
		    opcode == ATT_OP_MULTIPLE_HANDLE_VALUE_NTF) {
			if (--max_skip <= 0) {
				warnx("ATT: too many unsolicited PDUs while waiting for response");
				errno = EPROTO;
				return (-1);
			}
			continue;
		}

		/* Confirm and skip indications */
		if (opcode == ATT_OP_HANDLE_IND) {
			uint8_t cfm = ATT_OP_HANDLE_CFM;
			(void)send(fd, &cfm, 1, MSG_EOR);
			if (--max_skip <= 0) {
				warnx("ATT: too many unsolicited PDUs while waiting for response");
				errno = EPROTO;
				return (-1);
			}
			continue;
		}

		break;
	}

	/* Decrement EATT bearer pending count after response */
	if (fd != ac->fd) {
		int bi;
		for (bi = 0; bi < ac->eatt_count; bi++) {
			if (ac->eatt[bi].fd == fd && ac->eatt[bi].pending > 0) {
				ac->eatt[bi].pending--;
				break;
			}
		}
	}

	/* Log incoming ATT PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    rsp, (uint16_t)n, true);

	/* Check for error response */
	if (((uint8_t *)rsp)[0] == ATT_OP_ERROR_RSP && n >= 5) {
		if (ae != NULL) {
			ae->req_opcode = ((uint8_t *)rsp)[1];
			ae->handle = get_le16((uint8_t *)rsp + 2);
			ae->code = ((uint8_t *)rsp)[4];
		}
		warnx("ATT error: req=%02x handle=%04x code=%02x",
		    ((uint8_t *)rsp)[1], get_le16((uint8_t *)rsp + 2),
		    ((uint8_t *)rsp)[4]);
		errno = EPROTO;
		return (-1);
	}

	return (n);
}

/*
 * ATT Exchange MTU (Core Spec Vol 3 Part F 3.4.2)
 *
 * Client sends desired MTU, server responds with its MTU.
 * Effective MTU = min(client, server).
 */
int
att_exchange_mtu(struct att_conn *ac, uint16_t client_mtu)
{
	uint8_t req[3], rsp[5]; /* 5 bytes to hold ATT_ERROR_RSP */
	struct att_error ae;
	ssize_t n;
	uint16_t server_mtu;

	if (client_mtu < ATT_DEFAULT_MTU)
		client_mtu = ATT_DEFAULT_MTU;

	req[0] = ATT_OP_MTU_REQ;
	put_le16(req + 1, client_mtu);

	n = att_request(ac, req, sizeof(req), rsp, sizeof(rsp), &ae);
	if (n < 0)
		return (-1);

	if (n < 3 || rsp[0] != ATT_OP_MTU_RSP) {
		warnx("ATT: bad MTU response opcode=%02x len=%zd", rsp[0], n);
		errno = EPROTO;
		return (-1);
	}

	server_mtu = get_le16(rsp + 1);
	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;
	if (ac->mtu > ATT_MAX_MTU)
		ac->mtu = ATT_MAX_MTU;

	LOG_ATT(1, "MTU exchange: client=%d server=%d effective=%d",
	    client_mtu, server_mtu, ac->mtu);

	return (0);
}

/*
 * ATT Read Request (Core Spec Vol 3 Part F 3.4.4.3)
 */
int
att_read(struct att_conn *ac, uint16_t handle,
    void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[3];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_READ_REQ;
	put_le16(req + 1, handle);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_READ_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	LOG_ATT(2, "read handle=%04x len=%zu", handle, datalen);

	return (0);
}

/*
 * ATT Read Blob Request (Core Spec Vol 3 Part F 3.4.4.5)
 */
int
att_read_blob(struct att_conn *ac, uint16_t handle, uint16_t offset,
    void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[5];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_READ_BLOB_REQ;
	put_le16(req + 1, handle);
	put_le16(req + 3, offset);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_READ_BLOB_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	LOG_ATT(2, "read blob handle=%04x offset=%d len=%zu", handle, offset,
	    datalen);

	return (0);
}

/*
 * ATT Write Request (Core Spec Vol 3 Part F 3.4.5.1)
 * Waits for Write Response.
 */
int
att_write_req(struct att_conn *ac, uint16_t handle,
    const void *data, size_t len)
{
	uint8_t reqbuf[ATT_PDU_BUF_SIZE];
	struct att_error ae;
	ssize_t n;
	size_t reqlen = 3 + len;

	if (reqlen > ac->mtu || reqlen > sizeof(reqbuf)) {
		errno = EMSGSIZE;
		return (-1);
	}

	/*
	 * Build request in a separate buffer so att_request's recv()
	 * into ac->buf doesn't alias the request data.
	 */
	reqbuf[0] = ATT_OP_WRITE_REQ;
	put_le16(reqbuf + 1, handle);
	memcpy(reqbuf + 3, data, len);

	n = att_request(ac, reqbuf, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_WRITE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	LOG_ATT(2, "write req handle=%04x len=%zu", handle, len);

	return (0);
}

/*
 * ATT Write Command (Core Spec Vol 3 Part F 3.4.5.3)
 * No response expected.
 */
int
att_write_cmd(struct att_conn *ac, uint16_t handle,
    const void *data, size_t len)
{
	uint8_t *pdu;
	size_t pdulen = 3 + len;

	if (pdulen > ac->mtu) {
		errno = EMSGSIZE;
		return (-1);
	}

	pdu = ac->buf;
	pdu[0] = ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, data, len);

	if (send(ac->fd, pdu, pdulen, MSG_EOR) < 0)
		return (-1);

	BLUED_PROBE_ATT_SEND(pdu[0], (int)pdulen);

	/* Log outgoing ATT Write Command PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    pdu, pdulen, false);

	LOG_ATT(2, "write cmd handle=%04x len=%zu", handle, len);

	return (0);
}

/*
 * ATT Find By Type Value Request (Core Spec Vol 3 Part F 3.4.3.3)
 * Used to find attributes of a given type with a specific value.
 * Returns raw response payload (after opcode): list of
 * [found_handle(2) + group_end_handle(2)] pairs.
 */
int
att_find_by_type_value(struct att_conn *ac, uint16_t start, uint16_t end,
    uint16_t uuid16, const void *value, size_t vlen,
    void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[ATT_PDU_BUF_SIZE];
	struct att_error ae;
	ssize_t n;
	size_t reqlen = 7 + vlen;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EMSGSIZE;
		return (-1);
	}

	req[0] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);
	put_le16(req + 5, uuid16);
	memcpy(req + 7, value, vlen);

	n = att_request(ac, req, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (ac->buf[0] != ATT_OP_FIND_BY_TYPE_VALUE_RSP || n < 5) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * ATT Read Multiple Request (Core Spec Vol 3 Part F 3.4.4.7)
 * Reads multiple attribute values in a single request.
 * Concatenated values are returned; caller must know expected sizes.
 */
int
att_read_multiple(struct att_conn *ac, const uint16_t *handles, int count,
    void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[ATT_PDU_BUF_SIZE];
	struct att_error ae;
	ssize_t n;
	size_t reqlen;

	/* Guard against integer overflow in count * 2 */
	if (count < 2 || count > (int)((sizeof(req) - 1) / 2)) {
		errno = EINVAL;
		return (-1);
	}
	reqlen = 1 + (size_t)count * 2;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EINVAL;
		return (-1);
	}

	req[0] = ATT_OP_READ_MULTIPLE_REQ;
	for (int i = 0; i < count; i++)
		put_le16(req + 1 + i * 2, handles[i]);

	n = att_request(ac, req, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_READ_MULTIPLE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	LOG_ATT(2, "read multiple count=%d len=%zu", count, datalen);

	return (0);
}

/*
 * ATT Read Multiple Variable Length Request (Core Spec Vol 3 Part F 3.4.4.8)
 * Reads multiple attribute values with per-value length prefixes.
 * Response format: opcode(1) || {length(2) || value(length)}*
 *
 * BT 5.2+. Requires EATT or the unenhanced bearer.
 */
int
att_read_multiple_variable(struct att_conn *ac, const uint16_t *handles,
    int count, void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[ATT_PDU_BUF_SIZE];
	struct att_error ae;
	ssize_t n;
	size_t reqlen;

	if (count < 2 || count > (int)((sizeof(req) - 1) / 2)) {
		errno = EINVAL;
		return (-1);
	}
	reqlen = 1 + (size_t)count * 2;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EINVAL;
		return (-1);
	}

	req[0] = ATT_OP_READ_MULTIPLE_VARIABLE_REQ;
	for (int i = 0; i < count; i++)
		put_le16(req + 1 + i * 2, handles[i]);

	n = att_request(ac, req, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_READ_MULTIPLE_VARIABLE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	LOG_ATT(2, "read multiple variable count=%d len=%zu", count, datalen);

	return (0);
}

/*
 * ATT Prepare Write Request (Core Spec Vol 3 Part F 3.4.6.1)
 * Queues a partial write on the server.
 */
int
att_prepare_write(struct att_conn *ac, uint16_t handle, uint16_t offset,
    const void *data, size_t len)
{
	uint8_t req[ATT_PDU_BUF_SIZE];
	struct att_error ae;
	ssize_t n;
	size_t reqlen = 5 + len;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EMSGSIZE;
		return (-1);
	}

	req[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(req + 1, handle);
	put_le16(req + 3, offset);
	memcpy(req + 5, data, len);

	n = att_request(ac, req, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_PREPARE_WRITE_RSP || n < 5) {
		errno = EPROTO;
		return (-1);
	}

	/* Verify the server echoed back the same handle and offset */
	if (get_le16(ac->buf + 1) != handle ||
	    get_le16(ac->buf + 3) != offset) {
		warnx("ATT: prepare write echo mismatch");
		errno = EPROTO;
		return (-1);
	}

	LOG_ATT(2, "prepare write handle=%04x offset=%d len=%zu",
	    handle, offset, len);

	return (0);
}

/*
 * ATT Execute Write Request (Core Spec Vol 3 Part F 3.4.6.3)
 * flags: 0x00 = cancel all prepared writes, 0x01 = write all.
 */
int
att_execute_write(struct att_conn *ac, uint8_t flags)
{
	uint8_t req[2];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_EXECUTE_WRITE_REQ;
	req[1] = flags;

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_EXECUTE_WRITE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	LOG_ATT(2, "execute write flags=%02x", flags);

	return (0);
}

/*
 * ATT Write Long (convenience — Core Spec Vol 3 Part F 3.4.6)
 * Breaks data into MTU-5 chunks using Prepare Write, then executes.
 * On error during any Prepare, cancels with Execute Write flags=0x00.
 */
int
att_write_long(struct att_conn *ac, uint16_t handle,
    const void *data, size_t len)
{
	size_t chunkmax, off;
	int rc;

	/*
	 * Prepare Write offset is a 16-bit field (Core Spec Vol 3
	 * Part F §3.4.6.1), so the maximum attribute value length
	 * addressable is 0xFFFF + chunk.  Reject oversized writes
	 * to prevent offset truncation.
	 */
	if (len > UINT16_MAX) {
		errno = EINVAL;
		return (-1);
	}

	chunkmax = ac->mtu - 5;
	off = 0;

	while (off < len) {
		size_t chunk = len - off;
		if (chunk > chunkmax)
			chunk = chunkmax;

		rc = att_prepare_write(ac, handle, (uint16_t)off,
		    (const uint8_t *)data + off, chunk);
		if (rc != 0) {
			/* Cancel any queued writes */
			(void)att_execute_write(ac, 0x00);
			return (rc);
		}
		off += chunk;
	}

	rc = att_execute_write(ac, 0x01);
	if (rc != 0)
		return (rc);

	LOG_ATT(2, "write long handle=%04x len=%zu", handle, len);

	return (0);
}

/*
 * ATT Find Information Request (Core Spec Vol 3 Part F 3.4.3.1)
 * Used for descriptor discovery.
 * Returns raw response payload (after opcode).
 */
int
att_find_info(struct att_conn *ac, uint16_t start, uint16_t end,
    void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[5];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_FIND_INFO_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (ac->buf[0] != ATT_OP_FIND_INFO_RSP || n < 2) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * ATT Read By Type Request (Core Spec Vol 3 Part F 3.4.4.1)
 * Used for characteristic discovery within a service handle range.
 * Returns raw response payload (after opcode).
 */
int
att_read_by_type(struct att_conn *ac, uint16_t start, uint16_t end,
    uint16_t uuid16, void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[7];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);
	put_le16(req + 5, uuid16);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (ac->buf[0] != ATT_OP_READ_BY_TYPE_RSP || n < 2) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * ATT Read By Type Request with 128-bit UUID (Core Spec Vol 3 Part F 3.4.4.1)
 * Builds a 23-byte PDU: opcode(1) + start(2) + end(2) + uuid128(16).
 * Used for discovering characteristics with vendor-specific UUIDs.
 */
int
att_read_by_type_uuid128(struct att_conn *ac, uint16_t start, uint16_t end,
    const uint8_t uuid[16], void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[21];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_READ_BY_TYPE_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);
	memcpy(req + 5, uuid, 16);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (ac->buf[0] != ATT_OP_READ_BY_TYPE_RSP || n < 2) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * ATT Read By Group Type Request (Core Spec Vol 3 Part F 3.4.4.9)
 * Used for primary service discovery.
 * Returns raw response payload (after opcode).
 */
int
att_read_by_group_type(struct att_conn *ac, uint16_t start, uint16_t end,
    uint16_t uuid16, void *buf, size_t buflen, size_t *outlen)
{
	uint8_t req[7];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_READ_BY_GROUP_TYPE_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);
	put_le16(req + 5, uuid16);

	n = att_request(ac, req, sizeof(req), ac->buf, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (ac->buf[0] != ATT_OP_READ_BY_GROUP_TYPE_RSP || n < 2) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, ac->buf + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * Receive an unsolicited PDU (notification or indication).
 * Caller should use poll(2)/select(2) on ac->fd to know when data is ready.
 */
int
att_recv(struct att_conn *ac, void *buf, size_t buflen, size_t *outlen)
{
	ssize_t n;

	do {
		n = recv(ac->fd, buf, buflen, 0);
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return (-1);
	if (n == 0) {
		errno = ECONNRESET;
		return (-1);
	}

	/* Log incoming unsolicited ATT PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    buf, (uint16_t)n, true);

	BLUED_PROBE_ATT_RECV(((uint8_t *)buf)[0], (int)n);

	if (outlen != NULL)
		*outlen = (size_t)n;

	return (0);
}

/*
 * Send Handle Value Confirmation (for indications).
 * Core Spec Vol 3 Part F 3.4.7.3
 */
int
att_confirm(struct att_conn *ac)
{
	uint8_t pdu = ATT_OP_HANDLE_CFM;

	if (send(ac->fd, &pdu, 1, MSG_EOR) < 0)
		return (-1);

	/* Log outgoing Handle Value Confirmation */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004, &pdu, 1, false);

	return (0);
}

/*
 * Open EATT bearers on an existing ATT connection.
 * Establishes LE CoC channels on PSM 0x0027 (ATT_EATT_PSM).
 * Returns number of bearers successfully opened.
 *
 * Each connected CoC socket becomes an additional ATT bearer
 * capable of carrying GATT operations in parallel with the
 * primary bearer on CID 0x0004.
 */
int
att_open_eatt(struct att_conn *ac, const uint8_t *addr, uint8_t addr_type,
    int count)
{
	int i, opened;

	if (count > ATT_MAX_EATT_BEARERS)
		count = ATT_MAX_EATT_BEARERS;

	opened = 0;
	for (i = 0; i < count; i++) {
		int fd;
		uint16_t bearer_mtu;

		fd = ble_coc_connect(addr, addr_type, ATT_EATT_PSM, 0);
		if (fd < 0) {
			LOG_ATT(1, "EATT: bearer %d connect failed: %s",
			    i, strerror(errno));
			break;
		}

		/*
		 * EATT bearer MTU comes from L2CAP CoC connection
		 * parameters, not ATT_EXCHANGE_MTU_REQ which is only
		 * valid on the unenhanced ATT bearer (Core Spec Vol 3
		 * Part G §4.2).
		 */
		{
			socklen_t optlen = sizeof(bearer_mtu);
			if (getsockopt(fd, SOL_L2CAP, SO_L2CAP_OMTU,
			    &bearer_mtu, &optlen) < 0 ||
			    bearer_mtu < ATT_DEFAULT_MTU)
				bearer_mtu = ATT_DEFAULT_MTU;
		}

		ac->eatt[opened].fd = fd;
		ac->eatt[opened].mtu = bearer_mtu;
		ac->eatt[opened].active = true;
		opened++;

		LOG_ATT(1, "EATT: bearer %d connected, fd=%d mtu=%d",
		    i, fd, bearer_mtu);
	}

	ac->eatt_count = opened;
	LOG_ATT(1, "EATT: %d/%d bearers opened", opened, count);

	return (opened);
}

/*
 * Select the best available bearer for a request.
 * EATT enables ATT multiplexing: if any EATT bearer is idle,
 * use it; otherwise fall back to the primary bearer.
 *
 * Returns the fd to use for sending the next ATT PDU.
 */
int
att_eatt_select_bearer(struct att_conn *ac)
{
	int i;

	/*
	 * Least-loaded selection: pick the active EATT bearer with
	 * the fewest outstanding requests.  This distributes parallel
	 * GATT operations across bearers, matching BlueZ's per-channel
	 * queue approach.
	 */
	{
		int best = -1, best_pending = 0x7FFFFFFF;

		for (i = 0; i < ac->eatt_count; i++) {
			if (!ac->eatt[i].active || ac->eatt[i].fd < 0)
				continue;
			if (ac->eatt[i].pending < best_pending) {
				best_pending = ac->eatt[i].pending;
				best = i;
			}
		}
		if (best >= 0) {
			ac->eatt[best].pending++;
			return (ac->eatt[best].fd);
		}
	}

	/* Fall back to primary bearer */
	return (ac->fd);
}

/*
 * Accept an incoming EATT connection on PSM 0x0027.
 * Called by the ATT server when a peer initiates an EATT bearer.
 * listen_fd should be a listening L2CAP SOCK_SEQPACKET socket
 * bound to PSM 0x0027.
 *
 * Returns 0 on success (bearer added), -1 if no room or error.
 */
int
att_eatt_accept(struct att_conn *ac, int listen_fd)
{
	struct sockaddr_l2cap sa;
	socklen_t salen;
	int fd, idx;
	struct timeval tv;

	if (ac->eatt_count >= ATT_MAX_EATT_BEARERS) {
		LOG_ATT(1, "EATT: accept rejected, max bearers reached");
		errno = ENOSPC;
		return (-1);
	}

	salen = sizeof(sa);
	fd = accept4(listen_fd, (struct sockaddr *)&sa, &salen,
	    SOCK_CLOEXEC | SOCK_CLOFORK);
	if (fd < 0) {
		LOG_ATT(1, "EATT: accept() failed: %s", strerror(errno));
		return (-1);
	}

	/* Set receive timeout */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		warn("setsockopt SO_RCVTIMEO");

	idx = ac->eatt_count;
	ac->eatt[idx].fd = fd;
	ac->eatt[idx].active = true;
	ac->eatt_count++;

	/*
	 * EATT bearer MTU comes from L2CAP CoC connection parameters,
	 * not ATT_EXCHANGE_MTU_REQ (Core Spec Vol 3 Part G §5.3.1).
	 */
	{
		uint16_t bearer_mtu;
		socklen_t optlen = sizeof(bearer_mtu);
		if (getsockopt(fd, SOL_L2CAP, SO_L2CAP_OMTU,
		    &bearer_mtu, &optlen) == 0 &&
		    bearer_mtu >= ATT_DEFAULT_MTU)
			ac->eatt[idx].mtu = bearer_mtu;
		else
			ac->eatt[idx].mtu = ATT_DEFAULT_MTU;
	}

	LOG_ATT(1, "EATT: accepted bearer fd=%d (total=%d)",
	    fd, ac->eatt_count);

	return (0);
}

/*
 * Close all EATT bearers on an ATT connection.
 */
void
att_close_eatt(struct att_conn *ac)
{
	int i;

	for (i = 0; i < ac->eatt_count; i++) {
		if (ac->eatt[i].fd >= 0) {
			close(ac->eatt[i].fd);
			ac->eatt[i].fd = -1;
		}
		ac->eatt[i].active = false;
	}
	ac->eatt_count = 0;
}
