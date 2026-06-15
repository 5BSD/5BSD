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

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
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
	sa.l2cap_cid = NG_L2CAP_ATT_CID;
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return (-1);
	}

	/* BLE supervision timeout is max 32s; use 30s for ATT requests */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	ac->fd = fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		close(fd);
		ac->fd = -1;
		return (-1);
	}

	DBG("ATT connect to %02x:%02x:%02x:%02x:%02x:%02x type=%d",
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

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = NG_L2CAP_ATT_CID;
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return (-1);
	}

	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	ac->fd = fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		close(fd);
		ac->fd = -1;
		return (-1);
	}

	DBG("ATT connect via pool fd=%d", fd);

	return (0);
}

void
att_close(struct att_conn *ac)
{
	if (ac->fd >= 0) {
		close(ac->fd);
		ac->fd = -1;
	}
	free(ac->buf);
	ac->buf = NULL;
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

	n = send(ac->fd, req, reqlen, 0);
	if (n < 0)
		return (-1);

	n = recv(ac->fd, rsp, rsplen, 0);
	if (n < 0)
		return (-1);

	if (n == 0) {
		warnx("ATT: connection closed by peer");
		errno = ECONNRESET;
		return (-1);
	}

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
	uint8_t req[3], rsp[3];
	ssize_t n;

	if (client_mtu < ATT_DEFAULT_MTU)
		client_mtu = ATT_DEFAULT_MTU;

	req[0] = ATT_OP_MTU_REQ;
	put_le16(req + 1, client_mtu);

	n = att_request(ac, req, sizeof(req), rsp, sizeof(rsp), NULL);
	if (n < 0)
		return (-1);

	if (n < 3 || rsp[0] != ATT_OP_MTU_RSP) {
		warnx("ATT: bad MTU response opcode=%02x", rsp[0]);
		errno = EPROTO;
		return (-1);
	}

	uint16_t server_mtu = get_le16(rsp + 1);
	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;
	if (ac->mtu > ATT_MAX_MTU)
		ac->mtu = ATT_MAX_MTU;

	DBG("MTU exchange: client=%d server=%d effective=%d",
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

	DBG("ATT read handle=%04x len=%zu", handle, datalen);

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

	DBG("ATT read blob handle=%04x offset=%d len=%zu", handle, offset,
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
	uint8_t req[ATT_MAX_MTU];
	struct att_error ae;
	ssize_t n;
	size_t reqlen = 3 + len;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EMSGSIZE;
		return (-1);
	}

	req[0] = ATT_OP_WRITE_REQ;
	put_le16(req + 1, handle);
	memcpy(req + 3, data, len);

	n = att_request(ac, req, reqlen, ac->buf, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (ac->buf[0] != ATT_OP_WRITE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	DBG("ATT write req handle=%04x len=%zu", handle, len);

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

	if (send(ac->fd, pdu, pdulen, 0) < 0)
		return (-1);

	DBG("ATT write cmd handle=%04x len=%zu", handle, len);

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

	n = recv(ac->fd, buf, buflen, 0);
	if (n < 0)
		return (-1);
	if (n == 0) {
		errno = ECONNRESET;
		return (-1);
	}

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

	if (send(ac->fd, &pdu, 1, 0) < 0)
		return (-1);

	return (0);
}
