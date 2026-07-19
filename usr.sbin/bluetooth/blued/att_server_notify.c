/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * ATT server notification/indication sending.
 * Split from att_server.c for readability.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "att.h"
#include "att_server.h"
#include "att_server_internal.h"
#include "ble_util.h"
#include "blued_probes.h"

/*
 * Send an ATT Handle Value Notification.
 *
 * This function intentionally does NOT check the Client Characteristic
 * Configuration Descriptor (CCCD) value.  The caller is responsible for
 * verifying that the client has enabled notifications (CCCD bit 0) before
 * invoking this function.  This separation keeps the ATT transport layer
 * independent of GATT-level subscription state.
 */
int
att_send_notification(struct att_conn *ac, uint16_t handle,
    const void *value, uint16_t len)
{
	if (ac == NULL || (value == NULL && len > 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (ac->mtu < 3) {
		errno = EMSGSIZE;
		return (-1);
	}

	ATT_RSP_BUF_DECL(ac);
	uint16_t pdulen, maxlen;
	int ret;

	if (rsp == NULL)
		return (-1);

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	if (len > maxlen - 3)
		len = maxlen - 3;
	pdulen = 3 + len;
	if (pdulen > ac->mtu)
		pdulen = ac->mtu;
	rsp[0] = ATT_OP_HANDLE_NOTIFY;
	put_le16(rsp + 1, handle);
	if (pdulen > 3)
		memcpy(rsp + 3, value, pdulen - 3);

	ret = att_server_send(ac, rsp, pdulen) == pdulen ? 0 : -1;
	if (ret == 0)
		BLUED_PROBE_ATT_NOTIFY(handle, pdulen);
	ATT_RSP_BUF_FREE();
	return (ret);
}

int
att_send_indication(struct att_conn *ac, uint16_t handle,
    const void *value, uint16_t len)
{
	if (ac == NULL || (value == NULL && len > 0)) {
		errno = EINVAL;
		return (-1);
	}
	if (ac->mtu < 3) {
		errno = EMSGSIZE;
		return (-1);
	}

	ATT_RSP_BUF_DECL(ac);
	uint16_t pdulen, maxlen;
	int ret;

	if (rsp == NULL)
		return (-1);

	/* One indication at a time (Core Spec Vol 3 Part F Section 3.3.2) */
	if (ac->ind_pending) {
		ATT_RSP_BUF_FREE();
		errno = EBUSY;
		return (-1);
	}

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	if (len > maxlen - 3)
		len = maxlen - 3;
	pdulen = 3 + len;
	if (pdulen > ac->mtu)
		pdulen = ac->mtu;
	rsp[0] = ATT_OP_HANDLE_IND;
	put_le16(rsp + 1, handle);
	if (pdulen > 3)
		memcpy(rsp + 3, value, pdulen - 3);

	ret = att_server_send(ac, rsp, pdulen) == pdulen ? 0 : -1;
	ATT_RSP_BUF_FREE();
	if (ret == 0) {
		ac->ind_pending = true;
		ac->ind_handle = handle;	/* for robust-caching Fig 2.6 */
		BLUED_PROBE_ATT_INDICATE(handle, pdulen);
		/*
		 * Core Spec Vol 3 Part F §3.3.3 / §3.4.7.3: after sending a
		 * Handle Value Indication the server must start a 30 s
		 * confirmation timer; if the peer never sends the Handle Value
		 * Confirmation the bearer must be considered failed, otherwise
		 * ind_pending stays set forever and wedges every future
		 * indication (att_send_indication returns EBUSY).  Arming that
		 * timer requires the kqueue owned by the main event loop
		 * (blued_g.kq), which the ATT transport layer here has no
		 * handle to.  The main-loop peripheral GATT server path arms it
		 * via blued_ind_arm_timeout() (blued_event.c); any OTHER caller
		 * of att_send_indication() is responsible for arming an
		 * equivalent confirmation timeout and marking ac->failed / the
		 * ind_timer on expiry.  See ac->ind_timer (att.h), reserved for
		 * this purpose.  DEFERRED: wiring an att-layer timer belongs to
		 * blued_event.c (out of scope for the att*.c files).
		 */
	}
	return (ret);
}

/*
 * Send Multiple Handle Value Notification (Core Spec Vol 3 Part F 3.4.7.5)
 */
int
att_send_multiple_handle_value_ntf(struct att_conn *ac,
    const uint16_t *handles, const uint8_t **values,
    const uint16_t *lengths, int count)
{
	if (ac == NULL) {
		errno = EINVAL;
		return (-1);
	}

	ATT_RSP_BUF_DECL(ac);
	uint16_t pos, maxlen;
	int i, ret;

	if (rsp == NULL)
		return (-1);

	if (count <= 0) {
		ATT_RSP_BUF_FREE();
		return (0);
	}
	if (handles == NULL || values == NULL || lengths == NULL) {
		ATT_RSP_BUF_FREE();
		errno = EINVAL;
		return (-1);
	}

	maxlen = ac->mtu > ATT_PDU_BUF_SIZE ? ac->mtu : ATT_PDU_BUF_SIZE;
	rsp[0] = ATT_OP_MULTIPLE_HANDLE_VALUE_NTF;
	pos = 1;

	for (i = 0; i < count; i++) {
		uint32_t entry_len = 4 + (uint32_t)lengths[i];

		if (values[i] == NULL && lengths[i] > 0) {
			ATT_RSP_BUF_FREE();
			errno = EINVAL;
			return (-1);
		}
		if (pos + entry_len > maxlen)
			break;
		if (pos + entry_len > ac->mtu)
			break;

		put_le16(rsp + pos, handles[i]);
		put_le16(rsp + pos + 2, lengths[i]);
		if (lengths[i] > 0)
			memcpy(rsp + pos + 4, values[i], lengths[i]);
		pos += entry_len;
	}

	if (i == 0) {
		ATT_RSP_BUF_FREE();
		return (0);
	}

	LOG_ATT(2, "srv: multi handle value ntf count=%d/%d len=%d",
	    i, count, pos);

	ret = att_server_send(ac, rsp, pos) == pos ? 0 : -1;
	if (ret == 0)
		BLUED_PROBE_ATT_NOTIFY_MULTI(i, pos);
	ATT_RSP_BUF_FREE();
	return (ret);
}

/*
 * Notify a set of handles, coalescing into a single Multiple Handle Value
 * Notification only when the client has opted in via Client Supported
 * Features bit 2 (Core Spec Vol 3 Part G §7.2 / Part F §3.4.7.5).
 *
 * A Multiple HVN must never be sent to a client that did not set CSF bit 2,
 * so when the feature is absent (or only a single handle is being notified)
 * this falls back to one Handle Value Notification per handle.  Returns 0 if
 * every notification was sent, -1 otherwise.
 */
int
att_notify_multi_gated(struct att_conn *ac, const uint16_t *handles,
    const uint8_t **values, const uint16_t *lengths, int count)
{
	int i, ret = 0;

	if (ac == NULL || handles == NULL || values == NULL ||
	    lengths == NULL) {
		errno = EINVAL;
		return (-1);
	}

	if (count <= 0)
		return (0);

	if (ac->multi_notify && count > 1)
		return (att_send_multiple_handle_value_ntf(ac, handles,
		    values, lengths, count));

	/* Fallback: individual Handle Value Notifications (§3.4.7.1). */
	for (i = 0; i < count; i++) {
		if (att_send_notification(ac, handles[i], values[i],
		    lengths[i]) < 0)
			ret = -1;
	}
	return (ret);
}
