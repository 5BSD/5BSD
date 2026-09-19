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
#include <time.h>

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
 *
 * A-F2: for the same reason this transport-level sender does not consult the
 * parent characteristic's security requirement either.  The caller must gate
 * delivery on the link meeting that requirement (see ctl_gatt_notify_result,
 * which uses att_check_security_perms_read) — a subscription bit alone is not
 * sufficient authority to deliver over an under-secured link.
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

	/*
	 * One indication at a time (Core Spec Vol 3 Part F §3.3.2).  Before
	 * refusing, self-heal a pending indication whose 30 s confirmation
	 * window (§3.3.3) has already elapsed: if no caller armed the kqueue
	 * timer, ind_pending would otherwise stay set forever and wedge every
	 * future indication.  The self-armed ind_deadline below makes this
	 * function self-sufficient regardless of caller behaviour.
	 */
	if (ac->ind_pending) {
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > ac->ind_deadline.tv_sec ||
		    (now.tv_sec == ac->ind_deadline.tv_sec &&
		     now.tv_nsec >= ac->ind_deadline.tv_nsec)) {
			ac->ind_pending = false;
			ac->ind_handle = 0;
			ac->ind_bearer_fd = -1;
		} else {
			ATT_RSP_BUF_FREE();
			errno = EBUSY;
			return (-1);
		}
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
		struct timespec now;

		ac->ind_pending = true;
		ac->ind_handle = handle;	/* for robust-caching Fig 2.6 */
		/*
		 * att_server_send() puts an indication on the primary bearer,
		 * so that is where the confirmation must come back (Vol 3
		 * Part F Section 3.3.3).
		 */
		ac->ind_bearer_fd = -1;
		/*
		 * Self-arm the 30 s confirmation deadline (Core Spec Vol 3
		 * Part F §3.3.3 / §3.4.7.3).  A subsequent att_send_indication()
		 * clears ind_pending if this instant has passed with no
		 * confirmation, so indications can never be wedged permanently
		 * even if a caller forgets to arm an external timer.  The
		 * main-loop peripheral path additionally arms a kqueue timer via
		 * blued_ind_arm_timeout() (blued_event.c) for timely teardown;
		 * that remains the mechanism for failing the bearer on expiry,
		 * while this deadline is the always-present safety net.
		 */
		clock_gettime(CLOCK_MONOTONIC, &now);
		ac->ind_deadline = now;
		ac->ind_deadline.tv_sec += 30;
		BLUED_PROBE_ATT_INDICATE(handle, pdulen);
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
	ret = 0;

	/*
	 * Pack tuples into as many Multiple HVN PDUs as it takes: a caller of
	 * this function expects EVERY (handle,len,value) tuple to go out, not
	 * only the prefix that fit the first PDU.  Whenever a tuple does not
	 * fit the current PDU, flush the PDU and start a new one; a tuple that
	 * does not fit an EMPTY PDU (value > MTU-4) goes through the C2-M4
	 * per-tuple fallback below.  Returns -1 only if a send fails.
	 */
	i = 0;
	while (i < count) {
		int first = i;

		rsp[0] = ATT_OP_MULTIPLE_HANDLE_VALUE_NTF;
		pos = 1;

		for (; i < count; i++) {
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

		if (i == first) {
			/*
			 * C2-M4: this (handle,len,value) tuple alone does not
			 * fit an empty Multiple HVN PDU.  Returning 0 without
			 * sending would let the caller count the handle as
			 * delivered while nothing went out.  Fall back to one
			 * truncating Handle Value Notification (Core Spec Vol
			 * 3 Part F §3.4.7.1); att_send_notification clamps the
			 * value to MTU-3.  Report failure if the send fails.
			 */
			if (att_send_notification(ac, handles[i], values[i],
			    lengths[i]) < 0)
				ret = -1;
			i++;
			continue;
		}

		if (i - first == 1) {
			/*
			 * The packed PDU would carry exactly one tuple.  A
			 * plain Handle Value Notification (§3.4.7.1) conveys
			 * the same data in a smaller PDU, so send that
			 * instead (reusing the per-tuple fallback machinery).
			 * Covers both a single-tuple first PDU and a single
			 * leftover tuple in a continuation; the tuple fit the
			 * Multiple HVN (len <= MTU-4), so the notification's
			 * MTU-3 clamp never truncates it.
			 */
			if (att_send_notification(ac, handles[first],
			    values[first], lengths[first]) < 0)
				ret = -1;
			continue;
		}

		LOG_ATT(2, "srv: multi handle value ntf count=%d/%d len=%d",
		    i, count, pos);

		if (att_server_send(ac, rsp, pos) != pos) {
			ret = -1;
			continue;
		}
		BLUED_PROBE_ATT_NOTIFY_MULTI(i - first, pos);
	}

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
