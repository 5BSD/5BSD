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

#include <time.h>

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

/*
 * Unit tests use AF_UNIX SOCK_SEQPACKET pairs, which deliberately do not
 * implement the L2CAP MTU socket options.  A test binary may provide this
 * weak symbol to model parameters negotiated by its fake CoC.  Production
 * does not define it and therefore never falls back when either real query
 * fails.
 */
extern int att_test_eatt_mtu(int, uint16_t *, uint16_t *)
    __attribute__((weak));

static int
att_eatt_query_mtu(int fd, uint16_t *imtu, uint16_t *omtu)
{
	socklen_t optlen;
	int saved;

	optlen = sizeof(*imtu);
	if (getsockopt(fd, SOL_L2CAP, SO_L2CAP_IMTU, imtu, &optlen) < 0)
		goto test_seam;
	if (optlen != sizeof(*imtu)) {
		errno = EPROTO;
		goto test_seam;
	}
	optlen = sizeof(*omtu);
	if (getsockopt(fd, SOL_L2CAP, SO_L2CAP_OMTU, omtu, &optlen) < 0)
		goto test_seam;
	if (optlen != sizeof(*omtu)) {
		errno = EPROTO;
		goto test_seam;
	}
	return (0);

test_seam:
	saved = errno;
	if (att_test_eatt_mtu != NULL &&
	    att_test_eatt_mtu(fd, imtu, omtu) == 0)
		return (0);
	errno = saved;
	return (-1);
}
#include "hci_util.h"

/* Each client worker owns its response storage while parsing a transaction. */
static _Thread_local uint8_t att_client_rsp[ATT_MAX_MTU];

static void
att_bearers_lock(struct att_conn *ac)
{
	bool expected;

	for (;;) {
		expected = false;
		if (atomic_compare_exchange_weak_explicit(&ac->bearer_lock,
		    &expected, true, memory_order_acquire, memory_order_relaxed))
			return;
	}
}

static void
att_bearers_unlock(struct att_conn *ac)
{

	atomic_store_explicit(&ac->bearer_lock, false, memory_order_release);
}

/*
 * Select an idle bearer whose independently negotiated ATT_MTU can carry
 * the complete PDU.  EATT bearers are considered in array order before the
 * fixed bearer, matching att_eatt_select_bearer()'s established policy.
 *
 * C2-L6: when force_fixed is set the EATT bearers are skipped and only the
 * unenhanced fixed L2CAP channel (CID 0x0004) is eligible.  The Exchange MTU
 * sub-procedure "shall only be initiated on the ATT bearer using the L2CAP
 * fixed channel" (Core Spec Vol 3 Part F §3.4.2 / §5.3.1) — routing it over an
 * EATT bearer (which has its own per-CoC MTU and rejects MTU_REQ) is illegal.
 */
static int
att_select_bearer_for_pdu(struct att_conn *ac, size_t pdulen, uint16_t *mtu_out,
    bool force_fixed)
{
	bool has_capacity;
	int fd, i;

	has_capacity = false;
	att_bearers_lock(ac);
	for (i = 0; !force_fixed && i < ac->eatt_count; i++) {
		if (!ac->eatt[i].active || ac->eatt[i].fd < 0 ||
		    pdulen > ac->eatt[i].mtu)
			continue;
		has_capacity = true;
		if (ac->eatt[i].pending != 0)
			continue;
		ac->eatt[i].pending = 1;
		fd = ac->eatt[i].fd;
		/*
		 * Report the selected bearer's independently negotiated CoC
		 * MTU so the caller sizes its recv to this bearer, not to the
		 * fixed-channel ac->mtu (which may be smaller): an EATT response
		 * up to this MTU must not be truncated.
		 */
		if (mtu_out != NULL)
			*mtu_out = ac->eatt[i].mtu;
		att_bearers_unlock(ac);
		return (fd);
	}

	if (!ac->failed && ac->fd >= 0 && pdulen <= ac->mtu) {
		has_capacity = true;
		if (ac->primary_pending == 0) {
			ac->primary_pending = 1;
			fd = ac->fd;
			if (mtu_out != NULL)
				*mtu_out = ac->mtu;
			att_bearers_unlock(ac);
			return (fd);
		}
	}
	att_bearers_unlock(ac);

	if (ac->failed)
		errno = EPIPE;
	else
		errno = has_capacity ? EBUSY : EMSGSIZE;
	return (-1);
}

/*
 * Select one stable bearer for Write Commands.
 *
 * Core Spec Vol 3 Part F only preserves ATT PDU ordering on a single
 * bearer.  In particular, distributing a segmented higher-layer message
 * over independently ordered EATT channels can deliver its Last segment
 * before its First segment.  Choose the idle, fitting bearer with the
 * largest MTU (EATT wins an equal-MTU tie), then keep using it.  A busy
 * pinned bearer is reported as busy rather than silently changing the
 * ordering domain.
 */
static int
att_select_write_cmd_bearer(struct att_conn *ac, size_t pdulen)
{
	uint16_t mtu, best_mtu;
	int best_fd, i;
	bool busy, found, has_capacity, has_live;

	att_bearers_lock(ac);
	if (ac->write_cmd_bearer_pinned) {
		found = false;
		busy = false;
		mtu = 0;
		if (!ac->failed && ac->fd >= 0 &&
		    ac->write_cmd_bearer_fd == ac->fd) {
			found = true;
			busy = ac->primary_pending != 0;
			mtu = ac->mtu;
		} else {
			for (i = 0; i < ac->eatt_count; i++) {
				if (!ac->eatt[i].active || ac->eatt[i].fd < 0 ||
				    ac->eatt[i].fd != ac->write_cmd_bearer_fd)
					continue;
				found = true;
				busy = ac->eatt[i].pending != 0;
				mtu = ac->eatt[i].mtu;
				break;
			}
		}
		if (found) {
			if (pdulen > mtu) {
				att_bearers_unlock(ac);
				errno = EMSGSIZE;
				return (-1);
			}
			if (busy) {
				att_bearers_unlock(ac);
				errno = EBUSY;
				return (-1);
			}
			if (ac->write_cmd_bearer_fd == ac->fd)
				ac->primary_pending = 1;
			else
				ac->eatt[i].pending = 1;
			best_fd = ac->write_cmd_bearer_fd;
			att_bearers_unlock(ac);
			return (best_fd);
		}
		ac->write_cmd_bearer_pinned = false;
	}

	best_fd = -1;
	best_mtu = 0;
	has_capacity = false;
	has_live = false;
	/* EATT wins equal-capacity ties, preserving the existing preference. */
	for (i = 0; i < ac->eatt_count; i++) {
		if (!ac->eatt[i].active || ac->eatt[i].fd < 0 ||
		    pdulen > ac->eatt[i].mtu) {
			if (ac->eatt[i].active && ac->eatt[i].fd >= 0)
				has_live = true;
			continue;
		}
		has_live = true;
		has_capacity = true;
		if (ac->eatt[i].pending != 0 || ac->eatt[i].mtu <= best_mtu)
			continue;
		best_fd = ac->eatt[i].fd;
		best_mtu = ac->eatt[i].mtu;
	}
	if (!ac->failed && ac->fd >= 0 && pdulen <= ac->mtu) {
		has_live = true;
		has_capacity = true;
		if (ac->primary_pending == 0 && ac->mtu > best_mtu) {
			best_fd = ac->fd;
			best_mtu = ac->mtu;
		}
	} else if (!ac->failed && ac->fd >= 0) {
		has_live = true;
	}
	if (best_fd < 0) {
		att_bearers_unlock(ac);
		errno = !has_live ? EPIPE :
		    (has_capacity ? EBUSY : EMSGSIZE);
		return (-1);
	}
	ac->write_cmd_bearer_fd = best_fd;
	ac->write_cmd_bearer_pinned = true;
	if (best_fd == ac->fd)
		ac->primary_pending = 1;
	else {
		for (i = 0; i < ac->eatt_count; i++)
			if (ac->eatt[i].fd == best_fd) {
				ac->eatt[i].pending = 1;
				break;
			}
	}
	att_bearers_unlock(ac);
	return (best_fd);
}

/*
 * Open an ATT connection to a BLE device.
 */
int
att_open(struct att_conn *ac, const uint8_t *local_addr,
    uint8_t own_addr_type, const uint8_t *addr, uint8_t addr_type)
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

	if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_OWN_ADDR_TYPE,
	    &own_addr_type, sizeof(own_addr_type)) < 0) {
		close(fd);
		return (-1);
	}

	/* Bind to the selected local adapter. */
	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	if (local_addr != NULL)
		memcpy(&sa.l2cap_bdaddr, local_addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;

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
	/*
	 * Bound att_server_send(): it runs on the event-loop thread while
	 * gatt_db_lock is held, so a peer whose L2CAP TX buffer is full would
	 * otherwise stall every gatt_db_lock acquirer (the whole GATT worker
	 * pool) until link supervision (~32s) drops the link.  5s caps that
	 * priority inversion while staying far above any healthy backpressure.
	 */
	{
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_SNDTIMEO");
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
att_open_fd(struct att_conn *ac, int fd, const uint8_t *local_addr,
    uint8_t own_addr_type, const uint8_t *addr, uint8_t addr_type)
{
	struct sockaddr_l2cap sa;

	memset(ac, 0, sizeof(*ac));
	ac->fd = -1;
	ac->bearer_fd = -1;
	ac->eatt_count = 0;
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;

	if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_OWN_ADDR_TYPE,
	    &own_addr_type, sizeof(own_addr_type)) < 0)
		return (-1);
	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	if (local_addr != NULL)
		memcpy(&sa.l2cap_bdaddr, local_addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return (-1);

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
	/* Bound att_server_send() under gatt_db_lock; see att_open(). */
	{
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_SNDTIMEO");
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
	att_bearers_lock(ac);
	ac->write_cmd_bearer_pinned = false;
	att_bearers_unlock(ac);
	if (ac->fd >= 0) {
		close(ac->fd);
		ac->fd = -1;
	}
	free(ac->buf);
	ac->buf = NULL;
	ac->prep_queue.count = 0;
}

/*
 * Cap subsequent att_request() deadlines on this connection (finding 62).
 * See att.h: 0 restores the 30 s ATT default; any value is clamped to 30 s
 * inside att_request().  A single plain scalar store — att_request reads the
 * field once at entry, so there is no lock ordering concern.
 */
void
att_conn_set_op_timeout(struct att_conn *ac, unsigned int ms)
{

	if (ac != NULL)
		ac->op_timeout_ms = ms;
}

/*
 * Release a bearer previously selected by att_eatt_select_bearer():
 * decrement its outstanding-request count.  att_eatt_select_bearer()
 * does pending++ when it hands out an EATT bearer; that increment models a
 * response the client is still waiting for.  It MUST be undone on every
 * path that will not consume a matching response — a no-response Write
 * Command, and att_request()'s send / timeout / transport-error early
 * returns — otherwise pending grows without bound and the least-loaded
 * selector permanently starves the bearer (Core Spec Vol 3 Part G §5.3:
 * EATT multiplexing distributes work assuming the load counter reflects
 * only genuinely outstanding responses).  A no-op for the primary bearer.
 */
static void
att_eatt_bearer_release(struct att_conn *ac, int fd)
{
	int bi;

	att_bearers_lock(ac);
	if (fd == ac->fd) {
		ac->primary_pending = 0;
		att_bearers_unlock(ac);
		return;
	}
	for (bi = 0; bi < ac->eatt_count; bi++) {
		if (ac->eatt[bi].fd == fd && ac->eatt[bi].pending > 0) {
			ac->eatt[bi].pending--;
			att_bearers_unlock(ac);
			return;
		}
	}
	att_bearers_unlock(ac);
}

/* A transaction failure invalidates only the ATT bearer which carried it. */
static void
att_bearer_fail(struct att_conn *ac, int fd)
{
	int saved_errno;

	saved_errno = errno;
	if (fd == ac->fd) {
		att_bearers_lock(ac);
		ac->primary_pending = 0;
		ac->failed = true;
		if (ac->write_cmd_bearer_pinned &&
		    ac->write_cmd_bearer_fd == fd)
			ac->write_cmd_bearer_pinned = false;
		att_bearers_unlock(ac);
	} else
		att_eatt_remove_bearer(ac, fd);
	errno = saved_errno;
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
	uint16_t bearer_mtu = ac->mtu;
	size_t recvlen;
	unsigned int cap_ms;
	struct timespec deadline, now;
	struct timeval tv_remaining;

	if (ae != NULL)
		memset(ae, 0, sizeof(*ae));

	/*
	 * Record an absolute deadline so that interleaved notifications
	 * cannot reset the wall-clock timeout.  On each loop iteration,
	 * SO_RCVTIMEO is adjusted to the remaining time.
	 *
	 * The default cap is the ATT transaction ceiling of 30 s (Core Spec
	 * Vol 3 Part F §3.3.3).  A caller (e.g. the ctl layer processing a
	 * blocking GATT op on the shared event-loop thread) may install a
	 * tighter per-connection cap via att_conn_set_op_timeout(); it is
	 * honoured here so the whole request — across any interleaved
	 * notification drain — completes within that bound rather than being
	 * clobbered back to remaining-of-30 s each iteration.
	 */
	cap_ms = ac->op_timeout_ms;
	if (cap_ms == 0 || cap_ms > 30000)
		cap_ms = 30000;
	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += cap_ms / 1000;
	deadline.tv_nsec += (long)(cap_ms % 1000) * 1000000L;
	if (deadline.tv_nsec >= 1000000000L) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000L;
	}

	/*
	 * Select the best available bearer.  Prefer EATT bearers when
	 * available — they allow ATT multiplexing (Core Spec Vol 3
	 * Part G §5.3).  Fall back to the primary bearer on CID 0x0004.
	 */
	/* C2-L6: Exchange MTU must run only on the fixed bearer (§3.4.2). */
	fd = att_select_bearer_for_pdu(ac, reqlen, &bearer_mtu,
	    ((const uint8_t *)req)[0] == ATT_OP_MTU_REQ);
	if (fd < 0)
		return (-1);

	/*
	 * Size the receive to the selected bearer's MTU rather than to the
	 * caller-supplied rsplen (which is the fixed-channel ac->mtu).  An
	 * EATT bearer's CoC MTU is negotiated independently and can exceed the
	 * fixed MTU; capping recv at rsplen would silently truncate a longer
	 * EATT response.  The response buffer (att_client_rsp / att_exchange_mtu)
	 * is always ATT_MAX_MTU, an upper bound on any bearer MTU, so a full
	 * bearer-MTU recv never overruns it.  Never shrink below rsplen.
	 */
	recvlen = bearer_mtu;
	if (recvlen < rsplen)
		recvlen = rsplen;

	n = send(fd, req, reqlen, MSG_EOR);
	if (n < 0) {
		att_bearer_fail(ac, fd);
		return (-1);
	}

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
	 * spinning indefinitely by sending unsolicited PDUs.  The
	 * SO_RCVTIMEO is adjusted on each iteration to reflect the
	 * remaining wall-clock time until the absolute deadline.
	 */
	for (;;) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec > deadline.tv_sec ||
		    (now.tv_sec == deadline.tv_sec &&
		     now.tv_nsec >= deadline.tv_nsec)) {
			att_bearer_fail(ac, fd);
			errno = ETIMEDOUT;
			return (-1);
		}
		tv_remaining.tv_sec = deadline.tv_sec - now.tv_sec;
		if (deadline.tv_nsec >= now.tv_nsec) {
			tv_remaining.tv_usec =
			    (deadline.tv_nsec - now.tv_nsec) / 1000;
		} else {
			tv_remaining.tv_sec--;
			tv_remaining.tv_usec =
			    (1000000000L + deadline.tv_nsec - now.tv_nsec) / 1000;
		}
		/*
		 * SO_RCVTIMEO of {0,0} disables the timeout (blocks forever).
		 * A sub-second remaining deadline truncates tv_usec toward
		 * zero, so a remaining time under one microsecond would round
		 * to {0,0} and wait forever.  Round up to a minimum one-tick
		 * (1 ms) timeout so the wall-clock deadline is always honoured
		 * (Core Spec Vol 3 Part F §3.3.3).
		 */
		if (tv_remaining.tv_sec == 0 && tv_remaining.tv_usec == 0)
			tv_remaining.tv_usec = 1000;
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv_remaining, sizeof(tv_remaining));

		n = att_recv_record(fd, rsp, recvlen);
		if (n < 0) {
			int save = errno;
			att_bearer_fail(ac, fd);
			errno = save;
			return (-1);
		}

		if (n == 0) {
			att_bearer_fail(ac, fd);
			warnx("ATT: connection closed by peer");
			errno = ECONNRESET;
			return (-1);
		}

		opcode = ((uint8_t *)rsp)[0];

		/* Skip notifications -- they are unsolicited */
		if (opcode == ATT_OP_HANDLE_NOTIFY ||
		    opcode == ATT_OP_MULTIPLE_HANDLE_VALUE_NTF) {
			if (ac->unsolicited_cb != NULL)
				ac->unsolicited_cb(ac, fd, rsp, (size_t)n,
				    ac->unsolicited_arg);
			/* EATT notifications shall always be processed (§3.3.2). */
			if (fd != ac->fd)
				continue;
			if (--max_skip <= 0) {
				warnx("ATT: too many unsolicited PDUs while waiting for response");
				/*
				 * C2-H2: abandoning the request here while its
				 * response is still in flight desyncs the bearer —
				 * the response we never consumed sits in the socket
				 * and the NEXT att_request() recv()s it, matching a
				 * stale reply to a new request.  Core Spec Vol 3
				 * Part F §3.3.3 requires failing the bearer on such
				 * an abort, so mark it unusable (fixed bearer:
				 * ac->failed; EATT: remove the bearer) forcing a
				 * reconnect rather than silently reusing a
				 * desynchronised channel.  A distinct errno
				 * (EBADMSG, not the EPROTO reserved for a real
				 * Error Response) gives callers a clean transport
				 * failure.
				 */
				att_bearer_fail(ac, fd);
				errno = EBADMSG;
				return (-1);
			}
			continue;
		}

		/* Confirm and skip indications */
		if (opcode == ATT_OP_HANDLE_IND) {
			if (ac->unsolicited_cb != NULL)
				ac->unsolicited_cb(ac, fd, rsp, (size_t)n,
				    ac->unsolicited_arg);
			else {
				uint8_t cfm = ATT_OP_HANDLE_CFM;
				(void)send(fd, &cfm, 1, MSG_EOR);
			}
			if (--max_skip <= 0) {
				warnx("ATT: too many unsolicited PDUs while waiting for response");
				/*
				 * C2-H2: as above — the request's response is
				 * still in flight, so abandoning it without
				 * failing the bearer would let a later request
				 * consume the stale reply.  Fail the bearer
				 * (§3.3.3) to force a resynchronising reconnect.
				 */
				att_bearer_fail(ac, fd);
				errno = EBADMSG;
				return (-1);
			}
			continue;
		}

		break;
	}

	/* Log incoming ATT PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    rsp, n, true);

	/* Error Responses are valid only for this request and are exactly 5 B. */
	if (((uint8_t *)rsp)[0] == ATT_OP_ERROR_RSP) {
		if (n != 5 || ((uint8_t *)rsp)[1] != ((const uint8_t *)req)[0]) {
			att_bearer_fail(ac, fd);
			errno = EBADMSG;
			return (-1);
		}
		att_eatt_bearer_release(ac, fd);
		if (ae != NULL) {
			ae->req_opcode = ((uint8_t *)rsp)[1];
			ae->handle = get_le16((uint8_t *)rsp + 2);
			/*
			 * A-F4: 0x00 is a Reserved error code (Core Spec Vol 3
			 * Part F Table 3.4) that a peer must never send.  The
			 * error-returning wrappers surface ae.code when errno is
			 * EPROTO, and callers read 0 as success — so a malicious
			 * or garbage 0x00 would be mistaken for a successful
			 * operation.  Substitute a nonzero code so an Error
			 * Response is always a failure.
			 */
			ae->code = (((uint8_t *)rsp)[4] == 0x00) ?
			    ATT_ERR_UNLIKELY_ERROR : ((uint8_t *)rsp)[4];
		}
		warnx("ATT error: req=%02x handle=%04x code=%02x",
		    ((uint8_t *)rsp)[1], get_le16((uint8_t *)rsp + 2),
		    ((uint8_t *)rsp)[4]);
		errno = EPROTO;
		return (-1);
	}

	/* Response consumed successfully: this bearer can accept another request. */
	att_eatt_bearer_release(ac, fd);

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
	uint8_t req[3];
	/*
	 * Receive into the full-size thread-local response buffer, not a
	 * 5-byte MTU-Response-sized stack buffer: att_request()'s drain loop
	 * can surface an unsolicited notification/indication (the unsolicited
	 * handler is registered before the exchange) that is larger than the
	 * MTU Response, and a short buffer would truncate it — corrupting the
	 * PDU handed to the unsolicited callback.
	 */
	uint8_t *rsp = att_client_rsp;
	struct att_error ae;
	ssize_t n;
	uint16_t server_mtu;

	if (client_mtu < ATT_DEFAULT_MTU)
		client_mtu = ATT_DEFAULT_MTU;

	if (ac->mtu_exchanged) {
		errno = EALREADY;
		return (-1);
	}

	req[0] = ATT_OP_MTU_REQ;
	put_le16(req + 1, client_mtu);

	n = att_request(ac, req, sizeof(req), rsp, ATT_MAX_MTU, &ae);
	if (n < 0)
		return (-1);

	if (n != 3 || rsp[0] != ATT_OP_MTU_RSP) {
		warnx("ATT: bad MTU response opcode=%02x len=%zd", rsp[0], n);
		errno = EPROTO;
		return (-1);
	}

	server_mtu = get_le16(rsp + 1);
	ac->mtu = client_mtu < server_mtu ? client_mtu : server_mtu;
	if (ac->mtu < ATT_DEFAULT_MTU)
		ac->mtu = ATT_DEFAULT_MTU;
	/*
	 * A-F6: the unenhanced (fixed CID 0x0004) ATT bearer is capped at 517
	 * octets (Core Spec Vol 3 Part F §3.2.8); clamp to that, not the 65535
	 * EATT ceiling, since Exchange MTU only runs on the unenhanced bearer.
	 */
	if (ac->mtu > ATT_UNENHANCED_MAX_MTU)
		ac->mtu = ATT_UNENHANCED_MAX_MTU;

	ac->mtu_exchanged = true;

	/* role 0 == client (we initiated the exchange). */
	BLUED_PROBE_ATT_MTU(0, client_mtu, server_mtu, ac->mtu);
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (att_client_rsp[0] != ATT_OP_READ_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, att_client_rsp + 1, datalen);
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (att_client_rsp[0] != ATT_OP_READ_BLOB_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, att_client_rsp + 1, datalen);
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
	size_t reqlen;

	if (ac == NULL || (data == NULL && len > 0)) {
		errno = EINVAL;
		return (-1);
	}

	if (len > SIZE_MAX - 3) {
		errno = EMSGSIZE;
		return (-1);
	}
	reqlen = 3 + len;

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

	n = att_request(ac, reqbuf, reqlen, att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (n != 1 || att_client_rsp[0] != ATT_OP_WRITE_RSP) {
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
	uint8_t pdubuf[ATT_PDU_BUF_SIZE];
	uint8_t *pdu;
	size_t pdulen;
	int fd;

	if (ac == NULL || (data == NULL && len > 0)) {
		errno = EINVAL;
		return (-1);
	}

	if (len > SIZE_MAX - 3) {
		errno = EMSGSIZE;
		return (-1);
	}
	pdulen = 3 + len;

	/*
	 * Use a stack-local buffer instead of ac->buf to avoid data
	 * races — Write Command has no response phase, so ac->buf may
	 * be in use by a concurrent att_request() on another bearer.
	 * Heap-allocate only when the PDU exceeds the stack buffer.
	 */
	if (pdulen <= sizeof(pdubuf)) {
		pdu = pdubuf;
	} else {
		pdu = malloc(pdulen);
		if (pdu == NULL)
			return (-1);
	}

	pdu[0] = ATT_OP_WRITE_CMD;
	put_le16(pdu + 1, handle);
	memcpy(pdu + 3, data, len);

	/*
	 * Keep all Write Commands on one ordering domain.  This is required by
	 * users such as Mesh Proxy SAR, where a shorter Last segment must not be
	 * redirected to a different bearer than the full-size First segment.
	 */
	fd = att_select_write_cmd_bearer(ac, pdulen);
	if (fd < 0) {
		if (pdu != pdubuf)
			free(pdu);
		return (-1);
	}

	if (send(fd, pdu, pdulen, MSG_EOR) < 0) {
		/*
		 * A Write Command has no response phase (Core Spec Vol 3
		 * Part F §3.4.5.3), so the pending++ that att_eatt_select_bearer()
		 * charged for this send must be released here too — otherwise
		 * the bearer's load counter leaks on the send-failure path.
		 */
		att_bearer_fail(ac, fd);
		if (pdu != pdubuf)
			free(pdu);
		return (-1);
	}

	/*
	 * Write Command is a no-response PDU; release the bearer slot that
	 * att_eatt_select_bearer() reserved so pending reflects only
	 * outstanding responses (Core Spec Vol 3 Part F §3.4.5.3).
	 */
	att_eatt_bearer_release(ac, fd);

	BLUED_PROBE_ATT_SEND(pdu[0], (int)pdulen);

	/* Log outgoing ATT Write Command PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    pdu, pdulen, false);

	LOG_ATT(2, "write cmd handle=%04x len=%zu", handle, len);

	if (pdu != pdubuf)
		free(pdu);

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
	size_t reqlen;

	if (ac == NULL || (value == NULL && vlen > 0)) {
		errno = EINVAL;
		return (-1);
	}

	if (vlen > SIZE_MAX - 7) {
		errno = EMSGSIZE;
		return (-1);
	}
	reqlen = 7 + vlen;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EMSGSIZE;
		return (-1);
	}

	req[0] = ATT_OP_FIND_BY_TYPE_VALUE_REQ;
	put_le16(req + 1, start);
	put_le16(req + 3, end);
	put_le16(req + 5, uuid16);
	memcpy(req + 7, value, vlen);

	n = att_request(ac, req, reqlen, att_client_rsp, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (att_client_rsp[0] != ATT_OP_FIND_BY_TYPE_VALUE_RSP || n < 5 ||
	    ((size_t)n - 1) % 4 != 0) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (buf == NULL || datalen > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(buf, att_client_rsp + 1, datalen);
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

	n = att_request(ac, req, reqlen, att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (att_client_rsp[0] != ATT_OP_READ_MULTIPLE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, att_client_rsp + 1, datalen);
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

	n = att_request(ac, req, reqlen, att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (att_client_rsp[0] != ATT_OP_READ_MULTIPLE_VARIABLE_RSP) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (datalen > buflen)
		datalen = buflen;
	memcpy(buf, att_client_rsp + 1, datalen);
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
	size_t reqlen;

	if (ac == NULL || (data == NULL && len > 0)) {
		errno = EINVAL;
		return (-1);
	}

	if (len > SIZE_MAX - 5) {
		errno = EMSGSIZE;
		return (-1);
	}
	reqlen = 5 + len;

	if (reqlen > ac->mtu || reqlen > sizeof(req)) {
		errno = EMSGSIZE;
		return (-1);
	}

	req[0] = ATT_OP_PREPARE_WRITE_REQ;
	put_le16(req + 1, handle);
	put_le16(req + 3, offset);
	if (len > 0)
		memcpy(req + 5, data, len);

	n = att_request(ac, req, reqlen, att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (att_client_rsp[0] != ATT_OP_PREPARE_WRITE_RSP || n < 5) {
		errno = EPROTO;
		return (-1);
	}

	/* Verify the server echoed back the same handle and offset */
	if (get_le16(att_client_rsp + 1) != handle ||
	    get_le16(att_client_rsp + 3) != offset) {
		warnx("ATT: prepare write echo mismatch");
		errno = EPROTO;
		return (-1);
	}

	/*
	 * Verify the server echoed back the same value data.  Core Spec Vol 3
	 * Part F §3.4.6.2 requires the Part Attribute Value in the response to
	 * be set to the same value as in the request, so the response must
	 * carry the full echoed value (n == 5 + len) AND it must match.  A
	 * truncated echo (n < 5 + len) is itself a violation and must NOT be
	 * treated as a pass — otherwise a server can silently sidestep the
	 * value-integrity check by returning a short response.  Either fault
	 * means the queued write is untrustworthy; cancel all prepared writes
	 * to avoid applying bad data.
	 */
	if (n != 5 + (ssize_t)len ||
	    (len > 0 && memcmp(att_client_rsp + 5, data, len) != 0)) {
		att_execute_write(ac, ATT_EXECUTE_WRITE_CANCEL);
		warnx("ATT: prepare write value mismatch");
		errno = EPROTO;
		return (-1);
	}

	LOG_ATT(2, "prepare write handle=%04x offset=%d len=%zu",
	    handle, offset, len);

	return (0);
}

/*
 * ATT Execute Write Request (Core Spec Vol 3 Part F 3.4.6.3)
 * flags: ATT_EXECUTE_WRITE_CANCEL or ATT_EXECUTE_WRITE_COMMIT.
 */
int
att_execute_write(struct att_conn *ac, uint8_t flags)
{
	uint8_t req[2];
	struct att_error ae;
	ssize_t n;

	req[0] = ATT_OP_EXECUTE_WRITE_REQ;
	req[1] = flags;

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0)
		return (errno == EPROTO ? ae.code : -1);

	if (n != 1 || att_client_rsp[0] != ATT_OP_EXECUTE_WRITE_RSP) {
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
			(void)att_execute_write(ac, ATT_EXECUTE_WRITE_CANCEL);
			return (rc);
		}
		off += chunk;
	}

	rc = att_execute_write(ac, ATT_EXECUTE_WRITE_COMMIT);
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (att_client_rsp[0] != ATT_OP_FIND_INFO_RSP || n < 6 ||
	    (att_client_rsp[1] != 1 && att_client_rsp[1] != 2) ||
	    ((size_t)n - 2) % (att_client_rsp[1] == 1 ? 4 : 18) != 0) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (buf == NULL || datalen > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(buf, att_client_rsp + 1, datalen);
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (att_client_rsp[0] != ATT_OP_READ_BY_TYPE_RSP || n < 4 ||
	    att_client_rsp[1] < 2 ||
	    ((size_t)n - 2) % att_client_rsp[1] != 0) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (buf == NULL || datalen > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(buf, att_client_rsp + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * ATT Read By Type Request with 128-bit UUID (Core Spec Vol 3 Part F 3.4.4.1)
 * Builds a 21-byte PDU: opcode(1) + start(2) + end(2) + uuid128(16).
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (att_client_rsp[0] != ATT_OP_READ_BY_TYPE_RSP || n < 4 ||
	    att_client_rsp[1] < 2 ||
	    ((size_t)n - 2) % att_client_rsp[1] != 0) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (buf == NULL || datalen > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(buf, att_client_rsp + 1, datalen);
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

	n = att_request(ac, req, sizeof(req), att_client_rsp, ac->mtu, &ae);
	if (n < 0) {
		if (errno == EPROTO && ae.code == ATT_ERR_ATTR_NOT_FOUND) {
			if (outlen != NULL)
				*outlen = 0;
			return (0);
		}
		return (errno == EPROTO ? ae.code : -1);
	}

	if (att_client_rsp[0] != ATT_OP_READ_BY_GROUP_TYPE_RSP || n < 6 ||
	    att_client_rsp[1] < 4 ||
	    ((size_t)n - 2) % att_client_rsp[1] != 0) {
		errno = EPROTO;
		return (-1);
	}

	size_t datalen = n - 1;
	if (buf == NULL || datalen > buflen) {
		errno = EMSGSIZE;
		return (-1);
	}
	memcpy(buf, att_client_rsp + 1, datalen);
	if (outlen != NULL)
		*outlen = datalen;

	return (0);
}

/*
 * Receive an unsolicited PDU (notification or indication).
 * Caller should use poll(2)/select(2) on ac->fd to know when data is ready.
 */
ssize_t
att_recv_record(int fd, void *buf, size_t buflen)
{
	struct sockaddr_storage ss;
	struct iovec iov;
	struct msghdr msg;
	socklen_t sslen;
	int family;
	ssize_t n;

	sslen = sizeof(ss);
	family = AF_BLUETOOTH;
	if (getsockname(fd, (struct sockaddr *)&ss, &sslen) == 0)
		family = ss.ss_family;
	iov.iov_base = buf;
	iov.iov_len = buflen;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	do {
		n = recvmsg(fd, &msg, 0);
	} while (n < 0 && errno == EINTR);
	if (n >= 0 && att_record_is_truncated(family, msg.msg_flags)) {
		errno = EMSGSIZE;
		return (-1);
	}
	return (n);
}

bool
att_record_is_truncated(int family, int msg_flags)
{

	/* AF_UNIX is the byte-stream-like unit-test transport on FreeBSD. */
	return (family != AF_UNIX && (msg_flags & MSG_TRUNC) != 0);
}

int
att_recv_bearer(struct att_conn *ac, int fd, void *buf, size_t buflen,
    size_t *outlen)
{
	ssize_t n;

	n = att_recv_record(fd, buf, buflen);
	if (n < 0)
		return (-1);
	if (n == 0) {
		errno = ECONNRESET;
		return (-1);
	}

	/* Log incoming unsolicited ATT PDU */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004,
		    buf, n, true);

	BLUED_PROBE_ATT_RECV(((uint8_t *)buf)[0], (int)n);

	if (outlen != NULL)
		*outlen = (size_t)n;

	return (0);
}

int
att_recv(struct att_conn *ac, void *buf, size_t buflen, size_t *outlen)
{

	return (att_recv_bearer(ac, ac->fd, buf, buflen, outlen));
}

/*
 * Send Handle Value Confirmation (for indications).
 * Core Spec Vol 3 Part F 3.4.7.3
 */
int
att_confirm_bearer(struct att_conn *ac, int fd)
{
	uint8_t pdu = ATT_OP_HANDLE_CFM;

	if (send(fd, &pdu, 1, MSG_EOR) < 0)
		return (-1);

	/* Log outgoing Handle Value Confirmation */
	if (hci_log_enabled())
		hci_log_l2cap(ac->con_handle, 0x0004, &pdu, 1, false);

	return (0);
}

int
att_confirm(struct att_conn *ac)
{

	return (att_confirm_bearer(ac, ac->fd));
}

void
att_set_unsolicited_handler(struct att_conn *ac,
    void (*cb)(struct att_conn *, int, const uint8_t *, size_t, void *),
    void *arg)
{

	ac->unsolicited_cb = cb;
	ac->unsolicited_arg = arg;
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
att_open_eatt(struct att_conn *ac, const uint8_t *local_addr,
    const uint8_t *addr, uint8_t addr_type, int count)
{
	int fds[ATT_MAX_EATT_BEARERS];
	int connected, i, opened, room;

	if (ac == NULL || !ac->encrypted) {
		errno = EPERM;
		return (0);
	}

	att_bearers_lock(ac);
	room = ATT_MAX_EATT_BEARERS - ac->eatt_count;
	att_bearers_unlock(ac);
	if (count > room)
		count = room;
	if (count <= 0)
		return (0);

	/*
	 * EATT is carried only over Enhanced Credit Based Flow Control
	 * channels (Core Vol 3, Part G, 5.3).  In particular, using the
	 * legacy LE Credit Based Connection Request for SPSM 0x0027 is not
	 * an EATT bearer even though it reaches the same SPSM.
	 */
	connected = ble_ecbfc_connect(local_addr, addr, addr_type,
	    ATT_EATT_PSM, 0, count, fds);
	if (connected <= 0) {
		LOG_ATT(1, "EATT: ECBFC connect failed: %s", strerror(errno));
		return (0);
	}

	opened = 0;
	for (i = 0; i < connected; i++) {
		if (att_eatt_add_bearer(ac, fds[i]) < 0) {
			for (; i < connected; i++)
				close(fds[i]);
			break;
		}
		opened++;

		LOG_ATT(1, "EATT: bearer %d connected, fd=%d", i, fds[i]);
	}

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

	return (att_select_bearer_for_pdu(ac, 0, NULL, false));
}

/*
 * Attach an already-connected L2CAP CoC socket (PSM 0x0027) as an EATT
 * bearer on this connection.  Used both by att_eatt_accept() (server side,
 * after accept4) and by the daemon's incoming-EATT dispatch, which accepts
 * on a shared listener and routes the bearer to the matching connection by
 * peer address before attaching it here.
 *
 * The bearer MTU comes from the L2CAP CoC connection parameters.  ATT PDUs
 * travel in both directions, so the usable ATT_MTU is the smaller of
 * SO_L2CAP_IMTU and SO_L2CAP_OMTU, not from an ATT_EXCHANGE_MTU_REQ, which is
 * only valid on
 * the fixed unenhanced ATT bearer (Core Spec Vol 3 Part G §5.3.1).
 *
 * Returns 0 on success (bearer added); -1 with errno=ENOSPC if the bearer
 * set is full, in which case the caller retains ownership of fd.
 */
int
att_eatt_add_bearer(struct att_conn *ac, int fd)
{
	struct timeval tv;
	uint16_t imtu, omtu, bearer_mtu;
	int idx;

	/*
	 * Do not attach a bearer whose negotiated channel parameters cannot be
	 * established.  Substituting 64 here can truncate a larger inbound PDU
	 * or emit a PDU the peer's smaller outbound MTU cannot carry.
	 */
	if (att_eatt_query_mtu(fd, &imtu, &omtu) < 0)
		return (-1);
	if (imtu < ATT_EATT_MIN_MTU || omtu < ATT_EATT_MIN_MTU) {
		errno = EPROTO;
		return (-1);
	}
	bearer_mtu = imtu < omtu ? imtu : omtu;

	att_bearers_lock(ac);
	if (ac->eatt_count >= ATT_MAX_EATT_BEARERS) {
		att_bearers_unlock(ac);
		LOG_ATT(1, "EATT: add rejected, max bearers reached");
		errno = ENOSPC;
		return (-1);
	}

	/* Per-bearer flow control: one outstanding request at a time. */
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		warn("setsockopt SO_RCVTIMEO");

	idx = ac->eatt_count;
	ac->eatt[idx].fd = fd;
	ac->eatt[idx].active = true;
	ac->eatt[idx].pending = 0;

	ac->eatt[idx].mtu = bearer_mtu;

	ac->eatt_count++;
	att_bearers_unlock(ac);

	LOG_ATT(1, "EATT: bearer fd=%d added (total=%d mtu=%d)",
	    fd, ac->eatt_count, ac->eatt[idx].mtu);

	return (0);
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
	int fd;

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

	if (att_eatt_add_bearer(ac, fd) < 0) {
		close(fd);
		return (-1);
	}
	return (0);
}

/*
 * Remove a single EATT bearer identified by its fd (e.g. the peer closed
 * just that L2CAP CoC channel, or a transaction on it timed out).  Closes
 * the socket and compacts the bearer array so att_eatt_select_bearer()'s
 * [0, eatt_count) scan stays dense.  No-op if fd is not a current bearer.
 */
void
att_eatt_remove_bearer(struct att_conn *ac, int fd)
{
	int i;

	att_bearers_lock(ac);
	for (i = 0; i < ac->eatt_count; i++) {
		if (ac->eatt[i].fd != fd)
			continue;
		if (ac->write_cmd_bearer_pinned &&
		    ac->write_cmd_bearer_fd == fd)
			ac->write_cmd_bearer_pinned = false;
		close(ac->eatt[i].fd);
		ac->eatt_count--;
		/* Move the last bearer into the vacated slot. */
		if (i != ac->eatt_count)
			ac->eatt[i] = ac->eatt[ac->eatt_count];
		ac->eatt[ac->eatt_count].fd = -1;
		ac->eatt[ac->eatt_count].active = false;
		ac->eatt[ac->eatt_count].pending = 0;
		att_bearers_unlock(ac);
		return;
	}
	att_bearers_unlock(ac);
}

/*
 * Close all EATT bearers on an ATT connection.
 */
void
att_close_eatt(struct att_conn *ac)
{
	int i;

	att_bearers_lock(ac);
	/* Closing EATT invalidates a command pin that names any EATT fd. */
	if (ac->write_cmd_bearer_pinned &&
	    ac->write_cmd_bearer_fd != ac->fd)
		ac->write_cmd_bearer_pinned = false;
	for (i = 0; i < ac->eatt_count; i++) {
		if (ac->eatt[i].fd >= 0) {
			close(ac->eatt[i].fd);
			ac->eatt[i].fd = -1;
		}
		ac->eatt[i].active = false;
	}
	ac->eatt_count = 0;
	att_bearers_unlock(ac);
}
