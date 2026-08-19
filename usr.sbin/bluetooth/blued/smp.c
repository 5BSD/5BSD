/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * SMP (Security Manager Protocol) for LE pairing.
 *
 * Implements LE Legacy Pairing with "Just Works" and passkey entry methods.
 * Runs over L2CAP CID 0x0006.  Key distribution stores LTK and IRK.
 *
 * Crypto uses the c1 confirm generation function and s1 key generation
 * function per Core Spec Vol 3 Part H Section 2.2.3-2.2.4.
 *
 * Encryption is triggered via HCI LE_Start_Encryption on the raw HCI socket.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/endian.h>
#include <time.h>

#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netgraph/bluetooth/include/ng_hci.h>
#include <netgraph/bluetooth/include/ng_l2cap.h>

#include "att.h"
#include "att_server.h"
#include "ble_util.h"
#include "blued_probes.h"
#include "hci_log.h"
#include "hci_util.h"
#include "smp.h"
#include "smp_internal.h"

/*
 * S-m11: BLUED_DEBUG_KEYS gates blued_hexdump() calls that print live key
 * material (e.g. the derived STK) to the log.  It is a developer-only switch
 * and MUST remain undefined for any shipped build; it is not set by the
 * Makefile or any header, so release builds never dump keys.  As a
 * belt-and-braces safety net, refuse to compile if it is ever enabled in a
 * release (NDEBUG) build.
 */
#if defined(BLUED_DEBUG_KEYS) && defined(NDEBUG)
#error "BLUED_DEBUG_KEYS dumps key material and must never be set in a release build"
#endif

/*
 * Logged send/recv helpers for SMP — log PDUs as L2CAP on CID 0x0006
 * to BTSnoop when capture is active.
 */
ssize_t
smp_log_send(struct smp_conn *sc, const void *buf, size_t len)
{
	ssize_t n;

	do {
		n = send(sc->fd, buf, len, MSG_EOR);
	} while (n < 0 && errno == EINTR);
	if (n > 0 && hci_log_enabled())
		hci_log_l2cap(sc->con_handle, 0x0006,
		    buf, n, false);
	/*
	 * Every outbound SMP PDU funnels through smp_log_send, so a single
	 * tx probe here observes the whole handshake carrying opcode + length
	 * (never payload).
	 */
	if (n >= 1)
		BLUED_PROBE_SMP_PDU_TX(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    ((const uint8_t *)buf)[0], (int)n);
	/*
	 * Every Pairing Failed (Core Spec Vol 3 Part H §3.5.5) send site in
	 * smp.c / smp_sc.c / smp_legacy.c funnels through smp_log_send, so a
	 * single probe here observes them all carrying the real SMP reason
	 * byte.
	 */
	if (n >= 2 && ((const uint8_t *)buf)[0] == SMP_PAIRING_FAILED)
		BLUED_PROBE_AUTH_FAIL(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    ((const uint8_t *)buf)[1]);
	return (n);
}

ssize_t
smp_log_recv(struct smp_conn *sc, void *buf, size_t len)
{
	struct sockaddr_storage ss;
	struct iovec iov;
	struct msghdr msg;
	socklen_t sslen;
	int family;
	ssize_t n;

	sslen = sizeof(ss);
	family = AF_BLUETOOTH;
	if (getsockname(sc->fd, (struct sockaddr *)&ss, &sslen) == 0)
		family = ss.ss_family;
	iov.iov_base = buf;
	iov.iov_len = len;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	do {
		n = recvmsg(sc->fd, &msg, 0);
	} while (n < 0 && errno == EINTR);
	/*
	 * SMP uses a sequenced-packet fixed channel.  Plain recv() hides an
	 * oversized record by returning only the supplied buffer length, which
	 * can turn a malformed PDU into an apparently valid fixed-size packet.
	 */
	if (n >= 0 && smp_record_is_truncated(family, msg.msg_flags)) {
		errno = EMSGSIZE;
		return (-1);
	}
	if (n > 0 && hci_log_enabled())
		hci_log_l2cap(sc->con_handle, 0x0006,
		    buf, n, true);
	/*
	 * Every inbound SMP PDU funnels through smp_log_recv: emit an rx
	 * probe (opcode + length) and, for a peer Pairing Failed, a dedicated
	 * fail:rx probe carrying the spec reason code.
	 */
	if (n >= 1) {
		BLUED_PROBE_SMP_PDU_RX(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    ((const uint8_t *)buf)[0], (int)n);
		if (n >= 2 && ((const uint8_t *)buf)[0] == SMP_PAIRING_FAILED)
			BLUED_PROBE_SMP_FAIL_RX(
			    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
			    ((const uint8_t *)buf)[1]);
	}

	/*
	 * SMP timeout: Core Spec Vol 3 Part H Section 3.4 requires the
	 * link to be disconnected when the SMP timeout expires.
	 */
	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
		BLUED_PROBE_SMP_TIMEOUT(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
		LOG_SMP(1, "SMP timeout, disconnecting handle=%u",
		    sc->con_handle);
		BLUED_LOG_SECURITY("SMP timeout "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->con_handle);
		if (sc->hci_fd >= 0) {
			ng_hci_discon_cp dp;

			memset(&dp, 0, sizeof(dp));
			dp.con_handle = htole16(sc->con_handle);
			dp.reason = 0x13; /* Remote User Terminated */
			hci_send_raw_cmd(sc->hci_fd,
			    NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL,
			    NG_HCI_OCF_DISCON), &dp, sizeof(dp));
		}
	}
	return (n);
}

bool
smp_record_is_truncated(int family, int msg_flags)
{

	/* AF_UNIX is the byte-stream-like unit-test transport on FreeBSD. */
	return (family != AF_UNIX && (msg_flags & MSG_TRUNC) != 0);
}

/*
 * Seed the de-hardcoded SMP AuthReq / key-distribution policy to the historical
 * literal defaults.  Called from smp_open()/smp_open_accepted() after the
 * memset(), so a freshly opened connection behaves exactly as before unless the
 * caller (the daemon, from config or a runtime setter) overrides a field.
 */
void
smp_seed_policy_defaults(struct smp_conn *sc)
{

	sc->require_mitm = true;
	sc->bondable = true;
	sc->sc_enabled = true;
	sc->keypress = true;
	sc->our_key_dist = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_LINK_KEY;
	sc->their_key_dist = SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
	    SMP_KEY_DIST_LINK_KEY;
}

/*
 * Assemble the AuthReq octet of a Pairing Request/Response from the connection
 * policy fields (Core Spec Vol 3 Part H §3.5.1).  CT2 (cross-transport key
 * derivation h7 selection, §2.4.2.4) is always advertised, matching the prior
 * hardcoded value.
 */
uint8_t
smp_build_authreq(const struct smp_conn *sc)
{

	return ((uint8_t)((sc->bondable ? SMP_AUTH_BONDING : 0) |
	    (sc->require_mitm ? SMP_AUTH_MITM : 0) |
	    (sc->sc_enabled ? SMP_AUTH_SC : 0) |
	    (sc->keypress ? SMP_AUTH_KEYPRESS : 0) |
	    SMP_AUTH_CT2));
}

/*
 * Send a Keypress Notification PDU.
 * Core Spec Vol 3 Part H Section 3.5.8
 *
 * Only sent when both sides indicated Keypress Notification support
 * (SMP_AUTH_KEYPRESS bit) in their AuthReq fields.
 */
static int
smp_send_keypress(struct smp_conn *sc, uint8_t type)
{
	uint8_t pdu[2];

	pdu[0] = SMP_PAIRING_KEYPRESS_NOTIFY;
	pdu[1] = type;
	return (smp_log_send(sc, pdu, sizeof(pdu)) < 0 ? -1 : 0);
}

static const char *
smp_keypress_type_str(uint8_t type)
{
	switch (type) {
	case SMP_KEYPRESS_STARTED:		return ("started");
	case SMP_KEYPRESS_DIGIT_ENTERED:	return ("digit entered");
	case SMP_KEYPRESS_DIGIT_ERASED:		return ("digit erased");
	case SMP_KEYPRESS_CLEARED:		return ("cleared");
	case SMP_KEYPRESS_COMPLETED:		return ("completed");
	default:				return ("unknown");
	}
}

/*
 * Receive a PDU from the SMP socket, transparently consuming and
 * logging any Keypress Notification PDUs that arrive first.
 *
 * Per Core Spec Vol 3 Part H Section 3.5.8, the device performing
 * passkey entry sends Keypress Notifications to the displaying side
 * before or during the confirm exchange.  These are informational
 * and do not alter protocol state.
 *
 * Returns the number of bytes read into buf, or -1 on error.
 *
 * Shared with the SC Passkey Entry paths in smp_sc.c (declared in
 * smp_internal.h) so both legacy and SC passkey exchanges consume peer
 * Keypress Notifications instead of rejecting them as out-of-sequence.
 */
ssize_t
smp_recv_skip_keypress(struct smp_conn *sc, uint8_t *buf, size_t len)
{
	ssize_t n;
	int loops = 0;

	for (;;) {
		if (++loops > 100) {
			warnx("too many keypress notifications");
			return (-1);
		}
		n = smp_log_recv(sc, buf, len);
		if (n < 1)
			return (n);
		if (buf[0] != SMP_PAIRING_KEYPRESS_NOTIFY)
			return (n);
		/*
		 * A peer can hold the session open indefinitely by dribbling a
		 * Keypress Notification just inside each per-message SO_RCVTIMEO
		 * (Core Spec Vol 3 Part H §3.5.8 flooding).  Enforce the
		 * cumulative §3.4 pairing deadline before consuming the next one:
		 * on expiry the link is force-disconnected and we return the
		 * timeout sentinel so no further PDU is emitted.
		 */
		if (smp_pairing_timed_out(sc))
			return (SMP_RECV_TIMED_OUT);
		/* Log and discard keypress notification */
		if (n >= 2) {
			LOG_SMP(1, "recv keypress notification: %s (0x%02x)",
			    smp_keypress_type_str(buf[1]), buf[1]);
			/*
			 * Surface the inbound keypress to the app (Core Spec Vol
			 * 3 Part H §3.5.8).  Previously received-and-dropped; now
			 * delivered to a registered sink so a display-side UI can
			 * reflect the peer's passkey entry progress.
			 *
			 * S-m7: gate delivery on keypress having been negotiated
			 * by BOTH sides (preq[3]&pres[3] & SMP_AUTH_KEYPRESS),
			 * captured in sc->kp_negotiated during Pairing Feature
			 * exchange.  An inbound keypress that was never negotiated
			 * is consumed (for wire-sequence tolerance) but not
			 * surfaced.  Core Spec Vol 3 Part H §3.5.8.
			 */
			if (sc->kp_negotiated && sc->keypress_cb != NULL)
				sc->keypress_cb(buf[1], sc->keypress_cb_arg);
		} else
			LOG_SMP(1, "recv keypress notification (malformed)");
	}
}

/*
 * Determine association model from IO capabilities.
 * Core Spec Vol 3 Part H Table 2.8
 */
int
smp_select_model(uint8_t init_io, uint8_t resp_io, bool sc)
{
	/* Table 2.8 mapping (initiator rows, responder columns) */
	static const uint8_t legacy_table[5][5] = {
		/* Resp: DispOnly  DispYN    KbdOnly   NoIO      KbdDisp */
	/* I:DispOnly */ { 0,      0,        1,        0,        1       },
	/* I:DispYN   */ { 0,      0,        1,        0,        1       },
	/* I:KbdOnly  */ { 1,      1,        1,        0,        1       },
	/* I:NoIO     */ { 0,      0,        0,        0,        0       },
	/* I:KbdDisp  */ { 1,      1,        1,        0,        1       },
	};
	static const uint8_t sc_table[5][5] = {
		/* Resp: DispOnly  DispYN    KbdOnly   NoIO      KbdDisp */
	/* I:DispOnly */ { 0,      0,        1,        0,        1       },
	/* I:DispYN   */ { 0,      2,        1,        0,        2       },
	/* I:KbdOnly  */ { 1,      1,        1,        0,        1       },
	/* I:NoIO     */ { 0,      0,        0,        0,        0       },
	/* I:KbdDisp  */ { 1,      2,        1,        0,        2       },
	};

	if (init_io > 4 || resp_io > 4)
		return (SMP_MODEL_INVALID);

	return (sc ? sc_table[init_io][resp_io] :
	    legacy_table[init_io][resp_io]);
}

/*
 * For the Passkey Entry model, decide whether this device displays the
 * passkey or inputs it, per Core Spec Vol 3 Part H Table 2.8.  The role is a
 * function of both devices' IO capabilities and, only when both are fully
 * capable, the GAP role:
 *
 *   - A device can display iff it is DisplayOnly, DisplayYesNo or
 *     KeyboardDisplay, and can input a passkey iff it is KeyboardOnly or
 *     KeyboardDisplay.
 *   - If we cannot display, we input (the both-KeyboardOnly case has both
 *     sides input the same user-chosen passkey).
 *   - If the peer cannot input, the peer must display and we input.
 *   - If the peer can input but cannot display, we display.
 *   - If both sides are fully capable (both KeyboardDisplay), the tie is
 *     broken in favour of the initiator displaying.
 *
 * Passkey Entry is only selected for combinations where exactly one side
 * displays and the other inputs (or both input), so these branches cover
 * every reachable case.
 */
bool
smp_passkey_we_display(uint8_t our_io, uint8_t peer_io, bool is_initiator)
{
	bool we_can_display = (our_io == SMP_IO_DISPLAY_ONLY ||
	    our_io == SMP_IO_DISPLAY_YESNO ||
	    our_io == SMP_IO_KEYBOARD_DISPLAY);
	bool we_can_input = (our_io == SMP_IO_KEYBOARD_ONLY ||
	    our_io == SMP_IO_KEYBOARD_DISPLAY);
	bool peer_can_display = (peer_io == SMP_IO_DISPLAY_ONLY ||
	    peer_io == SMP_IO_DISPLAY_YESNO ||
	    peer_io == SMP_IO_KEYBOARD_DISPLAY);
	bool peer_can_input = (peer_io == SMP_IO_KEYBOARD_ONLY ||
	    peer_io == SMP_IO_KEYBOARD_DISPLAY);

	if (!we_can_display)
		return (false);		/* we input (or both-KbdOnly input) */
	if (!peer_can_input)
		return (false);		/* peer must display; we input */
	if (!we_can_input || !peer_can_display)
		return (true);		/* only we can display */
	return (is_initiator);		/* both fully capable: initiator shows */
}

/*
 * Minimum-security-for-pairing policy decision (Core Spec Vol 3 Part H
 * §2.3.5.1, Part C §10.2.1).  Levels are cumulative: 'auth' requires an
 * MITM-authenticated association (rejecting Just Works); 'sc' additionally
 * requires LE Secure Connections (rejecting legacy) and, being the strongest
 * level, remains authenticated via the 'auth' clause.  'enc'/'none' impose no
 * association-model floor because every completed LE pairing yields an
 * encrypted link.
 */
bool
smp_policy_permits(uint8_t floor, bool authenticated, bool use_sc)
{

	if (floor >= SMP_SEC_AUTH && !authenticated)
		return (false);
	if (floor >= SMP_SEC_SC && !use_sc)
		return (false);
	return (true);
}

/*
 * Generate 16 random bytes using /dev/urandom.
 */
int
smp_random(uint8_t *buf, size_t len)
{
	/* arc4random_buf is always available on FreeBSD */
	arc4random_buf(buf, len);
	return (0);
}

/*
 * Test-only monotonic-clock seam.  See smp_internal.h.  In production this
 * pointer is NULL and smp_now() reads the real CLOCK_MONOTONIC, so the
 * timing behaviour of the pairing timer and rate limiter is unchanged.  A
 * test installs a hook to drive a deterministic virtual clock.
 */
smp_clock_hook_t smp_clock_hook = NULL;

void
smp_now(struct timespec *ts)
{

	if (smp_clock_hook != NULL)
		smp_clock_hook(ts);	/* test-only virtual clock */
	else
		clock_gettime(CLOCK_MONOTONIC, ts);	/* production path */
}

/*
 * Compare an explicit monotonic instant with the cumulative pairing start.
 * Kept separate from the clock read so the exact Core §3.4 boundary can be
 * tested without sleeping or duplicating this arithmetic in a test.
 */
bool
smp_pairing_expired_at(const struct timespec *start, const struct timespec *now)
{

	return ((now->tv_sec - start->tv_sec) > 30 ||
	    ((now->tv_sec - start->tv_sec) == 30 &&
	     now->tv_nsec >= start->tv_nsec));
}

/* Check whether the Core §3.4 30-second cumulative timer has expired. */
bool
smp_pairing_expired(const struct timespec *start)
{
	struct timespec now;

	smp_now(&now);
	return (smp_pairing_expired_at(start, &now));
}

/*
 * Arm the cumulative pairing timer (Core Spec Vol 3 Part H §3.4) once.
 *
 * The deadline is established when the pairing procedure begins (Pairing
 * Request as initiator, Pairing Response as responder) and must remain a
 * SINGLE authoritative instant for the whole handshake — Phase 2 must not
 * reset it.  Idempotent: the first caller wins, later callers (e.g. an SC
 * sub-flow reached via smp_pair) leave the earlier deadline intact.  Called
 * at the entry of each of the five flows so direct-call unit tests that
 * invoke a sub-flow without smp_pair()/smp_respond() still get an armed
 * timer instead of an all-zero (already-expired) pair_start.
 */
void
smp_pairing_arm(struct smp_conn *sc)
{

	if (!sc->pair_armed) {
		smp_now(&sc->pair_start);
		sc->pair_armed = true;
	}
}

/*
 * Enforce the cumulative pairing deadline (Core Spec Vol 3 Part H §3.4).
 *
 * Returns false while the timer is unarmed or still within budget.  On
 * expiry the spec forbids sending any further SMP PDU and requires the
 * physical link to be dropped, so this forces the HCI disconnect and returns
 * true WITHOUT emitting a Pairing Failed.  The disconnect uses the same raw
 * HCI Disconnect path as the per-message SO_RCVTIMEO handler in
 * smp_log_recv(); it is stubbed out in the unit tests.
 */
bool
smp_pairing_timed_out(struct smp_conn *sc)
{

	if (!sc->pair_armed || !smp_pairing_expired(&sc->pair_start))
		return (false);

	BLUED_PROBE_SMP_TIMEOUT(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	LOG_SMP(1, "SMP pairing timer expired (§3.4), disconnecting handle=%u",
	    sc->con_handle);
	BLUED_LOG_SECURITY("SMP pairing timeout "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);
	if (sc->hci_fd >= 0) {
		ng_hci_discon_cp dp;

		memset(&dp, 0, sizeof(dp));
		dp.con_handle = htole16(sc->con_handle);
		dp.reason = 0x13;	/* Remote User Terminated Connection */
		hci_send_raw_cmd(sc->hci_fd,
		    NG_HCI_OPCODE(NG_HCI_OGF_LINK_CONTROL, NG_HCI_OCF_DISCON),
		    &dp, sizeof(dp));
	}
	errno = ETIMEDOUT;
	return (true);
}

/*
 * Timeout-aware recv: enforce the §3.4 deadline before AND after the recv.
 * Returns SMP_RECV_TIMED_OUT (link already disconnected, no PDU to send) on
 * expiry, otherwise the smp_log_recv() result.
 */
ssize_t
smp_recv_timed(struct smp_conn *sc, void *buf, size_t len)
{
	ssize_t n;

	if (smp_pairing_timed_out(sc))
		return (SMP_RECV_TIMED_OUT);
	n = smp_log_recv(sc, buf, len);
	if (smp_pairing_timed_out(sc))
		return (SMP_RECV_TIMED_OUT);
	return (n);
}

/*
 * Timeout-aware keypress-skipping recv: as smp_recv_timed() but transparently
 * consumes Keypress Notifications (which themselves re-check the deadline).
 */
ssize_t
smp_recv_timed_kp(struct smp_conn *sc, uint8_t *buf, size_t len)
{
	ssize_t n;

	if (smp_pairing_timed_out(sc))
		return (SMP_RECV_TIMED_OUT);
	n = smp_recv_skip_keypress(sc, buf, len);
	if (n == SMP_RECV_TIMED_OUT)
		return (n);
	if (smp_pairing_timed_out(sc))
		return (SMP_RECV_TIMED_OUT);
	return (n);
}

/*
 * Rate-limit pairing attempts per address to mitigate brute-force attacks.
 * Core Spec Vol 3 Part H Section 3.4: "A device in a Pairing mode shall
 * not allow ... multiple pairing attempts without appropriate delays."
 *
 * Track the most recent SMP_RATE_LIMIT_SLOTS addresses that have attempted
 * pairing.  If the same address attempts more than SMP_RATE_LIMIT_MAX times
 * within SMP_RATE_LIMIT_WINDOW seconds, reject with Repeated Attempts.
 *
 * Additionally, enforce a global rate limit across all addresses to prevent
 * bypass via address rotation: reject if total pairing attempts across all
 * addresses exceed SMP_RATE_LIMIT_GLOBAL_MAX within the window.
 */
#define SMP_RATE_LIMIT_SLOTS		32
#define SMP_RATE_LIMIT_MAX		3
#define SMP_RATE_LIMIT_WINDOW		60
#define SMP_RATE_LIMIT_MAX_WINDOW	900
#define SMP_RATE_LIMIT_GLOBAL_MAX	30

struct smp_rate_entry {
	uint8_t		addr[6];
	uint8_t		addr_type;
	int		count;
	uint8_t		failures;	/* consecutive failures for backoff */
	time_t		first;
};

static struct smp_rate_entry smp_rate_table[SMP_RATE_LIMIT_SLOTS];

/* Global rate limiter: total pairing attempts across all addresses */
static int	smp_rate_global_count;
static time_t	smp_rate_global_first;

/*
 * The rate table and the global counters are touched by every pairing
 * session.  Under the setup-thread model concurrent sessions race on the
 * counts and on slot eviction, so all accesses are serialized by this
 * mutex.  It is a leaf lock: smp_rate_check() resolves any RPA identity under
 * the bond-DB lock first and drops it before acquiring this one, so the two
 * locks never nest.
 */
static pthread_mutex_t smp_rate_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Compute the effective lockout window for a given failure count.
 * After SMP_RATE_LIMIT_MAX attempts, the window doubles for each
 * subsequent failure: 60s, 120s, 240s, ... capped at 900s.
 */
static time_t
smp_rate_window(uint8_t failures)
{
	time_t window;
	int doublings;

	if (failures <= SMP_RATE_LIMIT_MAX)
		return (SMP_RATE_LIMIT_WINDOW);

	doublings = failures - SMP_RATE_LIMIT_MAX;
	if (doublings > 4)
		doublings = 4;	/* cap shift to avoid overflow */
	window = SMP_RATE_LIMIT_WINDOW << doublings;
	if (window > SMP_RATE_LIMIT_MAX_WINDOW)
		window = SMP_RATE_LIMIT_MAX_WINDOW;
	return (window);
}

/*
 * Check and update the pairing rate limiter.
 * Returns 0 if the attempt is allowed, -1 if rate-limited.
 */
static int __attribute__((no_thread_safety_analysis))
smp_rate_check(const uint8_t *addr, uint8_t addr_type, struct smp_bond_db *db)
{
	uint8_t key_addr[6];
	uint8_t key_type;
	time_t now;
	int i, rc, victim;
	long throttle_us = 0;
	struct timespec ts;

	memcpy(key_addr, addr, 6);
	key_type = addr_type;

	/*
	 * Rate-limit per resolved identity where available.  A bonded
	 * peer that rotates its Resolvable Private Address would otherwise mint
	 * a fresh rate slot on every attempt, evading the per-address cap and
	 * evicting other slots.  Resolve the RPA against stored IRKs under the
	 * bond-DB lock and copy out the STABLE identity address; the returned
	 * bond pointer is never used after the lock is dropped, and the
	 * bond lock is released before the rate lock is taken so the two never
	 * nest.
	 */
	if (db != NULL && addr_type == BDADDR_LE_RANDOM) {
		struct smp_bond *b;

		if (db->lock != NULL)
			pthread_mutex_lock(db->lock);
		b = smp_find_bond(db, addr, addr_type);
		if (b != NULL) {
			memcpy(key_addr, b->addr, 6);
			key_type = b->addr_type;
		}
		if (db->lock != NULL)
			pthread_mutex_unlock(db->lock);
	}

	pthread_mutex_lock(&smp_rate_lock);

	/* Use monotonic clock — immune to NTP/settimeofday jumps */
	smp_now(&ts);
	now = ts.tv_sec;

	/* Proactively clear expired entries to reclaim slots */
	for (i = 0; i < SMP_RATE_LIMIT_SLOTS; i++) {
		if (smp_rate_table[i].count == 0)
			continue;
		if (now - smp_rate_table[i].first >
		    smp_rate_window(smp_rate_table[i].failures))
			smp_rate_table[i].count = 0;
	}

	/*
	 * Global rate limit: DEGRADE rather than hard-deny.  A host-wide
	 * hard rejection once total attempts exceed the cap would let a single
	 * peer deny pairing to EVERY device with ~31 requests/min.  Instead,
	 * when the global window saturates, apply a bounded throttle delay that
	 * grows with the excess but still admit the attempt; the per-identity
	 * limit below remains the authoritative gate.
	 */
	if (smp_rate_global_count > 0 &&
	    now - smp_rate_global_first <= SMP_RATE_LIMIT_WINDOW) {
		smp_rate_global_count++;
		if (smp_rate_global_count > SMP_RATE_LIMIT_GLOBAL_MAX) {
			int excess = smp_rate_global_count -
			    SMP_RATE_LIMIT_GLOBAL_MAX;

			/* 10 ms per excess attempt, capped at 250 ms */
			throttle_us = (long)excess * 10000L;
			if (throttle_us > 250000L)
				throttle_us = 250000L;
			BLUED_LOG_SECURITY("pairing global rate pressure "
			    "(%d attempts in %d sec), throttling %ld ms",
			    smp_rate_global_count,
			    (int)(now - smp_rate_global_first),
			    throttle_us / 1000);
		}
	} else {
		/* Window expired or first attempt — reset */
		smp_rate_global_count = 1;
		smp_rate_global_first = now;
	}

	rc = 0;

	/* Look for existing entry (keyed on the resolved identity) */
	for (i = 0; i < SMP_RATE_LIMIT_SLOTS; i++) {
		if (smp_rate_table[i].count == 0)
			continue;
		if (smp_rate_table[i].addr_type != key_type ||
		    memcmp(smp_rate_table[i].addr, key_addr, 6) != 0)
			continue;

		/* Found matching entry — check window with backoff */
		{
			time_t window = smp_rate_window(
			    smp_rate_table[i].failures);
			if (now - smp_rate_table[i].first > window) {
				/* Window expired, reset count but keep
				 * failure history for backoff */
				smp_rate_table[i].count = 1;
				smp_rate_table[i].first = now;
				goto done;
			}
		}
		smp_rate_table[i].count++;
		if (smp_rate_table[i].count > SMP_RATE_LIMIT_MAX) {
			/*
			 * Saturating increment: `failures` is uint8_t, so the
			 * former `if (failures > 255)` guard was dead and the
			 * bare ++ wrapped 255->0, resetting the anti-brute-force
			 * backoff.  Clamp at 255 instead (K-low).
			 */
			if (smp_rate_table[i].failures < 255)
				smp_rate_table[i].failures++;
			rc = -1;
		}
		goto done;
	}

	/*
	 * No existing entry — find a free slot, else evict the LEAST valuable
	 * slot: unauthenticated address churn must not evict a tracked
	 * offender.  Prefer a free slot; else the oldest slot with NO recorded
	 * failures; only if every slot is an offender evict the oldest offender.
	 */
	{
		int free_slot = -1, clean_oldest = -1, any_oldest = 0;
		time_t clean_time = 0, any_time = smp_rate_table[0].first;

		for (i = 0; i < SMP_RATE_LIMIT_SLOTS; i++) {
			if (smp_rate_table[i].count == 0) {
				free_slot = i;
				break;
			}
			if (smp_rate_table[i].first < any_time) {
				any_time = smp_rate_table[i].first;
				any_oldest = i;
			}
			if (smp_rate_table[i].failures == 0 &&
			    (clean_oldest < 0 ||
			    smp_rate_table[i].first < clean_time)) {
				clean_time = smp_rate_table[i].first;
				clean_oldest = i;
			}
		}
		if (free_slot >= 0)
			victim = free_slot;
		else if (clean_oldest >= 0)
			victim = clean_oldest;
		else
			victim = any_oldest;
	}

	memcpy(smp_rate_table[victim].addr, key_addr, 6);
	smp_rate_table[victim].addr_type = key_type;
	smp_rate_table[victim].count = 1;
	smp_rate_table[victim].failures = 0;
	smp_rate_table[victim].first = now;

done:
	pthread_mutex_unlock(&smp_rate_lock);

	/*
	 * Apply any global-pressure throttle outside the lock and only for an
	 * admitted attempt.  This delays (degrades) rather than denies.
	 */
	if (rc == 0 && throttle_us > 0) {
		struct timespec d;

		d.tv_sec = throttle_us / 1000000L;
		d.tv_nsec = (throttle_us % 1000000L) * 1000L;
		nanosleep(&d, NULL);
	}
	return (rc);
}

/*
 * Open SMP connection to a BLE device.
 */
int
smp_open(struct smp_conn *sc, const uint8_t *addr, uint8_t addr_type,
    const uint8_t *local_addr, uint8_t local_addr_type,
    int hci_fd, uint16_t con_handle, struct smp_bond_db *db)
{
	struct sockaddr_l2cap sa;

	memset(sc, 0, sizeof(*sc));
	sc->fd = -1;
	sc->hci_fd = hci_fd;
	sc->con_handle = con_handle;
	sc->remote_addr_type = addr_type;
	sc->bond_db = db;
	memcpy(sc->remote_addr, addr, 6);
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_addr_type;
	sc->io_capability = SMP_IO_KEYBOARD_DISPLAY;  /* default */
	/*
	 * Default minimum encryption key size = 16 bytes (128 bits).
	 * This is intentional for security: it mitigates the KNOB attack
	 * (CVE-2019-9506) which exploits negotiation of short key sizes.
	 * For interop with legacy devices that cannot negotiate 16-byte
	 * keys, min_key_size can be configured lower via blued.conf
	 * "security { min_key_size = 7; }" (range: 7-16).
	 */
	sc->min_key_size = 16;
	/* No masking until Phase 1 negotiates a size (Vol 3 Part H §2.3.4). */
	sc->neg_key_size = 16;
	smp_seed_policy_defaults(sc);

	sc->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (sc->fd < 0)
		return (-1);

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;

	if (bind(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		sc->fd = -1;
		return (-1);
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	memcpy(&sa.l2cap_bdaddr, addr, sizeof(sa.l2cap_bdaddr));
	sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
	sa.l2cap_bdaddr_type = addr_type;

	if (connect(sc->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(sc->fd);
		sc->fd = -1;
		return (-1);
	}

	/*
	 * Lock clofork on the SMP socket.  Active pairing sessions
	 * carry ephemeral key material (ECDH private key, nonces,
	 * confirm values) that must not be shared with forked children.
	 * The socket is already created with SOCK_CLOFORK; this locks
	 * the flag so it cannot be cleared.
	 */
	(void)cap_clofork_limit(sc->fd, CAP_CLOFORK_LOCKED);

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
	}

	return (0);
}

void
smp_close(struct smp_conn *sc)
{
	if (sc->fd >= 0) {
		close(sc->fd);
	}
	/* Zero entire struct to scrub all residual pairing data */
	explicit_bzero(sc, sizeof(*sc));
	sc->fd = -1;
	sc->hci_fd = -1;
}

/*
 * LE Legacy Pairing — "Just Works" method.
 *
 * Sequence:
 *  1. Send Pairing Request
 *  2. Receive Pairing Response
 *  3. Generate random, compute confirm using TK=0
 *  4. Exchange Pairing Confirm
 *  5. Exchange Pairing Random
 *  6. Verify confirm values
 *  7. Derive STK = s1(TK, Srand, Mrand)
 *  8. Start encryption via HCI LE_Start_Encryption
 *  9. Receive key distribution (LTK, IRK)
 */
int
smp_pair(struct smp_conn *sc)
{
	uint8_t preq[7], pres[7];
	uint8_t tk[16];		/* Temporary Key — 0 for Just Works */
	uint8_t mrand[16];	/* Our random */
	uint8_t srand[16];	/* Peer random */
	uint8_t mconfirm[16], sconfirm[16], verify[16];
	uint8_t stk[16];
	uint8_t pdu[65];
	ssize_t n;
	uint8_t iat, rat;
	int ret = -1;
	bool legacy_mitm = false;

	/*
	 * Arm the single cumulative §3.4 pairing deadline at the very start of
	 * the initiator procedure (before the Pairing Request), authoritative
	 * for the whole handshake including any SC Phase 2 sub-flow.
	 */
	smp_pairing_arm(sc);

	/*
	 * Rate-limit pairing attempts on the initiator side as well.
	 * Core Spec Vol 3 Part H Section 3.4 recommends rate-limiting
	 * on both sides to prevent brute-force attacks on passkey values.
	 */
	if (smp_rate_check(sc->remote_addr, sc->remote_addr_type, sc->bond_db) < 0) {
		BLUED_LOG_SECURITY("pairing rate-limited (initiator) "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0]);
		errno = EACCES;
		return (-1);
	}

	memset(tk, 0, sizeof(tk));

	/* SMP address types: 0=public, 1=random */
	iat = (sc->local_addr_type == BDADDR_LE_RANDOM) ?
	    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;
	rat = (sc->remote_addr_type == BDADDR_LE_RANDOM) ?
	    SMP_ID_ADDR_STATIC_RANDOM : SMP_ID_ADDR_PUBLIC;

	/*
	 * Step 1: Send Pairing Request
	 * Format: [opcode, IO cap, OOB, AuthReq, max_key_size,
	 *          init_key_dist, resp_key_dist]
	 */
	preq[0] = SMP_PAIRING_REQUEST;
	preq[1] = sc->io_capability;
	preq[2] = (sc->oob != NULL &&
	    (sc->oob->legacy != NULL || sc->oob->sc != NULL)) ?
	    0x01 : 0x00;
	preq[3] = smp_build_authreq(sc);
	preq[4] = 16;				/* Max encryption key size */
	/*
	 * InitKeyDist = keys we (the initiator) will distribute;
	 * RespKeyDist = keys we request the responder to distribute
	 * (Core Spec Vol 3 Part H §3.6.1).  Seeded to the historical
	 * ENC|ID|SIGN full mask so this stays a no-op unless configured.
	 */
	preq[5] = sc->our_key_dist;
	preq[6] = sc->their_key_dist;

	if (smp_log_send(sc, preq, sizeof(preq)) < 0)
		return (-1);
	LOG_SMP(1, "pairing request sent IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Step 2: Receive Pairing Response.  On §3.4 timeout the link is
	 * already dropped and no PDU may be sent; abort silently.
	 */
	n = smp_recv_timed(sc, pres, sizeof(pres));
	if (n == SMP_RECV_TIMED_OUT)
		return (-1);
	if (n < 1) {
		errno = EPROTO;
		return (-1);
	}

	/*
	 * A Pairing Failed (Core Spec Vol 3 Part H §3.5.5) is a 2-octet PDU;
	 * dispatch on the opcode before enforcing the 7-octet Pairing Response
	 * length, otherwise a spec-legal peer rejection is dropped as EPROTO
	 * instead of surfacing as the EACCES rejection.
	 */
	if (pres[0] == SMP_PAIRING_FAILED && n >= 2) {
		warnx("SMP: peer sent pairing failed reason=%02x", pres[1]);
		errno = EACCES;
		return (-1);
	}

	if (pres[0] != SMP_PAIRING_RESPONSE) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_CMD_NOT_SUPPORTED };
		smp_log_send(sc, fail, sizeof(fail));
		errno = EPROTO;
		return (-1);
	}
	/* A Pairing Response must carry the full 7-octet PDU. */
	if (n < 7) {
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_INVALID_PARAMETERS;
		smp_log_send(sc, pdu, 2);
		errno = EPROTO;
		return (-1);
	}
	LOG_SMP(1, "pairing response IO=%d auth=%02x", pres[1], pres[3]);
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "feature");

	{
		bool use_sc_log = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		BLUED_LOG_SECURITY("pairing initiated "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "type=%d sc=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->remote_addr_type, use_sc_log);
	}

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs).
	 *
	 * Post-KNOB Erratum 11838: SC pairing requires a minimum
	 * negotiated key size of 16 bytes.  Legacy pairing retains
	 * the original minimum of 7 bytes.
	 */
	{
		uint8_t peer_key_sz = pres[4];
		uint8_t neg_key_sz;
		bool is_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			/* S-m6: out-of-range key size is ENCRYPTION_KEY_SIZE. */
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, pdu, 2);
			errno = EPROTO;
			return (-1);
		}
		neg_key_sz = (preq[4] < peer_key_sz) ? preq[4] : peer_key_sz;
		/*
		 * Retain the agreed size so legacy STK/LTK can be masked to
		 * it before use/distribution (Vol 3 Part H §2.3.4).
		 */
		sc->neg_key_size = neg_key_sz;
		if (is_sc && neg_key_sz < 16) {
			LOG_SMP(1, "SC key size %d < 16, rejecting (KNOB)",
			    neg_key_sz);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			return (-1);
		} else if (!is_sc && neg_key_sz < sc->min_key_size) {
			LOG_SMP(1, "legacy key size %d < %d, rejecting",
			    neg_key_sz, sc->min_key_size);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, pdu, 2);
			errno = EACCES;
			return (-1);
		}
	}

	/*
	 * sc_only: reject if peer does not support Secure Connections.
	 * Core Spec Vol 3 Part H Section 2.3.5.1: a device in SC Only
	 * mode shall reject pairing with a peer that does not support SC.
	 */
	if (sc->sc_only && !(pres[3] & SMP_AUTH_SC)) {
		LOG_SMP(1, "sc_only: peer does not support SC, rejecting");
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_AUTH_REQUIREMENTS;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		return (-1);
	}

	/*
	 * Determine association model and dispatch.
	 */
	{
		bool use_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		bool use_mitm = (preq[3] & SMP_AUTH_MITM) ||
		    (pres[3] & SMP_AUTH_MITM);
		/*
		 * Core Spec Vol 3 Part H Table 2.6 (legacy): OOB used
		 * when BOTH sides have OOB data.
		 * Table 2.7 (SC): OOB used when EITHER side has OOB data.
		 */
		bool have_oob = use_sc ?
		    (preq[2] != 0 || pres[2] != 0) :
		    (preq[2] != 0 && pres[2] != 0);
		int model;

		/*
		 * S-m8: validate the peer's IO-capability and OOB-flag byte
		 * ranges up front so reserved values are rejected on every
		 * path, not only when MITM forces smp_select_model().  On the
		 * initiator path the peer (responder) fields are in pres.
		 * Table 3.4: IO capability 0x05-0xFF reserved; OOB data flag
		 * 0x02-0xFF reserved.
		 */
		if (pres[1] > SMP_IO_KEYBOARD_DISPLAY || pres[2] > 1) {
			LOG_SMP(1, "reserved peer IO-cap/OOB value "
			    "(io=%d oob=%d), rejecting", pres[1], pres[2]);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_INVALID_PARAMETERS;
			smp_log_send(sc, pdu, 2);
			errno = EPROTO;
			return (-1);
		}

		/*
		 * OOB takes priority over IO capabilities.
		 */
		if (have_oob)
			model = SMP_MODEL_OOB;
		else if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);
		LOG_SMP(1, "model=%d sc=%d", model, use_sc);

		/*
		 * Legacy Passkey Entry and OOB are MITM-protected association
		 * models, so the resulting bond is "Authenticated pairing with
		 * encryption" (LE security mode 1 level 3, Core Spec Vol 3
		 * Part C §10.2.1; model mapping Vol 3 Part H Table 2.8/§2.3.5.1).
		 * Just Works provides no MITM protection (level 2).  Record this
		 * so the bond is not later mis-classified as unauthenticated.
		 * (SC paths set bond.is_mitm from the model directly.)
		 */
		legacy_mitm = (model == SMP_MODEL_PASSKEY_ENTRY ||
		    model == SMP_MODEL_OOB);

		/*
		 * Reject pairing if peer's IO capability is out of
		 * range [0..4].  Core Spec Vol 3 Part H Table 3.4:
		 * values 0x05-0xFF are reserved.
		 */
		if (model == SMP_MODEL_INVALID) {
			LOG_SMP(1, "invalid peer IO capability %d, "
			    "rejecting", pres[1]);
			pdu[0] = SMP_PAIRING_FAILED;
			pdu[1] = SMP_ERR_INVALID_PARAMETERS;
			smp_log_send(sc, pdu, 2);
			errno = EPROTO;
			return (-1);
		}

		/*
		 * Enforce the configured minimum-security-for-pairing floor
		 * (Core Spec Vol 3 Part H §2.3.5.1) once the association
		 * model is known but before any key is derived.  Passkey Entry,
		 * Numeric Comparison and OOB are MITM-authenticated; Just Works
		 * is not.  Reject with Authentication Requirements so the peer
		 * learns the pairing cannot meet policy.
		 */
		{
			bool authed = (model == SMP_MODEL_PASSKEY_ENTRY ||
			    model == SMP_MODEL_NUMERIC_COMPARISON ||
			    model == SMP_MODEL_OOB);

			if (!smp_policy_permits(sc->min_pairing_security,
			    authed, use_sc)) {
				LOG_SMP(1, "min_pairing_security=%u not met "
				    "(authed=%d sc=%d), rejecting",
				    sc->min_pairing_security, authed, use_sc);
				pdu[0] = SMP_PAIRING_FAILED;
				pdu[1] = SMP_ERR_AUTH_REQUIREMENTS;
				smp_log_send(sc, pdu, 2);
				errno = EACCES;
				return (-1);
			}
		}

		BLUED_PROBE_SMP_METHOD_SELECT(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    preq[1], pres[1], preq[3], model);
		BLUED_PROBE_SMP_PAIR_START(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), model);

		if (model == SMP_MODEL_OOB)
			BLUED_LOG_SECURITY("OOB pairing "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x sc=%d",
			    sc->remote_addr[5], sc->remote_addr[4],
			    sc->remote_addr[3], sc->remote_addr[2],
			    sc->remote_addr[1], sc->remote_addr[0],
			    use_sc);

		if (use_sc) {
			int rc;

			explicit_bzero(tk, sizeof(tk));
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				rc = smp_pair_sc_passkey(sc, preq, pres);
			else
				rc = smp_pair_sc(sc, preq, pres, model);
			return (rc);
		}

		/*
		 * Legacy OOB: use peer's TK received out-of-band.
		 * Core Spec Vol 3 Part H Section 2.3.5.5
		 */
		if (model == SMP_MODEL_OOB) {
			if (sc->oob == NULL || sc->oob->legacy == NULL) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_OOB_NOT_AVAILABLE };
				smp_log_send(sc, fail, 2);
				errno = ENOTSUP;
				return (-1);
			}
			memcpy(tk, sc->oob->legacy->tk, 16);
			LOG_SMP(1, "legacy OOB: TK set from OOB data");
			/* Fall through to legacy c1/s1 with this TK */
		}

		/* Legacy Passkey Entry: TK = passkey value */
		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;
			bool kp_notify;
			bool we_display;

			if (sc->passkey_cb == NULL) {
				/*
				 * No local UI to enter/display the passkey: we
				 * cannot fulfil the negotiated method.  Send
				 * Pairing Failed so the peer is not left waiting
				 * for a confirm until the SMP timeout (Vol 3
				 * Part H §3.5.5).  Use the same reason (Pairing
				 * Not Supported) as the responder path
				 * (smp_respond) and the SC passkey paths for
				 * cross-role consistency.
				 */
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PAIRING_NOT_SUPPORTED };
				smp_log_send(sc, fail, 2);
				errno = ENOTSUP;
				return (-1);
			}
			/*
			 * Keypress Notification: both sides must have set the
			 * SMP_AUTH_KEYPRESS bit in their AuthReq fields.
			 * Core Spec Vol 3 Part H Section 3.5.8
			 */
			kp_notify = (preq[3] & SMP_AUTH_KEYPRESS) &&
			    (pres[3] & SMP_AUTH_KEYPRESS);
			sc->kp_negotiated = kp_notify;	/* S-m7 */

			/*
			 * Passkey Entry display/input role, initiator side:
			 * our IO capability is preq[1], the peer/responder's
			 * is pres[1] (Core Spec Vol 3 Part H Table 2.8).
			 */
			we_display = smp_passkey_we_display(preq[1], pres[1],
			    true);

			if (we_display)
				passkey = arc4random_uniform(1000000);
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_STARTED);
			if (sc->passkey_cb(&passkey, we_display,
			    sc->passkey_cb_arg) < 0) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				smp_log_send(sc, fail, 2);
				errno = ECANCELED;
				return (-1);
			}
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_COMPLETED);
			/* TK = passkey as 128-bit LE integer */
			memset(tk, 0, sizeof(tk));
			tk[0] = passkey & 0xFF;
			tk[1] = (passkey >> 8) & 0xFF;
			tk[2] = (passkey >> 16) & 0xFF;
			/* Fall through to legacy c1/s1 with this TK */
		}
	}

	/*
	 * LE Legacy Pairing (Just Works or Passkey Entry).
	 * TK is already set: 0 for Just Works, passkey for Passkey Entry.
	 * Step 3: Generate our random and compute confirm value
	 */
	smp_random(mrand, sizeof(mrand));
	if (smp_c1(tk, mrand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, mconfirm) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}

	/*
	 * Step 4: Send Pairing Confirm
	 */
	pdu[0] = SMP_PAIRING_CONFIRM;
	memcpy(pdu + 1, mconfirm, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto legacy_cleanup;
	LOG_SMP(2, "legacy confirm sent");

	/*
	 * Receive Pairing Confirm from responder.
	 * The responder may send Keypress Notifications (opcode 0x0E) before
	 * the confirm when the responder is performing passkey entry.
	 * Consume and log them transparently.
	 */
	n = smp_recv_timed_kp(sc, pdu, 17);
	if (n == SMP_RECV_TIMED_OUT)
		goto legacy_cleanup;
	if (n < 17 || pdu[0] != SMP_PAIRING_CONFIRM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED)
			errno = EACCES;
		else
			errno = EPROTO;
		goto legacy_cleanup;
	}
	memcpy(sconfirm, pdu + 1, 16);

	/*
	 * Step 5: Send Pairing Random
	 */
	pdu[0] = SMP_PAIRING_RANDOM;
	memcpy(pdu + 1, mrand, 16);
	if (smp_log_send(sc, pdu, 17) < 0)
		goto legacy_cleanup;

	/*
	 * Receive Pairing Random from responder
	 */
	n = smp_recv_timed(sc, pdu, 17);
	if (n == SMP_RECV_TIMED_OUT)
		goto legacy_cleanup;
	if (n < 17 || pdu[0] != SMP_PAIRING_RANDOM) {
		if (n > 0 && pdu[0] == SMP_PAIRING_FAILED)
			errno = EACCES;
		else
			errno = EPROTO;
		goto legacy_cleanup;
	}
	memcpy(srand, pdu + 1, 16);

	/*
	 * Step 6: Verify responder's confirm value
	 */
	if (smp_c1(tk, srand, preq, pres, iat, sc->local_addr,
	    rat, sc->remote_addr, verify) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}
	if (timingsafe_bcmp(verify, sconfirm, 16) != 0) {
		/* Send Pairing Failed */
		pdu[0] = SMP_PAIRING_FAILED;
		pdu[1] = SMP_ERR_CONFIRM_VALUE_FAILED;
		smp_log_send(sc, pdu, 2);
		errno = EACCES;
		goto legacy_cleanup;
	}
	LOG_SMP(1, "legacy confirm verified");

	/*
	 * Step 7: Derive STK
	 */
	if (smp_s1(tk, srand, mrand, stk) < 0) {
		errno = EIO;
		goto legacy_cleanup;
	}
	/*
	 * Mask the STK to the negotiated key size before it is used for
	 * encryption (Vol 3 Part H §2.3.4).
	 */
	smp_mask_key(stk, sc->neg_key_size);
	LOG_SMP(1, "STK derived, starting encryption");
#ifdef BLUED_DEBUG_KEYS
	if (blued_verbose >= 3)
		blued_hexdump("SMP", "s1 output (STK)", stk, 16);
#endif

	/*
	 * Step 8: Start encryption via HCI LE_Start_Encryption
	 *
	 * HCI command format:
	 *   [opcode_lo, opcode_hi, param_len,
	 *    handle_lo, handle_hi,
	 *    random(8), ediv(2), ltk(16)]
	 *
	 * For STK: random=0, ediv=0
	 */
	{
		uint8_t params[28];

		params[0] = sc->con_handle & 0xFF;
		params[1] = (sc->con_handle >> 8) & 0xFF;
		memset(params + 2, 0, 8);	/* random = 0 */
		memset(params + 10, 0, 2);	/* EDIV = 0 */
		memcpy(params + 12, stk, 16);	/* STK as LTK */

		if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params,
		    sizeof(params)) < 0) {
			explicit_bzero(params, sizeof(params));
			goto legacy_cleanup;
		}
		/* Scrub the STK copy from the HCI command buffer. */
		explicit_bzero(params, sizeof(params));
	}

	if (hci_wait_encryption(sc->hci_fd, sc->con_handle, 5) < 0)
		goto legacy_cleanup;

	BLUED_PROBE_ENCRYPT_START(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL));
	BLUED_LOG_SECURITY("encryption active "
	    "addr=%02x:%02x:%02x:%02x:%02x:%02x handle=%d",
	    sc->remote_addr[5], sc->remote_addr[4],
	    sc->remote_addr[3], sc->remote_addr[2],
	    sc->remote_addr[1], sc->remote_addr[0],
	    sc->con_handle);

	/*
	 * Step 9: Receive key distribution from responder
	 *
	 * Expected: Encryption Information (LTK) + Master Identification
	 *           Identity Information (IRK) + Identity Address
	 */
	{
		struct smp_bond bond;
		memset(&bond, 0, sizeof(bond));
		memcpy(bond.addr, sc->remote_addr, 6);
		bond.addr_type = sc->remote_addr_type;
		/* Persist the negotiated key size (Vol 3 Part H §2.3.4). */
		bond.key_size = sc->neg_key_size;
		/*
		 * Record the authentication level of this legacy bond
		 * (Core Spec Vol 3 Part C §10.2.1 level 3 vs level 2).
		 */
		bond.is_mitm = legacy_mitm;

		/*
		 * S-m5: expect only the keys we actually requested.  RespKeyDist
		 * is the intersection of what the central requested (preq[6]) and
		 * what the peripheral agreed to send (pres[6]); using pres[6]
		 * verbatim would store/expect key material we never asked for.
		 */
		if (smp_receive_peer_keys(sc, &bond, preq[6] & pres[6],
		    false) != 0) {
			uint8_t fail[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_INVALID_PARAMETERS };

			(void)smp_log_send(sc, fail, sizeof(fail));
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			errno = EPROTO;
			goto legacy_cleanup;
		}

		/* Distribute initiator keys to responder */
		if (smp_distribute_init_keys(sc, preq, pres, false) != 0) {
			explicit_bzero(&bond, sizeof(bond));
			ret = -1;
			goto legacy_cleanup;
		}

		/*
		 * Store bond only if BOTH sides requested Bonding (Core Spec
		 * Vol 3 Part H §3.5.1 / §2.3.5.1).  A "No Bonding" peer's keys
		 * are session-only and must not be persisted.
		 */
		if (bond.has_ltk &&
		    (preq[3] & pres[3] & SMP_AUTH_BONDING)) {
			if (smp_bond_db_store(sc->bond_db, &bond) != 0) {
				explicit_bzero(&bond, sizeof(bond));
				ret = -1;
				goto legacy_cleanup;
			}
			LOG_SMP(1, "bond stored");
			BLUED_LOG_SECURITY("bond stored "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
			    "ltk=%d irk=%d lk=%d",
			    bond.addr[5], bond.addr[4],
			    bond.addr[3], bond.addr[2],
			    bond.addr[1], bond.addr[0],
			    bond.has_ltk, bond.has_irk,
			    bond.has_link_key);
		} else if (bond.has_ltk) {
			LOG_SMP(1, "no-bonding peer: keys kept session-only");
		}

		BLUED_LOG_SECURITY("pairing complete "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "sc=%d bonded=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    0, bond.has_ltk);
		explicit_bzero(&bond, sizeof(bond));
	}

	ret = 0;

legacy_cleanup:
	BLUED_PROBE_SMP_PAIR_DONE(
	    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), ret);
	if (ret != 0)
		BLUED_LOG_SECURITY("pairing failed "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x reason=%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    (unsigned)errno);
	explicit_bzero(tk, sizeof(tk));
	explicit_bzero(mrand, sizeof(mrand));
	explicit_bzero(srand, sizeof(srand));
	explicit_bzero(mconfirm, sizeof(mconfirm));
	explicit_bzero(sconfirm, sizeof(sconfirm));
	explicit_bzero(verify, sizeof(verify));
	explicit_bzero(stk, sizeof(stk));
	return (ret);
}

/*
 * Encrypt a connection using a previously bonded LTK.
 */
int
smp_encrypt_with_ltk(struct smp_conn *sc, const struct smp_bond *bond)
{
	uint8_t params[28];

	LOG_SMP(1, "encrypting with stored LTK");

	if (!bond->has_ltk) {
		errno = ENOENT;
		return (-1);
	}

	put_le16(params, sc->con_handle);
	memcpy(params + 2, &bond->rand, 8);
	put_le16(params + 10, bond->ediv);
	memcpy(params + 12, bond->ltk, 16);

	if (hci_send_raw_cmd(sc->hci_fd, HCI_OP_LE_START_ENCRYPTION, params, sizeof(params)) < 0) {
		explicit_bzero(params, sizeof(params));
		return (-1);
	}

	/* Scrub the LTK copy from the HCI command buffer. */
	explicit_bzero(params, sizeof(params));
	return (0);
}

/* ----------------------------------------------------------------
 *  SMP Responder (Peripheral) Mode
 * ---------------------------------------------------------------- */

/*
 * Initialize an SMP connection from an already-accepted socket fd.
 */
int
smp_open_accepted(struct smp_conn *sc, int fd,
    const uint8_t *local_addr, uint8_t local_addr_type,
    const uint8_t *remote_addr, uint8_t remote_addr_type,
    int hci_fd, uint16_t con_handle, struct smp_bond_db *db)
{

	memset(sc, 0, sizeof(*sc));
	sc->fd = fd;
	sc->hci_fd = hci_fd;
	sc->con_handle = con_handle;
	sc->remote_addr_type = remote_addr_type;
	memcpy(sc->remote_addr, remote_addr, 6);
	memcpy(sc->local_addr, local_addr, 6);
	sc->local_addr_type = local_addr_type;
	sc->bond_db = db;
	sc->io_capability = SMP_IO_KEYBOARD_DISPLAY;  /* default */
	/*
	 * Default minimum encryption key size = 16 bytes (128 bits).
	 * This is intentional for security: it mitigates the KNOB attack
	 * (CVE-2019-9506) which exploits negotiation of short key sizes.
	 * For interop with legacy devices that cannot negotiate 16-byte
	 * keys, min_key_size can be configured lower via blued.conf
	 * "security { min_key_size = 7; }" (range: 7-16).
	 */
	sc->min_key_size = 16;
	/* No masking until Phase 1 negotiates a size (Vol 3 Part H §2.3.4). */
	sc->neg_key_size = 16;
	smp_seed_policy_defaults(sc);

	/*
	 * Lock clofork: accepted SMP sockets carry active pairing state.
	 */
	(void)cap_clofork_limit(sc->fd, CAP_CLOFORK_LOCKED);

	/* SMP timeout: 30 seconds per spec (Vol 3 Part H Section 3.4) */
	{
		struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
		if (setsockopt(sc->fd, SOL_SOCKET, SO_RCVTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_RCVTIMEO");
	}

	return (0);
}

/*
 * SMP Responder entry point.
 * Receives Pairing Request, sends Response, dispatches to legacy or SC.
 */
int
smp_respond(struct smp_conn *sc)
{
	uint8_t preq[7], pres[7];
	uint8_t tk[16];
	ssize_t n;

	memset(tk, 0, sizeof(tk));

	/*
	 * Arm the single cumulative §3.4 pairing deadline for the responder
	 * procedure, authoritative for the whole handshake including any SC
	 * Phase 2 sub-flow reached via the dispatch below.
	 */
	smp_pairing_arm(sc);

	/* Receive Pairing Request (or a Security Request from the peer). */
	n = smp_log_recv(sc, preq, sizeof(preq));
	if (n < 1) {
		errno = EPROTO;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	/*
	 * Dispatch on the opcode before enforcing the Pairing Request length:
	 * a Security Request (Core Spec Vol 3 Part H §3.6.7) is only 2 octets
	 * (Code | AuthReq), so gating on n >= 7 first would drop a well-formed
	 * Security Request as a protocol error and never reach the EAGAIN path
	 * that tells the caller to initiate pairing as the central.
	 */
	if (preq[0] != SMP_PAIRING_REQUEST) {
		if (preq[0] == SMP_SECURITY_REQUEST && n >= 2) {
			errno = EAGAIN;
		} else {
			uint8_t fail[2] = { SMP_PAIRING_FAILED, SMP_ERR_CMD_NOT_SUPPORTED };
			smp_log_send(sc, fail, sizeof(fail));
			errno = EPROTO;
		}
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	/* A Pairing Request must carry the full 7-octet PDU. */
	if (n < 7) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_INVALID_PARAMETERS };

		smp_log_send(sc, fail, sizeof(fail));
		errno = EPROTO;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	LOG_SMP(1, "resp: request received IO=%d auth=%02x", preq[1], preq[3]);

	/*
	 * Operator pairable gate (the common adapter pairable control).  When the daemon is
	 * not pairable, decline with "Pairing Not Supported" (Core Spec Vol 3
	 * Part H §3.5.1) rather than proceeding with the handshake.
	 */
	if (sc->reject_pairing) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_PAIRING_NOT_SUPPORTED };
		smp_log_send(sc, fail, sizeof(fail));
		errno = EACCES;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}

	/*
	 * Rate-limit pairing attempts per Core Spec Vol 3 Part H §3.4.
	 * Reject with SMP_ERR_REPEATED_ATTEMPTS if too many attempts
	 * from the same address within the rate-limit window.
	 */
	if (smp_rate_check(sc->remote_addr, sc->remote_addr_type, sc->bond_db) < 0) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_REPEATED_ATTEMPTS };
		BLUED_LOG_SECURITY("pairing rate-limited "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0]);
		smp_log_send(sc, fail, 2);
		errno = EACCES;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}

	/*
	 * Send Pairing Response.
	 *
	 * Key distribution fields must be a subset of what the initiator
	 * offered (Core Spec Vol 3 Part H Section 3.6.1): "The Peripheral
	 * shall not set to one any flag ... that the Central has set to zero."
	 *
	 * For SC, EncKey is ignored and EDIV/Rand shall not be distributed.
	 */
	{
		bool peer_sc = (preq[3] & SMP_AUTH_SC) != 0;

		pres[0] = SMP_PAIRING_RESPONSE;
		pres[1] = sc->io_capability;
		pres[2] = (sc->oob != NULL &&
		    (sc->oob->legacy != NULL || sc->oob->sc != NULL)) ?
		    0x01 : 0x00;
		pres[3] = smp_build_authreq(sc);
		pres[4] = 16;
		/*
		 * The responder's key-distribution fields shall be a subset of
		 * what the initiator offered (Core Spec Vol 3 Part H §3.6.1) --
		 * masked further by our own policy: pres[5] (InitKeyDist, keys we
		 * request from the initiator) by their_key_dist, pres[6]
		 * (RespKeyDist, keys we distribute) by our_key_dist.  Both default
		 * to the current ENC|ID|LINK mask, so this is a no-op unless
		 * configured.  For SC, EncKey is dropped from both directions.
		 */
		if (peer_sc)
			pres[5] = preq[5] & sc->their_key_dist &
			    (SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LINK_KEY);
		else
			pres[5] = preq[5] & sc->their_key_dist &
			    (SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
			    SMP_KEY_DIST_LEGACY_SIGN_KEY);
		if (peer_sc)
			pres[6] = preq[6] & sc->our_key_dist &
			    (SMP_KEY_DIST_ID_KEY | SMP_KEY_DIST_LINK_KEY);
		else
			pres[6] = preq[6] & sc->our_key_dist &
			    (SMP_KEY_DIST_ENC_KEY | SMP_KEY_DIST_ID_KEY |
			    SMP_KEY_DIST_LEGACY_SIGN_KEY);
	}

	if (smp_log_send(sc, pres, sizeof(pres)) < 0) {
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}
	LOG_SMP(1, "resp: response sent IO=%d auth=%02x sc=%d",
	    pres[1], pres[3], (pres[3] & SMP_AUTH_SC) != 0);
	BLUED_PROBE_SMP_PHASE(bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
	    "feature");

	{
		bool use_sc_log = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		BLUED_LOG_SECURITY("pairing initiated "
		    "addr=%02x:%02x:%02x:%02x:%02x:%02x "
		    "type=%d sc=%d",
		    sc->remote_addr[5], sc->remote_addr[4],
		    sc->remote_addr[3], sc->remote_addr[2],
		    sc->remote_addr[1], sc->remote_addr[0],
		    sc->remote_addr_type, use_sc_log);
	}

	/*
	 * Validate encryption key size (Core Spec Vol 3 Part H 3.6.1).
	 * Max_Encryption_Key_Size must be in range [7,16].
	 * Negotiated size = min(ours, theirs).
	 *
	 * Post-KNOB Erratum 11838: SC pairing requires a minimum
	 * negotiated key size of 16 bytes.  Legacy pairing retains
	 * the original minimum of 7 bytes.
	 */
	{
		uint8_t peer_key_sz = preq[4];
		uint8_t neg_key_sz;
		uint8_t fail[2];
		bool is_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);

		if (peer_key_sz < 7 || peer_key_sz > 16) {
			/* S-m6: out-of-range key size is ENCRYPTION_KEY_SIZE. */
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, fail, 2);
			errno = EPROTO;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		}
		neg_key_sz = (pres[4] < peer_key_sz) ? pres[4] : peer_key_sz;
		/*
		 * Retain the agreed size so legacy STK/LTK can be masked to
		 * it before use/distribution (Vol 3 Part H §2.3.4).
		 */
		sc->neg_key_size = neg_key_sz;
		if (is_sc && neg_key_sz < 16) {
			LOG_SMP(1, "SC key size %d < 16, rejecting (KNOB)",
			    neg_key_sz);
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, fail, 2);
			errno = EACCES;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		} else if (!is_sc && neg_key_sz < sc->min_key_size) {
			LOG_SMP(1, "legacy key size %d < %d, rejecting",
			    neg_key_sz, sc->min_key_size);
			fail[0] = SMP_PAIRING_FAILED;
			fail[1] = SMP_ERR_ENCRYPTION_KEY_SIZE;
			smp_log_send(sc, fail, 2);
			errno = EACCES;
			explicit_bzero(tk, sizeof(tk));
			return (-1);
		}
	}

	if (sc->sc_only && !(preq[3] & SMP_AUTH_SC)) {
		uint8_t fail[2] = { SMP_PAIRING_FAILED,
		    SMP_ERR_AUTH_REQUIREMENTS };
		LOG_SMP(1, "sc_only: peer does not support SC, rejecting");
		smp_log_send(sc, fail, 2);
		errno = EACCES;
		explicit_bzero(tk, sizeof(tk));
		return (-1);
	}

	{
		bool use_sc = (preq[3] & SMP_AUTH_SC) &&
		    (pres[3] & SMP_AUTH_SC);
		bool use_mitm = (preq[3] & SMP_AUTH_MITM) ||
		    (pres[3] & SMP_AUTH_MITM);
		/*
		 * Core Spec Vol 3 Part H Table 2.6 (legacy): OOB used
		 * when BOTH sides have OOB data.
		 * Table 2.7 (SC): OOB used when EITHER side has OOB data.
		 */
		bool have_oob = use_sc ?
		    (preq[2] != 0 || pres[2] != 0) :
		    (preq[2] != 0 && pres[2] != 0);
		int model;

		/*
		 * S-m8: validate the peer's IO-capability and OOB-flag byte
		 * ranges up front so reserved values are rejected on every
		 * path, not only when MITM forces smp_select_model().  On the
		 * responder path the peer (initiator) fields are in preq.
		 * Table 3.4: IO capability 0x05-0xFF reserved; OOB data flag
		 * 0x02-0xFF reserved.
		 */
		if (preq[1] > SMP_IO_KEYBOARD_DISPLAY || preq[2] > 1) {
			uint8_t fail[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_INVALID_PARAMETERS };
			LOG_SMP(1, "reserved peer IO-cap/OOB value "
			    "(io=%d oob=%d), rejecting", preq[1], preq[2]);
			smp_log_send(sc, fail, sizeof(fail));
			errno = EPROTO;
			return (-1);
		}

		/*
		 * OOB takes priority over IO capabilities.
		 */
		if (have_oob)
			model = SMP_MODEL_OOB;
		else if (!use_mitm)
			model = SMP_MODEL_JUST_WORKS;
		else
			model = smp_select_model(preq[1], pres[1], use_sc);

		/*
		 * Reject pairing if peer's IO capability is out of
		 * range [0..4].  Core Spec Vol 3 Part H Table 3.4:
		 * values 0x05-0xFF are reserved.
		 */
		if (model == SMP_MODEL_INVALID) {
			uint8_t fail[2] = { SMP_PAIRING_FAILED,
			    SMP_ERR_INVALID_PARAMETERS };
			LOG_SMP(1, "invalid peer IO capability %d, "
			    "rejecting", preq[1]);
			smp_log_send(sc, fail, sizeof(fail));
			errno = EPROTO;
			return (-1);
		}

		/*
		 * Enforce the configured minimum-security-for-pairing floor
		 * (Core Spec Vol 3 Part H §2.3.5.1) before deriving keys.
		 * Mirrors the initiator gate: reject an unauthenticated (Just
		 * Works) association when 'auth' is required, or legacy pairing
		 * when 'sc' is required, with Authentication Requirements.
		 */
		{
			bool authed = (model == SMP_MODEL_PASSKEY_ENTRY ||
			    model == SMP_MODEL_NUMERIC_COMPARISON ||
			    model == SMP_MODEL_OOB);

			if (!smp_policy_permits(sc->min_pairing_security,
			    authed, use_sc)) {
				uint8_t fail[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_AUTH_REQUIREMENTS };

				LOG_SMP(1, "min_pairing_security=%u not met "
				    "(authed=%d sc=%d), rejecting",
				    sc->min_pairing_security, authed, use_sc);
				smp_log_send(sc, fail, sizeof(fail));
				errno = EACCES;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
		}

		BLUED_PROBE_SMP_METHOD_SELECT(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL),
		    preq[1], pres[1], preq[3], model);
		BLUED_PROBE_SMP_PAIR_START(
		    bt_ntoa((bdaddr_t *)sc->remote_addr, NULL), model);

		if (model == SMP_MODEL_OOB)
			BLUED_LOG_SECURITY("OOB pairing "
			    "addr=%02x:%02x:%02x:%02x:%02x:%02x sc=%d",
			    sc->remote_addr[5], sc->remote_addr[4],
			    sc->remote_addr[3], sc->remote_addr[2],
			    sc->remote_addr[1], sc->remote_addr[0],
			    use_sc);

		if (use_sc) {
			int rc;

			explicit_bzero(tk, sizeof(tk));
			if (model == SMP_MODEL_PASSKEY_ENTRY)
				rc = smp_respond_sc_passkey(sc, preq, pres);
			else
				rc = smp_respond_sc(sc, preq, pres, model);
			return (rc);
		}

		/*
		 * Legacy OOB: use peer's TK received out-of-band.
		 * Core Spec Vol 3 Part H Section 2.3.5.5
		 */
		if (model == SMP_MODEL_OOB) {
			if (sc->oob == NULL || sc->oob->legacy == NULL) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_OOB_NOT_AVAILABLE };
				smp_log_send(sc, f, 2);
				errno = ENOTSUP;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			memcpy(tk, sc->oob->legacy->tk, 16);
			LOG_SMP(1, "resp: legacy OOB: TK set from OOB data");
			/* Fall through to legacy c1/s1 with this TK */
		}

		if (model == SMP_MODEL_PASSKEY_ENTRY) {
			uint32_t passkey = 0;
			bool kp_notify;
			bool we_display;

			if (sc->passkey_cb == NULL) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PAIRING_NOT_SUPPORTED };
				smp_log_send(sc, f, 2);
				errno = ENOTSUP;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			/*
			 * Keypress Notification: both sides must have set the
			 * SMP_AUTH_KEYPRESS bit in their AuthReq fields.
			 * Core Spec Vol 3 Part H Section 3.5.8
			 */
			kp_notify = (preq[3] & SMP_AUTH_KEYPRESS) &&
			    (pres[3] & SMP_AUTH_KEYPRESS);
			sc->kp_negotiated = kp_notify;	/* S-m7 */

			/*
			 * Passkey Entry display/input role, responder side:
			 * our IO capability is pres[1], the peer/initiator's
			 * is preq[1] (Core Spec Vol 3 Part H Table 2.8).
			 */
			we_display = smp_passkey_we_display(pres[1], preq[1],
			    false);

			if (we_display)
				passkey = arc4random_uniform(1000000);
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_STARTED);
			if (sc->passkey_cb(&passkey, we_display,
			    sc->passkey_cb_arg) < 0) {
				uint8_t f[2] = { SMP_PAIRING_FAILED,
				    SMP_ERR_PASSKEY_ENTRY_FAILED };
				smp_log_send(sc, f, 2);
				errno = ECANCELED;
				explicit_bzero(tk, sizeof(tk));
				return (-1);
			}
			if (kp_notify && !we_display)
				smp_send_keypress(sc,
				    SMP_KEYPRESS_COMPLETED);
			memset(tk, 0, sizeof(tk));
			tk[0] = passkey & 0xFF;
			tk[1] = (passkey >> 8) & 0xFF;
			tk[2] = (passkey >> 16) & 0xFF;
		}

		{
			int rc = smp_respond_legacy(sc, preq, pres, tk);
			explicit_bzero(tk, sizeof(tk));
			return (rc);
		}
	}
}
