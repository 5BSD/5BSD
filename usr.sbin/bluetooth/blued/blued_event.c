/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued event loop: kqueue setup, kevent dispatch, fd event handling,
 * timer handling, HCI event processing, connection disconnect.
 */

#include "blued_internal.h"
#include "blued_encryption_event.h"
#include "blued_le_meta.h"
#include "hci_internal.h"
#include "iso.h"

static void	blued_periph_save_cccds(struct blued_conn *conn);

/*
 * Walk a multi-report advertising event and hand each usable report's AD
 * fields to the Mesh broker.
 *
 * HCI permits several reports in one event.  Every report's length is fully
 * determined by its own Data_Length at a fixed offset, so a report whose
 * VALUES cannot be used is always skippable, and skipping it is the only
 * disposition the specification supports: nothing in §7.7.65.2 or §7.7.65.13
 * authorises discarding an event because one report carries a reserved value,
 * and no reference implementation does (NimBLE advances past the report and
 * continues, Zephyr keeps everything already delivered, BlueZ labels the value
 * "Reserved" and continues).  Dropping the batch instead loses valid mesh
 * beacons intermittently, on exactly the controllers that coalesce reports.
 *
 * A broken FRAMING is different: the next report's offset is then unknown, so
 * the walk stops there.  Reports already forwarded stay forwarded -- they were
 * each individually well formed.
 */
static void
blued_mesh_walk_adv_event(const uint8_t *buf, size_t len, uint8_t subevent)
{
	size_t off, consumed;
	uint8_t nreports, r;

	if (len < 5)
		return;
	nreports = buf[4];
	/*
	 * Num_Reports: 0x01 to 0x19 for the legacy event (§7.7.65.2) and
	 * 0x01 to 0x0A for the extended one (§7.7.65.13).  A count outside
	 * its own event's range is a framing statement, not a per-report
	 * value, so the whole event is untrustworthy.
	 */
	if ((subevent == NG_HCI_LEEV_ADVREP &&
	    (nreports == 0 || nreports > 25)) ||
	    (subevent == NG_HCI_LEEV_EXT_ADVREP &&
	    (nreports == 0 || nreports > 10)))
		return;

	off = 5;
	for (r = 0; r < nreports; r++) {
		bool usable;

		if (subevent == NG_HCI_LEEV_EXT_ADVREP) {
			/*
			 * The parser's validate-only entry (NULL result):
			 * this path forwards raw AD to the Mesh broker and
			 * keeps no scan result, and the parser's fragment
			 * reassembly is scan-thread state that must not be
			 * driven from the main loop.
			 */
			consumed = hci_ext_adv_report_len(buf + off,
			    len - off);
			if (consumed == 0)
				return;		/* framing lost */
			usable = hci_parse_ext_adv_report(buf + off,
			    len - off, NULL) != 0;
		} else {
			uint8_t dlen;
			int8_t rssi;

			/*
			 * Legacy report: event_type(1) addr_type(1) addr(6)
			 * data_length(1) data[] rssi(1).
			 */
			if (len - off < 10)
				return;		/* framing lost */
			dlen = buf[off + 8];
			if (dlen > 31 || len - off < (size_t)10 + dlen)
				return;		/* framing lost */
			consumed = (size_t)10 + dlen;
			rssi = (int8_t)buf[off + 9 + dlen];
			usable = buf[off] <= 0x04 && buf[off + 1] <= 0x03 &&
			    (rssi == 0x7f || (rssi >= -127 && rssi <= 20));
		}
		if (usable) {
			size_t hdr = (subevent == NG_HCI_LEEV_ADVREP) ? 8 : 23;

			blued_mesh_demux_report(buf + off + hdr + 1,
			    buf[off + hdr]);
		}
		off += consumed;
	}
}

/*
 * Arm the 30-second ATT indication timeout (Core Spec Vol 3 Part F 3.3.3).
 * Called after successfully sending an indication.  If the client does not
 * confirm within 30 seconds, the bearer must be disconnected.
 */
void
blued_ind_arm_timeout(struct blued_conn *conn)
{
	struct kevent kev;
	uintptr_t ident;

	if (conn->att == NULL)
		return;

	ident = blued_next_timer_id++;
	conn->att->ind_timer = ident;

	EV_SET(&kev, ident, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, ATT_TIMEOUT_SEC,
	    BLUED_KQ_IND_TIMEOUT);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

/*
 * Disarm the indication timeout (called when confirmation is received).
 */
void
blued_ind_disarm_timeout(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn->att == NULL || conn->att->ind_timer == 0)
		return;

	EV_SET(&kev, conn->att->ind_timer, EVFILT_TIMER,
	    EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	conn->att->ind_timer = 0;
}

/*
 * Arm or reset the idle connection timeout.
 * Called on connection setup and on each received ATT PDU.
 */
void
blued_idle_arm(struct blued_conn *conn)
{
	struct kevent kev;

	/* Only for peripheral connections */
	if (conn->role != BLUED_ROLE_PERIPHERAL)
		return;

	/*
	 * C3-M6: allocate a FRESH ident on every arm, exactly as the sibling
	 * blued_ind_arm_timeout does.  Re-arming the same ident does not
	 * retract an expiry kevent that the kernel already placed in the
	 * current batch, so an idle timeout that fired just before an ATT PDU
	 * arrived would still be dispatched afterwards and disconnect a live
	 * connection.  A new ident cannot match the stale event; the old one
	 * is deleted first so a re-armed connection never leaks knotes.
	 */
	if (conn->idle_timer != 0) {
		EV_SET(&kev, conn->idle_timer, EVFILT_TIMER, EV_DELETE, 0, 0,
		    NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
	conn->idle_timer = blued_next_timer_id++;

	EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, NOTE_SECONDS, BLUED_IDLE_TIMEOUT_SEC,
	    BLUED_KQ_IDLE_TIMEOUT);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
}

void
blued_idle_disarm(struct blued_conn *conn)
{
	struct kevent kev;

	if (conn->idle_timer == 0)
		return;

	EV_SET(&kev, conn->idle_timer, EVFILT_TIMER,
	    EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	conn->idle_timer = 0;
}

/*
 * Handle asynchronous HCI events from the adapter.
 *
 * Registered with kqueue in peripheral mode to catch LE LTK Request
 * events (subevent 0x05) that arrive when a bonded device reconnects
 * and initiates encryption.  The kernel forwards these to userspace
 * via the raw HCI socket -- we must reply with either LTK Reply or
 * Negative Reply, otherwise the controller stalls.
 *
 * Also handles Authenticated Payload Timeout Expired (0x57).
 */
static void blued_hci_event_process(struct blued_adapter *adp, uint8_t *buf,
    ssize_t n);

/*
 * Deferred raw HCI events: a blocking waiter on a worker thread (e.g.
 * hci_wait_encryption, via hci_event_defer_hook) can drain events from the
 * shared adapter fd that belong to the main loop; they cannot be re-queued
 * on the socket, so the waiter parks them here and signals the setup pipe.
 * The main thread's setup-pipe sweep drains the ring through the normal
 * event processing.
 *
 * The ring is BOUNDED and CLASSIFIED.  Both multi-second scan loops are bulk
 * producers: with one periodic-advertising sync, LE Periodic Advertising
 * Reports arrive as fast as every 7.5 ms and an unprioritised drop-newest
 * ring filled in well under a second, after which every newly arriving LTK
 * Request / Disconnection Complete was evicted -- starving exactly the
 * control events the deferral exists to protect.  So:
 *   - control events (blued_hci_defer_is_priority) are ALWAYS admitted, and
 *     when the ring is full they evict the OLDEST bulk entry rather than
 *     being dropped themselves;
 *   - bulk reports are admitted only into spare capacity, leaving
 *     BLUED_HCI_DEFER_RESERVE slots for control events;
 *   - drops are counted per class in the overflow log.
 * Ordering WITHIN a class is preserved; a control event may overtake bulk
 * reports, which is exactly the intent.
 */
#define BLUED_HCI_DEFER_DEPTH	32
#define BLUED_HCI_DEFER_RESERVE	8	/* slots kept for control events */
#define BLUED_HCI_DEFER_PKT_MAX	(3 + NG_HCI_EVENT_PKT_SIZE)

struct blued_hci_deferred {
	int		hci_fd;
	uint16_t	len;
	bool		prio;		/* control event, never starved */
	uint8_t		pkt[BLUED_HCI_DEFER_PKT_MAX];
};

static struct blued_hci_deferred blued_hci_defer_q[BLUED_HCI_DEFER_DEPTH];
static int blued_hci_defer_head;
static int blued_hci_defer_count;
/* Overflow accounting (guarded by blued_hci_defer_lock): log once per
 * overflow burst, then report the burst's total, per class, once space
 * frees up. */
static bool blued_hci_defer_dropping;
static unsigned int blued_hci_defer_drops_prio;
static unsigned int blued_hci_defer_drops_bulk;
static pthread_mutex_t blued_hci_defer_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Classify a raw HCI event packet (type(1), event(1), length(1)[, LE
 * subevent(1)]).  A control event is one the main loop must see to keep a
 * link's state machine correct; everything else -- above all the advertising
 * report subevents 0x02 (Advertising Report), 0x0D (Extended Advertising
 * Report), 0x0F (Periodic Advertising Report) and 0x22 (Periodic Advertising
 * Report v2) -- is bulk.  A malformed/short packet is treated as priority so
 * a parse failure can never silently starve a control event.
 */
static bool
blued_hci_defer_is_priority(const uint8_t *pkt, size_t len)
{

	if (len < 3)
		return (true);
	if (pkt[1] != NG_HCI_EVENT_LE) {
		switch (pkt[1]) {
		case 0x05:	/* Disconnection Complete */
		case 0x08:	/* Encryption Change */
		case 0x30:	/* Encryption Key Refresh Complete */
		case 0x57:	/* Authenticated Payload Timeout Expired */
		case 0x59:	/* Encryption Change v2 */
			return (true);
		default:
			return (false);
		}
	}
	if (len < 4)
		return (true);
	switch (pkt[3]) {
	case 0x01:	/* LE Connection Complete */
	case 0x03:	/* LE Connection Update Complete */
	case 0x04:	/* LE Read Remote Features Complete */
	case 0x05:	/* LE Long Term Key Request */
	case 0x0A:	/* LE Enhanced Connection Complete */
	case 0x0C:	/* LE PHY Update Complete */
		return (true);
	default:
		return (false);
	}
}

/* Remove the IDX'th (0 == oldest) ring entry.  Caller holds the lock. */
static void
blued_hci_defer_drop_at(int idx)
{
	int j;

	if (idx == 0) {
		blued_hci_defer_head = (blued_hci_defer_head + 1) %
		    BLUED_HCI_DEFER_DEPTH;
		blued_hci_defer_count--;
		return;
	}
	for (j = idx; j < blued_hci_defer_count - 1; j++)
		blued_hci_defer_q[(blued_hci_defer_head + j) %
		    BLUED_HCI_DEFER_DEPTH] =
		    blued_hci_defer_q[(blued_hci_defer_head + j + 1) %
		    BLUED_HCI_DEFER_DEPTH];
	blued_hci_defer_count--;
}

/*
 * Push an entry back onto the FRONT of the ring, preserving replay order.
 * Used by the drain when a replay it had already dequeued turns out to be
 * blocked after all (C3-M15).  Returns false if the ring filled up behind us,
 * in which case the caller must drop the packet.
 */
static bool
blued_hci_defer_push_front(const struct blued_hci_deferred *ev)
{
	bool ok;

	pthread_mutex_lock(&blued_hci_defer_lock);
	ok = blued_hci_defer_count < BLUED_HCI_DEFER_DEPTH;
	if (ok) {
		blued_hci_defer_head = (blued_hci_defer_head +
		    BLUED_HCI_DEFER_DEPTH - 1) % BLUED_HCI_DEFER_DEPTH;
		blued_hci_defer_q[blued_hci_defer_head] = *ev;
		blued_hci_defer_count++;
	}
	pthread_mutex_unlock(&blued_hci_defer_lock);
	return (ok);
}

/*
 * Make room for a control event by discarding the OLDEST bulk entry.
 * Caller holds the lock; returns false when the ring holds control events
 * only (then the newcomer really must be dropped).
 */
static bool
blued_hci_defer_evict_bulk(void)
{
	int i;

	for (i = 0; i < blued_hci_defer_count; i++)
		if (!blued_hci_defer_q[(blued_hci_defer_head + i) %
		    BLUED_HCI_DEFER_DEPTH].prio) {
			blued_hci_defer_drop_at(i);
			return (true);
		}
	return (false);
}

void
blued_hci_event_defer(int hci_fd, const void *pkt, size_t len)
{
	unsigned int dropped_prio, dropped_bulk;
	bool prio;
	int limit, slot;

	if (pkt == NULL || len == 0 || len > BLUED_HCI_DEFER_PKT_MAX)
		return;
	prio = blued_hci_defer_is_priority(pkt, len);
	limit = prio ? BLUED_HCI_DEFER_DEPTH :
	    BLUED_HCI_DEFER_DEPTH - BLUED_HCI_DEFER_RESERVE;
	pthread_mutex_lock(&blued_hci_defer_lock);
	if (blued_hci_defer_count >= limit &&
	    (!prio || !blued_hci_defer_evict_bulk())) {
		bool first = !blued_hci_defer_dropping;

		blued_hci_defer_dropping = true;
		if (prio)
			blued_hci_defer_drops_prio++;
		else
			blued_hci_defer_drops_bulk++;
		pthread_mutex_unlock(&blued_hci_defer_lock);
		if (first)
			warnx("deferred HCI event ring full (%d), "
			    "dropping events", BLUED_HCI_DEFER_DEPTH);
		return;
	}
	dropped_prio = dropped_bulk = 0;
	if (blued_hci_defer_dropping) {
		/* The overflow burst ended; report what it cost, once. */
		blued_hci_defer_dropping = false;
		dropped_prio = blued_hci_defer_drops_prio;
		dropped_bulk = blued_hci_defer_drops_bulk;
		blued_hci_defer_drops_prio = blued_hci_defer_drops_bulk = 0;
	}
	slot = (blued_hci_defer_head + blued_hci_defer_count) %
	    BLUED_HCI_DEFER_DEPTH;
	blued_hci_defer_q[slot].hci_fd = hci_fd;
	blued_hci_defer_q[slot].len = (uint16_t)len;
	blued_hci_defer_q[slot].prio = prio;
	memcpy(blued_hci_defer_q[slot].pkt, pkt, len);
	blued_hci_defer_count++;
	pthread_mutex_unlock(&blued_hci_defer_lock);
	if (dropped_prio != 0 || dropped_bulk != 0)
		warnx("deferred HCI event ring overflow ended: %u control "
		    "and %u bulk event(s) dropped", dropped_prio,
		    dropped_bulk);
	/*
	 * Deliberately no setup-pipe signal here: the enqueuing waiter still
	 * holds the fd's devreq mutex, so an immediate main-loop replay would
	 * only block event handlers on that mutex for up to the whole wait.
	 * The waiter signals ONCE, after releasing the mutex, via
	 * blued_hci_defer_kick (hci_event_defer_kick_hook).
	 */
}

/*
 * Wake the main loop to drain the deferred-event ring.  Called by every
 * blocking waiter AFTER it released the fd's devreq mutex, so the replayed
 * handlers can immediately issue their own HCI commands.
 *
 * RING-driven, not caller-driven: the kick used to be conditioned on THIS
 * waiter having deferred something, so entries parked by an earlier waiter
 * and skipped by a trylock-aborted drain were stranded -- the pipe byte was
 * already consumed, the adapter went quiet and nothing re-triggered the
 * drain.  Kicking whenever the ring is non-empty makes every mutex release
 * a retry point.
 */
void
blued_hci_defer_kick(void)
{
	bool pending;

	pthread_mutex_lock(&blued_hci_defer_lock);
	pending = blued_hci_defer_count != 0;
	pthread_mutex_unlock(&blued_hci_defer_lock);
	if (pending)
		(void)write(blued_g.setup_pipe[1], "x", 1);
}

/*
 * Main-thread drain of the deferred-event ring.  The owning adapter is
 * re-resolved by fd (and must still be active) so a packet parked across an
 * adapter loss is dropped rather than processed against a stale adapter.
 *
 * Best-effort non-blocking: the owning fd's devreq mutex is trylock'd before
 * each replay, and re-probed immediately before the replay itself.  On
 * contention (a blocking waiter such as hci_wait_encryption still owns the
 * fd) the drain does NOT abort at the selection stage: it skips to the oldest
 * entry belonging to a DIFFERENT fd, so one contended adapter cannot hold up
 * every other adapter's parked events.  Order within an fd is preserved (the
 * oldest drainable entry for that fd is always taken first).  Entries for a
 * contended fd stay queued; because blued_hci_defer_kick() is ring-driven,
 * the waiter that owns the fd re-triggers the drain when it releases the
 * mutex.
 *
 * C3-M15: the trylock is a probe-then-release, so it is NOT a guarantee.
 * Another worker can take the same fd's devreq mutex between the probe and
 * the replay (a scan holds it for up to 5 s), and the replayed handler -- which
 * takes the mutex itself -- would then block the single-threaded event loop
 * for that long.  Holding the mutex across the replay is not an option for
 * exactly that reason.  What the drain does instead is narrow the window to
 * nothing but the dequeue, re-probe immediately before the replay, and on a
 * lost race push the entry back to the FRONT of the ring and return, leaving
 * the ring-driven kick to retry once the mutex is released.  The residual
 * window (probe, then handler acquires) is unavoidable without redesigning
 * devreq ownership.
 *
 * (no_thread_safety_analysis: clang cannot follow the probe-only
 * trylock/unlock pair on the runtime-looked-up devreq mutex, as with
 * blued_handle_hci_event below.)
 */
static void __attribute__((no_thread_safety_analysis))
blued_hci_defer_drain(void)
{
	int contended[BLUED_HCI_DEFER_DEPTH];
	int ncontended;

	for (;;) {
		struct blued_hci_deferred ev;
		struct blued_adapter *adp;
		pthread_mutex_t *hci_mtx;
		int i, idx, slot = 0;
		bool got = false;

		ncontended = 0;
		for (;;) {
			pthread_mutex_lock(&blued_hci_defer_lock);
			for (idx = 0; idx < blued_hci_defer_count; idx++) {
				slot = (blued_hci_defer_head + idx) %
				    BLUED_HCI_DEFER_DEPTH;
				for (i = 0; i < ncontended; i++)
					if (contended[i] ==
					    blued_hci_defer_q[slot].hci_fd)
						break;
				if (i == ncontended)
					break;	/* drainable candidate */
			}
			if (idx >= blued_hci_defer_count) {
				pthread_mutex_unlock(&blued_hci_defer_lock);
				break;	/* every remaining fd is contended */
			}
			/* Peek only; the entry is removed after the trylock. */
			ev = blued_hci_defer_q[slot];
			pthread_mutex_unlock(&blued_hci_defer_lock);

			/*
			 * C3-M16: resolve the owning adapter BEFORE the
			 * per-fd mutex lookup.  hci_devreq_mutex() ALLOCATES
			 * a lock slot for an fd it has not seen and there are
			 * only 8 of them, so probing a packet whose fd has
			 * already been closed permanently consumed a slot and
			 * eventually degraded the whole table to the hashed
			 * fallback.  A packet that no active adapter owns is
			 * dropped outright -- it could only be replayed
			 * against a stale adapter anyway.
			 */
			LIST_FOREACH(adp, &blued_g.adapters, entries)
				if (adp->active && adp->hci_fd == ev.hci_fd)
					break;
			if (adp == NULL) {
				pthread_mutex_lock(&blued_hci_defer_lock);
				blued_hci_defer_drop_at(idx);
				pthread_mutex_unlock(&blued_hci_defer_lock);
				continue;
			}

			hci_mtx = hci_devreq_mutex(ev.hci_fd);
			if (pthread_mutex_trylock(hci_mtx) != 0) {
				/* Waiter still owns this fd; try another. */
				if (ncontended < (int)nitems(contended))
					contended[ncontended++] = ev.hci_fd;
				continue;
			}
			pthread_mutex_unlock(hci_mtx);

			/*
			 * Remove the peeked entry.  Only this (main) thread
			 * dequeues and workers only append, so IDX still
			 * names the same entry.
			 */
			pthread_mutex_lock(&blued_hci_defer_lock);
			blued_hci_defer_drop_at(idx);
			pthread_mutex_unlock(&blued_hci_defer_lock);
			got = true;
			break;
		}
		if (!got)
			return;

		/*
		 * C3-M15: last-moment re-probe.  If a worker grabbed the fd
		 * between the selection probe and here, requeue at the front
		 * (order preserved) and leave; the ring-driven kick retries
		 * once the mutex is released.  Returning rather than looping
		 * is deliberate: the per-iteration contended[] set is reset at
		 * the top of the outer loop, so continuing would re-select the
		 * very same entry and spin.
		 */
		if (pthread_mutex_trylock(hci_mtx) != 0) {
			if (!blued_hci_defer_push_front(&ev))
				warnx("deferred HCI event ring full on "
				    "requeue; dropping one event");
			return;
		}
		pthread_mutex_unlock(hci_mtx);
		blued_hci_event_process(adp, ev.pkt, (ssize_t)ev.len);
	}
}

/*
 * The raw-HCI read is guarded by a conditional trylock (held iff the
 * per-fd devreq mutex exists and was free); clang's thread-safety
 * analysis cannot follow the NULL-guarded trylock/unlock pair, as with
 * the other conditional-lock helpers in this daemon (see smp_keys.c).
 */
void __attribute__((no_thread_safety_analysis))
blued_handle_hci_event(struct blued_adapter *adp)
{
	uint8_t buf[3 + NG_HCI_EVENT_PKT_SIZE];
	ssize_t n;
	pthread_mutex_t *hci_mtx;

	if (adp == NULL)
		return;

	/*
	 * Replay parked events BEFORE reading new ones off the socket: a
	 * deferred event is always OLDER than whatever is pending on the fd,
	 * yet the ring used to drain only from the setup-pipe sweep, so a
	 * same-batch hci-fd event could be processed first (e.g. a stale
	 * parked Disconnection Complete tearing down a NEW connection on a
	 * reused handle).  The drain is trylock-guarded; if a waiter still owns
	 * the fd it leaves the ring for the pipe-kicked sweep.  (It is
	 * best-effort, not proof against blocking -- see C3-M15 in
	 * blued_hci_defer_drain().)
	 */
	blued_hci_defer_drain();

	/*
	 * Finding 43: the event loop and detached setup threads (bt_devreq /
	 * hci_wait_encryption) both recv() this one raw HCI fd; whichever wins
	 * steals the other's packet — spurious devreq timeouts, pairing stalls.
	 * Serialise the read through the same per-fd mutex the devreq callers
	 * use.  trylock (not lock): if a devreq owns the fd right now, leave the
	 * event pending — EVFILT_READ is level-triggered, so kqueue re-notifies
	 * once the devreq releases — rather than block the whole event loop.
	 * The mutex is dropped immediately after the read so the event handlers
	 * below (which issue their own devreq-locking HCI commands) do not
	 * self-deadlock on it.
	 */
	hci_mtx = hci_devreq_mutex(adp->hci_fd);
	if (hci_mtx != NULL && pthread_mutex_trylock(hci_mtx) != 0)
		return;
	do {
		n = recv(adp->hci_fd, buf, sizeof(buf), MSG_DONTWAIT);
	} while (n < 0 && errno == EINTR);
	if (hci_mtx != NULL)
		pthread_mutex_unlock(hci_mtx);
	blued_hci_event_process(adp, buf, n);
}

/*
 * Process one raw HCI event packet.  Split out of blued_handle_hci_event so
 * the deferred-event drain above can feed packets a worker thread received
 * on the main loop's behalf through the exact same handling.  Runs on the
 * main thread only.
 */
static void
blued_hci_event_process(struct blued_adapter *adp, uint8_t *buf, ssize_t n)
{

	if (n < 3 || buf[0] != NG_HCI_EVENT_PKT ||
	    (size_t)n != (size_t)buf[2] + 3)
		return;
	if (n < 5)
		return;

	/*
	 * HCI event packet from raw socket includes packet type prefix:
	 * [type(1), event_code(1), param_len(1), params...]
	 * type is always 0x04 (HCI_EVENT_PKT).
	 * For LE Meta: params = [subevent(1), ...]
	 */
	uint8_t event_code = buf[1];

	/* LE Meta Event (0x3E) */
	if (event_code == 0x3E && n >= 5) {
		uint8_t subevent = buf[3];

		/* Creating a connection is no longer active after either complete
		 * event, including a failed/canceled attempt.  Wake a blocked global
		 * Random_Address transaction instead of waiting for the full period. */
		if ((subevent == 0x01 || subevent == 0x0A) && adp->powered &&
		    adp->privacy && adp->rpa_pending_global)
			(void)blued_rpa_retry_arm();

		/*
		 * Mesh bearer receive demux (broker step C).  While the mesh
		 * always-on scanner is active on this adapter, walk each report's
		 * AD structures and forward the mesh AD fields (0x29/0x2A/0x2B) to
		 * mesh subscribers; NON-mesh AD is dropped (blued_mesh_demux_report
		 * is the leak filter).  blued never parses the mesh PDU.
		 *
		 * LE Advertising Report (0x02, legacy) layout:
		 *   [type][evt][plen][subevt][num_reports]
		 *   then per report: event_type(1) addr_type(1) addr(6)
		 *   data_length(1) data[data_length] rssi(1)
		 *
		 * LE Extended Advertising Report (0x0D) layout:
		 *   [type][evt][plen][subevt][num_reports]
		 *   then per report: event_type(2) addr_type(1) addr(6)
		 *   primary_phy(1) secondary_phy(1) sid(1) tx_power(1) rssi(1)
		 *   periodic_interval(2) direct_addr_type(1) direct_addr(6)
		 *   data_length(1) data[data_length]
		 */
		if (adp->mesh_scan_active &&
		    (subevent == 0x02 || subevent == 0x0D) && n >= 5) {
			blued_mesh_walk_adv_event(buf, (size_t)n, subevent);
		}

		/* LE Connection Complete (subevent 0x01):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), role(1), addr_type(1), addr(6),
		 *  interval(2), latency(2), timeout(2), accuracy(1)]
		 * = 22 bytes total */
		if (subevent == 0x01 && n == 22 && buf[4] == 0 &&
		    adp->powered && !adp->power_quiescing) {
			uint16_t interval = get_le16(buf + 15);
			uint16_t latency = get_le16(buf + 17);
			uint16_t timeout = get_le16(buf + 19);
			const uint8_t *peer_addr = buf + 9;
			struct blued_conn *conn;

			/* Observable controller fact: status/handle/role/interval. */
			BLUED_PROBE_HCI_LE_CONN_COMPLETE(buf[4],
			    get_le16(buf + 5), buf[7], interval);

			/*
			 * Match by peer address, not con_handle,
			 * because con_handle may not be set yet
			 * in the blued_conn during connection setup.
			 */
			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter == adp &&
				    conn->controller_epoch == adp->controller_epoch &&
				    conn->addr_type == ((buf[8] & 1) != 0 ?
				    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC) &&
				    memcmp(&conn->dst, peer_addr, 6) == 0) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE Enhanced Connection Complete (subevent 0x0A):
		 * Same conn param offsets as 0x01 but with
		 * additional local/peer RPA fields.
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), role(1), addr_type(1), addr(6),
		 *  local_rpa(6), peer_rpa(6),
		 *  interval(2), latency(2), timeout(2), accuracy(1)]
		 * = 34 bytes total */
		if (subevent == 0x0A && n == 34 && buf[4] == 0 &&
		    adp->powered && !adp->power_quiescing) {
			uint16_t handle_ec = get_le16(buf + 5);
			uint16_t interval = get_le16(buf + 27);
			uint16_t latency = get_le16(buf + 29);
			uint16_t timeout = get_le16(buf + 31);
			const uint8_t *peer_addr = buf + 9;
			struct blued_conn *conn;

			/* Observable controller fact: status/handle/role/interval. */
			BLUED_PROBE_HCI_LE_ENH_CONN_COMPLETE(buf[4], handle_ec,
			    buf[7], interval);

			/*
			 * SMP c1/f5/f6 bind the cryptographic transcript to the
			 * addresses actually used on air.  Local_RPA is zero when the
			 * controller used the identity address.  Record this before
			 * pairing; the helper also caches an event that beats accept().
			 */
			blued_conn_note_enhanced(adp, handle_ec, peer_addr, buf[8],
			    buf + 15, buf + 21);

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter == adp &&
				    conn->controller_epoch == adp->controller_epoch &&
				    ((conn->addr_type == ((buf[8] & 1) != 0 ?
				    BDADDR_LE_RANDOM : BDADDR_LE_PUBLIC) &&
				    memcmp(&conn->dst, peer_addr, 6) == 0) ||
				    (conn->con_handle_valid &&
				    conn->con_handle == handle_ec))) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE Connection Update Complete (subevent 0x03):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), interval(2), latency(2), timeout(2)]
		 * = 13 bytes total */
		if (subevent == 0x03 && n == 13 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint16_t interval = get_le16(buf + 7);
			uint16_t latency = get_le16(buf + 9);
			uint16_t timeout = get_le16(buf + 11);
			struct blued_conn *conn;

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter == adp && conn->con_handle_valid &&
				    conn->con_handle == handle) {
					conn->conn_interval = interval;
					conn->conn_latency = latency;
					conn->supervision_timeout = timeout;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}

		/* LE PHY Update Complete (subevent 0x0C):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), tx_phy(1), rx_phy(1)] = 9 bytes total */
		if (subevent == 0x0C && n == 9 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint8_t tx_phy = buf[7];
			uint8_t rx_phy = buf[8];

			LOG_HCI(1, "PHY update: handle=%04x tx=%s rx=%s",
			    handle,
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
		}

		/* LE Read Remote Features Complete (subevent 0x04):
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  handle(2), features(8)] = 15 bytes total */
		if (subevent == 0x04 && n == 15 && buf[4] == 0) {
			uint16_t handle = get_le16(buf + 5);
			uint64_t features;

			memcpy(&features, buf + 7, 8);
			LOG_HCI(1, "remote features: handle=%04x "
			    "features=0x%016llx", handle,
			    (unsigned long long)features);
		}

		/* LE LTK Request (subevent 0x05):
		 * [type(1), evt(1), len(1), subevent(1), handle(2),
		 *  random(8), ediv(2)] = 16 bytes total */
		if (subevent == 0x05 && n == 16) {
			uint16_t handle = get_le16(buf + 4);
			uint64_t rand_val;
			uint16_t ediv;

			memcpy(&rand_val, buf + 6, 8);
			ediv = get_le16(buf + 14);

			/* Observable fact: handle/ediv/rand (never the LTK itself). */
			BLUED_PROBE_HCI_LE_LTK_REQUEST(handle, ediv,
			    (int64_t)rand_val);

			LOG_SMP(1, "LTK request: handle=%04x ediv=%04x",
			    handle, ediv);

			/* Find the bond for this connection */
			if (blued_g.bond_db != NULL) {
				struct blued_conn *conn;
				struct smp_bond *bond = NULL;
				uint8_t ltk_copy[16];
				bool has_ltk = false;
				bool smp_owns = false;

				/*
				 * Look up bond under conns_lock, copy LTK
				 * into a local, then release the lock before
				 * issuing HCI commands that do blocking I/O.
				 *
				 * Lock ordering: conns_lock -> bond_db_lock.
				 */
				pthread_rwlock_rdlock(&blued_g.conns_lock);
				LIST_FOREACH(conn, &blued_g.conns, entries) {
					if (conn->adapter == adp &&
					    conn->con_handle_valid &&
					    conn->con_handle == handle) {
						/*
						 * C3-D31: a pairing worker is
						 * mid-handshake on this
						 * handle and owns the LTK
						 * response.  Answer NOTHING
						 * -- a reply from the stale
						 * bond, or a negative reply,
						 * would earn one of the two
						 * Command Disallowed and
						 * either abort the pairing or
						 * drop the link on MIC
						 * failure.
						 */
						if (atomic_load_explicit(
						    &conn->smp_owns_ltk,
						    memory_order_acquire)) {
							smp_owns = true;
							break;
						}
						pthread_mutex_lock(
						    &blued_g.bond_db_lock);
						bond = smp_find_bond(
						    blued_g.bond_db,
						    (const uint8_t *)&conn->dst,
						    conn->addr_type);
						if (bond != NULL &&
						    bond->has_ltk) {
							/*
							 * Validate EDIV/Rand.  A
							 * legacy bond matches its
							 * stored EDIV/Rand.
							 * Finding S-m4: a Secure
							 * Connections bond is only
							 * ever addressed by
							 * EDIV=0/Rand=0 (Core Spec
							 * Vol 3 Part H §2.4.4); a
							 * reconnect LTK request
							 * carrying a non-zero
							 * EDIV/Rand is not this bond,
							 * so refuse it rather than
							 * returning the SC LTK.
							 */
							bool match;

							if (bond->is_sc)
								match = (ediv == 0 &&
								    rand_val == 0);
							else
								match = (bond->ediv ==
								    ediv &&
								    memcmp(&bond->rand,
								    &rand_val, 8) == 0);
							if (!match) {
								/* EDIV/Rand mismatch */
								LOG_SMP(1,
								    "EDIV/Rand mismatch "
								    "for handle=%04x",
								    handle);
							} else {
								memcpy(ltk_copy,
								    bond->ltk, 16);
								has_ltk = true;
							}
						}
						pthread_mutex_unlock(
						    &blued_g.bond_db_lock);
						break;
					}
				}
				pthread_rwlock_unlock(&blued_g.conns_lock);

				/*
				 * Issue HCI commands outside the lock to
				 * avoid blocking other threads on I/O.
				 */
				if (smp_owns) {
					LOG_SMP(1, "LTK request for handle="
					    "%04x owned by an in-flight SMP "
					    "session; not answering", handle);
				} else if (has_ltk) {
					if (hci_le_ltk_request_reply(
					    adp->hci_fd, handle,
					    ltk_copy) == 0) {
						LOG_SMP(1, "LTK reply sent "
						    "for handle=%04x", handle);
						/*
						 * Encryption state will be set
						 * asynchronously when the
						 * Encryption Change event
						 * (0x08) arrives.
						 */
					} else {
						warn("LTK reply failed");
					}
					explicit_bzero(ltk_copy,
					    sizeof(ltk_copy));
				} else {
					LOG_SMP(1, "no bond for handle=%04x, "
					    "sending negative reply", handle);
					hci_le_ltk_request_neg_reply(
					    adp->hci_fd, handle);
				}
			} else {
				hci_le_ltk_request_neg_reply(
				    adp->hci_fd, handle);
			}
		}

		/*
		 * Finding H-M2: LE Advertising Set Terminated (subevent 0x12).
		 * [type(1), evt(1), len(1), subevent(1), status(1),
		 *  adv_handle(1), conn_handle(2), num_completed_ext_adv_events(1)]
		 * The controller has stopped this advertising set (a connection
		 * was established on it, or its duration / max extended advertising
		 * events elapsed).  Clear the host-side enabled flag for the
		 * terminated handle so the RPA-rotation and privacy re-enable paths
		 * do not act on a set the controller already stopped.
		 */
		if (subevent == 0x12 && n == 9) {
			uint8_t adv_handle = buf[5];

			for (size_t i = 0; i < nitems(adp->ext_adv_sets); i++) {
				if (adp->ext_adv_sets[i].used &&
				    adp->ext_adv_sets[i].configured &&
				    adp->ext_adv_sets[i].handle == adv_handle) {
					adp->ext_adv_sets[i].enabled = false;
					break;
				}
			}
			/*
			 * C3-L: also clear the ctl adv-set registry's enabled
			 * flag for this handle so the operator-facing view does
			 * not keep reporting a controller-stopped set as active.
			 */
			blued_ctl_adv_set_terminated(adp, adv_handle);
			if (adv_handle == 0 && adp->adv_use_extended)
				adp->adv_enabled = false;
			LOG_HCI(1, "adv set terminated: handle=%u status=0x%02x",
			    adv_handle, buf[4]);
		}

		/*
		 * BT 5.2 LE Power Control and LE Isochronous (ISO) transport
		 * meta-events.  hci_le_default_event_mask() unmasks these on the
		 * controller for each corresponding LE feature it advertises, so
		 * they arrive here, but none has a legacy connection-management
		 * arm above.  Decode them through
		 * the shared seam (blued_parse_le_meta_event) and CONSUME the
		 * report -- a structured log at an observable level is the
		 * minimal conformant action for a host that does not otherwise
		 * track per-connection tx-power or path-loss-zone state.  The
		 * seam ignores the connection-management subevents handled
		 * above (it returns > 0 for them), so calling it here is safe.
		 *
		 * ISO transport: on an established CIS/BIG, stand up its HCI
		 * ISO data path(s) (LE Setup ISO Data Path, §7.8.109) so the
		 * Controller routes isochronous payload between the air and the
		 * kernel ISO socket.  Direction follows the stream's role: a CIS
		 * is bidirectional (Input + Output); a BIS this device
		 * broadcasts sources SDUs (Input); a BIS it is synchronized to
		 * sinks SDUs (Output).  This is transport only -- the LE Audio
		 * profiles that would consume the SDUs remain out of scope.
		 */
		{
			struct blued_le_meta_report rep;
			int pr;

			pr = blued_parse_le_meta_event(buf, (size_t)n, &rep);
			if (pr == 0) {
				switch (rep.subevent) {
				case NG_HCI_LEEV_REMOTE_CONN_PARAM_REQUEST:
					/*
					 * 7.7.65.6 -- the peer asked to change
					 * the connection parameters and its
					 * Link Layer is waiting for our answer.
					 * Core Vol 6 Part B §5.1.7.2: an
					 * unanswered (masked) request is
					 * rejected on air with Unsupported
					 * Remote Feature (0x1A), which peers
					 * read as "this device does not
					 * implement the procedure" and cache,
					 * so every request MUST be answered --
					 * with the Reply (§7.8.31) when the
					 * proposal is one we would have made
					 * ourselves, and otherwise with the
					 * Negative Reply (§7.8.32) carrying
					 * Unacceptable Connection Parameters
					 * (0x3B), the code §5.1.7.2 names for
					 * a Host rejection.  A quiescing
					 * adapter still answers: declining is
					 * a rejection, not a reason to leave
					 * the peer waiting.
					 */
					LOG_HCI(1, "LE conn param request: "
					    "handle=%04x interval=%u-%u "
					    "latency=%u timeout=%u",
					    rep.connection_handle,
					    rep.conn_interval_min,
					    rep.conn_interval_max,
					    rep.conn_latency,
					    rep.supervision_timeout);
					if (adp->powered &&
					    !adp->power_quiescing &&
					    hci_le_conn_param_req_acceptable(
					    rep.conn_interval_min,
					    rep.conn_interval_max,
					    rep.conn_latency,
					    rep.supervision_timeout)) {
						(void)hci_le_remote_conn_param_req_reply(
						    adp->hci_fd,
						    rep.connection_handle,
						    rep.conn_interval_min,
						    rep.conn_interval_max,
						    rep.conn_latency,
						    rep.supervision_timeout);
					} else {
						(void)hci_le_remote_conn_param_req_neg_reply(
						    adp->hci_fd,
						    rep.connection_handle,
						    BLUED_HCI_ERR_UNACCEPTABLE_CONN_PARAMS);
					}
					break;
				case NG_HCI_LEEV_PATH_LOSS_THRESHOLD:
					/* 7.7.65.32 */
					LOG_HCI(1, "LE path loss threshold: "
					    "handle=%04x path_loss=%udB zone=%s",
					    rep.connection_handle,
					    rep.current_path_loss,
					    rep.zone_entered == 0 ? "low" :
					    rep.zone_entered == 1 ? "mid" :
					    rep.zone_entered == 2 ? "high" :
					    "reserved");
					BLUED_PROBE_PATH_LOSS(rep.connection_handle,
					    rep.current_path_loss, rep.zone_entered);
					break;
				case NG_HCI_LEEV_TX_POWER_REPORTING:
					/* 7.7.65.33 */
					LOG_HCI(1, "LE tx power report: "
					    "handle=%04x status=%u reason=%u "
					    "phy=%u tx_power=%ddBm flag=0x%02x "
					    "delta=%ddB", rep.connection_handle,
					    rep.status, rep.reason, rep.phy,
					    (int)rep.tx_power_level,
					    rep.tx_power_level_flag,
					    (int)rep.delta);
					break;
				case NG_HCI_LEEV_CIS_ESTABLISHED:
					/* 7.7.65.25 -- transport only, no audio */
					LOG_HCI(1, "LE CIS established: "
					    "handle=%04x status=%u nse=%u "
					    "iso_interval=%u",
					    rep.connection_handle, rep.status,
					    rep.nse, rep.iso_interval);
					/*
					 * Advance the pending CIS stream: on
					 * success stand up both data-path
					 * directions and ready the fd handout;
					 * on failure free it and report the loss
					 * (§7.8.109, iso.c).
					 */
					if (!adp->powered || adp->power_quiescing) {
						if (rep.status == 0)
							(void)hci_disconnect(adp->hci_fd,
							    rep.connection_handle, 0x13);
						break;
					}
					iso_on_cis_established(adp, rep.connection_handle,
					    rep.status);
					break;
				case NG_HCI_LEEV_CIS_REQUEST:
					/* 7.7.65.26 -- peripheral accept/reject */
					LOG_HCI(1, "LE CIS request: acl=%04x "
					    "cis=%04x cig_id=%u cis_id=%u",
					    rep.acl_connection_handle,
					    rep.cis_connection_handle,
					    rep.cig_id, rep.cis_id);
					if (!adp->powered || adp->power_quiescing) {
						(void)hci_le_reject_cis_request(adp->hci_fd,
						    rep.cis_connection_handle, 0x0d);
						break;
					}
					iso_on_cis_request(adp,
					    rep.acl_connection_handle,
					    rep.cis_connection_handle,
					    rep.cig_id, rep.cis_id);
					break;
				case NG_HCI_LEEV_CREATE_BIG_COMPL:
					/* 7.7.65.27 */
					LOG_HCI(1, "LE create BIG complete: "
					    "big_handle=%u status=%u num_bis=%u "
					    "iso_interval=%u", rep.big_handle,
					    rep.status, rep.num_bis,
					    rep.iso_interval);
					/*
					 * Broadcaster: record the BIS handles,
					 * set up one Input data path per BIS,
					 * and ready the fd handout (§7.8.109,
					 * iso.c).
					 */
					if (!adp->powered || adp->power_quiescing) {
						if (rep.status == 0)
							(void)hci_le_terminate_big(adp->hci_fd,
							    rep.big_handle, 0x13);
						break;
					}
					iso_on_big_complete(adp, rep.big_handle,
					    rep.status, rep.num_bis,
					    rep.bis_handles);
					break;
				case NG_HCI_LEEV_TERMINATE_BIG_COMPL:
					/* 7.7.65.28 */
					LOG_HCI(1, "LE terminate BIG complete: "
					    "big_handle=%u reason=0x%02x",
					    rep.big_handle, rep.reason_code);
					iso_on_big_terminated(adp, rep.big_handle,
					    rep.reason_code);
					break;
				case NG_HCI_LEEV_BIG_SYNC_EST:
					/* 7.7.65.29 */
					LOG_HCI(1, "LE BIG sync established: "
					    "big_handle=%u status=%u num_bis=%u",
					    rep.big_handle, rep.status,
					    rep.num_bis);
					/*
					 * Synchronized receiver: record the BIS
					 * handles, set up one Output data path
					 * per BIS, and ready the fd handout
					 * (§7.8.109, iso.c).
					 */
					if (!adp->powered || adp->power_quiescing) {
						if (rep.status == 0)
							(void)hci_le_big_terminate_sync(
							    adp->hci_fd, rep.big_handle);
						break;
					}
					iso_on_big_sync_established(adp,
					    rep.big_handle, rep.status,
					    rep.num_bis, rep.bis_handles);
					break;
				case NG_HCI_LEEV_BIG_SYNC_LOST:
					/* 7.7.65.30 */
					LOG_HCI(1, "LE BIG sync lost: "
					    "big_handle=%u reason=0x%02x",
					    rep.big_handle, rep.reason_code);
					iso_on_big_sync_lost(adp, rep.big_handle,
					    rep.reason_code);
					break;

				/*
				 * BT 5.0 Periodic Advertising (observer/sync):
				 * a periodic train is announced via extended
				 * advertising and its BIGInfo rides in the
				 * periodic adv reports.  A structured log is the
				 * minimal conformant action for a host that does
				 * not otherwise persist per-sync state.
				 */
				case NG_HCI_LEEV_PER_ADV_SYNC_EST:
					/* 7.7.65.14 */
					LOG_HCI(1, "LE periodic adv sync "
					    "established: status=%u "
					    "sync_handle=%04x sid=%u phy=%u "
					    "interval=%u",
					    rep.status, rep.sync_handle,
					    rep.advertising_sid,
					    rep.advertiser_phy,
					    rep.periodic_adv_interval);
					BLUED_PROBE_PER_ADV_SYNC(rep.sync_handle, rep.status);
					if (!adp->powered || adp->power_quiescing) {
						if (rep.status == 0)
							(void)hci_le_periodic_adv_terminate_sync(
							    adp->hci_fd, rep.sync_handle);
						break;
					}
					adp->periodic_sync_pending = false;
					if (rep.status == 0)
						adp->periodic_syncs[rep.sync_handle / 8] |=
						    (uint8_t)(1U << (rep.sync_handle % 8));
					break;
				case NG_HCI_LEEV_PER_ADV_REPORT:
					/* 7.7.65.15 */
					LOG_HCI(1, "LE periodic adv report: "
					    "sync_handle=%04x rssi=%ddBm "
					    "cte_type=%u data_status=%u len=%u",
					    rep.sync_handle, (int)rep.rssi,
					    rep.cte_type, rep.data_status,
					    rep.data_length);
					BLUED_PROBE_PER_ADV_REPORT(rep.sync_handle,
					    rep.data_length);
					break;
				case NG_HCI_LEEV_PER_ADV_SYNC_LOST:
					/* 7.7.65.16 */
					LOG_HCI(1, "LE periodic adv sync lost: "
					    "sync_handle=%04x", rep.sync_handle);
					BLUED_PROBE_PER_ADV_SYNC(rep.sync_handle, 0xff);
					adp->periodic_syncs[rep.sync_handle / 8] &=
					    (uint8_t)~(1U << (rep.sync_handle % 8));
					break;

				/*
				 * BT 5.1 Direction Finding.  IQ sample buffers
				 * feed an AoA/AoD angle estimator, which is a
				 * radio/DSP concern above this transport layer;
				 * blued logs the report envelope.
				 */
				case NG_HCI_LEEV_CONNECTIONLESS_IQ_REPORT:
					/* 7.7.65.21 */
					LOG_HCI(1, "LE connectionless IQ report: "
					    "sync_handle=%04x channel=%u "
					    "cte_type=%u samples=%u",
					    rep.sync_handle, rep.channel_index,
					    rep.cte_type, rep.sample_count);
					break;
				case NG_HCI_LEEV_CONNECTION_IQ_REPORT:
					/* 7.7.65.22 */
					LOG_HCI(1, "LE connection IQ report: "
					    "handle=%04x rx_phy=%u channel=%u "
					    "cte_type=%u samples=%u",
					    rep.connection_handle, rep.rx_phy,
					    rep.data_channel_index, rep.cte_type,
					    rep.sample_count);
					break;
				case NG_HCI_LEEV_CTE_REQUEST_FAILED:
					/* 7.7.65.23 */
					LOG_HCI(1, "LE CTE request failed: "
					    "status=0x%02x handle=%04x",
					    rep.status, rep.connection_handle);
					break;

				/*
				 * BT 5.1 Periodic Advertising Sync Transfer: a
				 * connected peer handed us sync to its periodic
				 * train (status 0 => a new sync_handle is live).
				 */
				case NG_HCI_LEEV_PER_ADV_SYNC_XFER_RCVD:
					/* 7.7.65.24 */
					LOG_HCI(1, "LE PAST received: status=%u "
					    "handle=%04x service_data=%04x "
					    "sync_handle=%04x sid=%u",
					    rep.status, rep.connection_handle,
					    rep.service_data, rep.sync_handle,
					    rep.advertising_sid);
					if (!adp->powered || adp->power_quiescing) {
						if (rep.status == 0)
							(void)hci_le_periodic_adv_terminate_sync(
							    adp->hci_fd, rep.sync_handle);
						break;
					}
					if (rep.status == 0)
						adp->periodic_syncs[rep.sync_handle / 8] |=
						    (uint8_t)(1U << (rep.sync_handle % 8));
					break;
				}
			} else if (pr < 0) {
				LOG_HCI(1, "malformed LE meta subevent 0x%02x "
				    "(%zd bytes)", subevent, n);
			}
			/* pr > 0: connection-management subevent handled above. */
		}
	}

	/* Disconnection Complete (0x05)
	 * [type(1), evt(1), len(1), status(1), handle(2), reason(1)] = 7 bytes.
	 * A CIS connection handle is a normal Disconnect target, so a peer- or
	 * controller-initiated CIS drop arrives here; route it to the ISO
	 * registry, which frees the stream and emits ISO_LOST if the handle is
	 * one it tracks (a no-op otherwise, incl. self-initiated teardown that
	 * already unlinked the stream).  ACL links are torn down separately via
	 * the ATT socket EV_EOF path, so this arm only concerns ISO. */
	if (event_code == 0x05 && n == 7 && buf[3] == 0) {
		uint16_t handle = get_le16(buf + 4);
		uint8_t reason = buf[6];

		iso_on_cis_disconnected(adp, handle, reason);
	}

	/* Core 6.3 Vol 4 Part E §7.7.8 Encryption Change v1/v2. */
	struct blued_encryption_change encryption_change;
	if (blued_parse_encryption_change(buf, (size_t)n,
	    &encryption_change) == 0) {
		uint8_t status = encryption_change.status;
		uint16_t handle = encryption_change.handle;
		uint8_t enc_enabled = encryption_change.encryption_enabled;

		if (blued_encryption_change_is_le_on(&encryption_change)) {
			struct blued_conn *conn;
			bool bond_is_mitm = false;
			/*
			 * Only open the ATT gate when this encryption is
			 * backed by a stored LTK for this peer (or the LTK a
			 * just-completed SMP session left in the bond).  The
			 * Encryption Change event alone is not trusted.
			 */
			bool have_key_material = false;
			/*
			 * Real negotiated encryption key size (Core Spec Vol 3
			 * Part H §2.3.4).  A valid persisted 7-16 value is
			 * authoritative.  Unknown migrated metadata fails closed to
			 * 7; assuming 16 could wrongly satisfy a minimum-key-size ATT
			 * permission gate.
			 */
			uint8_t enc_key_size =
			    blued_encryption_change_effective_key_size(0);

			pthread_rwlock_rdlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter == adp && conn->con_handle_valid &&
				    conn->con_handle == handle) {
					pthread_mutex_lock(
					    &blued_g.bond_db_lock);
					if (blued_g.bond_db != NULL) {
						struct smp_bond *bond;

						bond = smp_find_bond(
						    blued_g.bond_db,
						    (const uint8_t *)&conn->dst,
						    conn->addr_type);
						if (bond != NULL &&
						    bond->has_ltk)
							have_key_material = true;
						if (bond != NULL &&
						    bond->is_mitm)
							bond_is_mitm = true;
						/*
						 * key_size in [7,16] is a real
						 * persisted negotiation; 0 marks a
						 * migrated bond of unknown size (use
						 * the conservative 7-octet floor).
						 */
						if (bond != NULL)
							enc_key_size =
							    blued_encryption_change_effective_key_size(
							    bond->key_size);
					}
					pthread_mutex_unlock(
					    &blued_g.bond_db_lock);
					/*
					 * conn->att is owned by the connection.  Keep the
					 * registry read lock through this write so teardown
					 * cannot unlink and free it between lookup and use.
					 * att_sec_lock serialises the security-state write
					 * against ctl_elevate_security / the setup thread
					 * (finding 95).
					 */
					pthread_mutex_lock(&blued_g.att_sec_lock);
					if (conn->att != NULL &&
					    !att_conn_apply_encryption(conn->att,
					    have_key_material, bond_is_mitm, 0,
					    enc_key_size))
						LOG_SMP(1, "encryption change "
						    "handle=%04x not backed by known "
						    "key material; ATT gate stays "
						    "closed", handle);
					pthread_mutex_unlock(&blued_g.att_sec_lock);
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
			hci_le_write_auth_payload_timeout(
			    adp->hci_fd, handle, 3000);
			/* Observable fact: status/handle/enabled/key-size (no keys). */
			BLUED_PROBE_HCI_ENC_CHANGE(status, handle, enc_enabled,
			    enc_key_size);
			LOG_SMP(1, "encryption change: handle=%04x "
			    "enabled=%d", handle, enc_enabled);
		} else {
			struct blued_conn *conn;

			/* A failed or disabled encryption transition closes every
			 * authorization gate immediately.  The fixed ATT bearer remains,
			 * but EATT cannot survive an unencrypted ACL (GATT 5.3.2). */
			pthread_rwlock_rdlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter != adp || !conn->con_handle_valid ||
				    conn->con_handle != handle || conn->att == NULL)
					continue;
				/* Serialise the security-state clear + EATT teardown
				 * against other att writers (finding 95). */
				pthread_mutex_lock(&blued_g.att_sec_lock);
				conn->att->encrypted = false;
				conn->att->authenticated = false;
				conn->att->enc_key_size = 0;
				att_close_eatt(conn->att);
				pthread_mutex_unlock(&blued_g.att_sec_lock);
				break;
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
		}
	}

	/* Encryption Key Refresh Complete (0x30): failure means the link can no
	 * longer be trusted as encrypted.  Success preserves the established gates;
	 * the controller keeps encryption active across the permitted refresh. */
	if (event_code == NG_HCI_EVENT_ENCRYPTION_KEY_REFRESH && n == 6 &&
	    buf[3] != 0) {
		uint16_t handle = get_le16(buf + 4);
		struct blued_conn *conn;

		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(conn, &blued_g.conns, entries) {
			if (conn->adapter != adp || !conn->con_handle_valid ||
			    conn->con_handle != handle || conn->att == NULL)
				continue;
			pthread_mutex_lock(&blued_g.att_sec_lock);	/* finding 95 */
			conn->att->encrypted = false;
			conn->att->authenticated = false;
			conn->att->enc_key_size = 0;
			att_close_eatt(conn->att);
			pthread_mutex_unlock(&blued_g.att_sec_lock);
			break;
		}
		pthread_rwlock_unlock(&blued_g.conns_lock);
	}

	/* Authenticated Payload Timeout Expired (0x57)
	 * [type(1), evt(1), len(1), handle(2)] = 5 bytes */
	if (event_code == 0x57 && n == 5) {
		uint16_t handle = get_le16(buf + 3);
		struct blued_conn *conn;

		LOG_SMP(1, "auth payload timeout expired: handle=%04x",
		    handle);
		BLUED_LOG_SECURITY("auth payload timeout expired "
		    "handle=%04x — disconnecting", handle);

		{
			bool found = false;

			pthread_rwlock_rdlock(&blued_g.conns_lock);
			LIST_FOREACH(conn, &blued_g.conns, entries) {
				if (conn->adapter == adp && conn->con_handle_valid &&
				    conn->con_handle == handle) {
					atomic_store_explicit(
					    &conn->needs_cleanup, true,
					    memory_order_release);
					found = true;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
			/* Signal main loop to process the cleanup */
			if (found) {
				uint8_t sig = 1;
				(void)write(blued_g.setup_pipe[1], &sig, 1);
			}
		}
	}
}

/*
 * Handle loss of a controller (HCI fd EOF/error) — for example a USB
 * dongle unplugged at runtime.  The readable filter on the HCI fd would
 * otherwise report EOF on every kqueue pass and spin the event loop.
 *
 * Under Capsicum the daemon cannot re-open the device node after
 * cap_enter(), so recovery is a clean, well-defined degraded state:
 * stop watching the dead fd, tear down every connection bound to the
 * adapter (without attempting the futile reconnect), mark the adapter
 * absent, and log an actionable message.  A daemon restart is required
 * to pick a re-attached controller back up.
 */
static void
blued_adapter_lost(struct blued_adapter *a)
{
	struct kevent kev;
	struct blued_conn *c, *tmp;
	int torn = 0;

	if (!a->active)
		return;		/* already handled */
	blued_periph_readvertise_cancel(a);

	/* Stop the busy-spin: remove the dead fd from the kqueue. */
	EV_SET(&kev, a->hci_fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

	/* Tear down connections bound to this adapter; do not reconnect. */
	LIST_FOREACH_SAFE(c, &blued_g.conns, entries, tmp) {
		if (c->adapter != a)
			continue;
		c->reconnect = false;
		blued_conn_disconnect(c);
		torn++;
	}
	/* The dead controller no longer owns these objects.  Drop their host
	 * registrations and acquired descriptors without issuing HCI teardown. */
	blued_iso_reset_adapter(a);
	a->periodic_adv_enabled = false;
	a->periodic_sync_pending = false;
	memset(a->periodic_syncs, 0, sizeof(a->periodic_syncs));

	a->active = false;
	/*
	 * Release the fd-keyed side tables (devreq lock slot, scan own-address
	 * type, mesh legacy-adv record).  They are only ever released on a
	 * clean close, so a runtime controller loss leaked a slot in each:
	 * after BLUED_MAX_ADAPTERS losses the lock table degrades to shared
	 * hashed mutexes and the scan-state table starts silently refusing
	 * new adapters (which then scan from the public identity address).
	 * The mesh record goes with them -- the dead controller dropped the
	 * advertisement, and a stale record would let a later stop disable a
	 * future adapter's OWN advertising on a recycled fd.
	 */
	hci_fd_closed(a->hci_fd);

	warnx("BLE: controller %s lost (HCI fd EOF); tore down %d "
	    "connection(s), entering degraded state -- restart the daemon "
	    "to recover the controller", a->name, torn);
}

/*
 * Control clients reaped during the current kevent batch, freed only once the
 * batch is fully processed (C3-M9).
 *
 * The stale-event guard is `ev->udata == client && ev->ident == client->fd`,
 * and within ONE batch both halves are forgeable: a client accepted later in
 * the same batch can get the departed client's fd number back from the kernel
 * AND its heap address back from malloc, so a stale EVFILT_WRITE would tear
 * down a brand-new, unrelated client.  Withholding the free() for the rest of
 * the batch makes the address unforgeable, which makes the pair unforgeable.
 * Main thread only; the list borrows the client's now-unused list linkage.
 */
static LIST_HEAD(, blued_ctl_client) blued_ctl_reaped =
    LIST_HEAD_INITIALIZER(blued_ctl_reaped);

static void
blued_ctl_client_retire(struct blued_ctl_client *client)
{

	LIST_INSERT_HEAD(&blued_ctl_reaped, client, entries);
}

static void
blued_ctl_reaped_free(void)
{
	struct blued_ctl_client *client;

	while ((client = LIST_FIRST(&blued_ctl_reaped)) != NULL) {
		LIST_REMOVE(client, entries);
		free(client);
	}
}

static void
blued_handle_readable(struct kevent *ev)
{
	struct blued_conn *conn;
	struct blued_ctl_client *client;

	/* Check if the event is from an adapter HCI fd */
	{
		struct blued_adapter *a;

		LIST_FOREACH(a, &blued_g.adapters, entries) {
			if (ev->udata == a) {
				if ((int)ev->ident == a->periph_listen_fd) {
					blued_periph_accept(a);
					return;
				}
				if ((int)ev->ident == a->eatt_listen_fd) {
					blued_eatt_accept(a);
					return;
				}
				if ((int)ev->ident != a->hci_fd)
					continue;
				/*
				 * EV_EOF on the HCI fd means the controller
				 * went away; recover into a degraded state
				 * instead of spinning on a dead descriptor.
				 */
				if (ev->flags & EV_EOF)
					blued_adapter_lost(a);
				else
					blued_handle_hci_event(a);
				return;
			}
		}
	}

	if (ev->udata == BLUED_KQ_SETUP_PIPE) {
		struct blued_conn *c, *tmp;
		char buf[32];
		bool readv;

		(void)read(blued_g.setup_pipe[0], buf, sizeof(buf));

		/*
		 * First replay any raw HCI events a blocking waiter drained
		 * on the main loop's behalf (hci_event_defer_hook).
		 */
		blued_hci_defer_drain();

		/*
		 * Sweep conns flagged by setup threads.
		 * This runs in the main thread so LIST_REMOVE is safe.
		 * Use acquire to pair with the release store in the
		 * setup thread failure helpers.
		 */
		LIST_FOREACH_SAFE(c, &blued_g.conns, entries, tmp) {
			/*
			 * needs_cleanup is terminal (APTO / non-reconnect setup
			 * failure): tear the conn down now and free it.  Handle
			 * it FIRST so a coincident disconnect_pending can't
			 * `continue` past it and strand a conn that no longer
			 * has a setup thread to re-signal the pipe.  For a
			 * central conn this releases the hogp/att/vhid that
			 * blued_conn_free alone leaks (findings 59, 60).
			 */
			if (atomic_load_explicit(&c->needs_cleanup,
			    memory_order_acquire)) {
				/*
				 * A CONNECTING conn is still owned by its
				 * detached setup thread, which keeps
				 * dereferencing conn/hogp through blocking
				 * discovery and pairing (finding 86).  Defer
				 * exactly as blued_conn_disconnect does:
				 * latch disconnect_pending and leave
				 * needs_cleanup set; both setup-thread exit
				 * paths re-signal the pipe, so this sweep
				 * runs again once the thread is done.
				 */
				if (atomic_load(&c->state) ==
				    BLUED_CONN_CONNECTING) {
					atomic_store_explicit(
					    &c->disconnect_pending, true,
					    memory_order_release);
					continue;
				}
				/*
				 * Finding H-H2: a GATT worker (or the central
				 * pairing worker) may still be mid-ATT,
				 * dereferencing c->att / c->hogp.  The terminal
				 * APTO teardown must defer until every in-flight
				 * ATT op retires, exactly as the EV_EOF path
				 * does — otherwise blued_conn_central_teardown
				 * frees att/hogp under the worker (UAF on
				 * job->conn->att->mtu et al).  Set
				 * disconnect_pending BEFORE reading
				 * att_ops_active so a worker retiring right now
				 * (which re-signals the pipe only while
				 * disconnect_pending is set) cannot be missed;
				 * needs_cleanup stays set so the re-signalled
				 * sweep finishes the teardown.
				 */
				atomic_store_explicit(&c->disconnect_pending,
				    true, memory_order_seq_cst);
				if (atomic_load_explicit(&c->att_ops_active,
				    memory_order_seq_cst) != 0)
					continue;
				(void)atomic_exchange_explicit(
				    &c->disconnect_pending, false,
				    memory_order_acq_rel);
				/*
				 * If the link had been announced up, tell the
				 * push-events clients it is gone before the
				 * conn disappears (finding 59).
				 */
				if (c->announced) {
					c->announced = false;
					blued_ctl_broadcast_conn_event(&c->dst,
					    c->role, c->addr_type,
					    (uint8_t)c->adapter->index,
					    c->con_handle, 0, false, 0);
				}
				ctl_acquire_conn_gone(c);
				ctl_gatt_conn_gone(c);
				/*
				 * A bonded peripheral peer's CCCD writes must
				 * survive a terminal teardown too, exactly as
				 * they do in blued_conn_disconnect.
				 */
				if (c->role == BLUED_ROLE_PERIPHERAL)
					blued_periph_save_cccds(c);
				blued_conn_central_teardown(c);
				/*
				 * Consume a pending readvertise request
				 * (blued_periph_setup_fail) before the conn
				 * is freed, or the adapter stays silent.  For
				 * a PERIPHERAL conn re-advertise
				 * unconditionally (idempotent): a terminal
				 * teardown here (e.g. APTO) frees the slot,
				 * and relying on the flag alone left the
				 * adapter permanently silent whenever the
				 * teardown was not a setup failure.
				 */
				readv = atomic_exchange_explicit(
				    &c->needs_readvertise, false,
				    memory_order_acq_rel) ||
				    c->role == BLUED_ROLE_PERIPHERAL;
				blued_conn_free(c);
				if (readv)
					blued_periph_readvertise();
				continue;
			}
			if (atomic_exchange_explicit(&c->disconnect_pending, false,
			    memory_order_acq_rel)) {
				/*
				 * Finding 45's guard makes blued_conn_disconnect()
				 * a NO-OP for a conn already awaiting its
				 * reconnect timer.  Consuming disconnect_pending
				 * must not also swallow a pending
				 * needs_reconnect_arm in that case: nothing
				 * would write the setup pipe again, so the conn
				 * sat in RECONNECTING forever holding one of the
				 * BLUED_MAX_CONNS slots with no timer armed.
				 * Fall through to the arm check for exactly that
				 * conn; every other disconnect may free C, so it
				 * still stops here.
				 */
				if (atomic_load(&c->state) !=
				    BLUED_CONN_RECONNECTING || !c->reconnect) {
					blued_conn_disconnect(c);
					continue;
				}
			}
			/*
			 * A central setup thread flagged a failed attempt for
			 * retry (blued_central_setup_fail): arm the reconnect
			 * ONESHOT here, on the main thread, so the arm cannot
			 * race a main-thread teardown that frees the conn with
			 * a timer (udata=conn) still pending.
			 */
			if (atomic_exchange_explicit(&c->needs_reconnect_arm,
			    false, memory_order_acq_rel)) {
				if (atomic_load(&c->state) ==
				    BLUED_CONN_RECONNECTING && c->reconnect) {
					struct kevent rkev;

					if (c->reconnect_delay == 0)
						c->reconnect_delay = 3;
					LOG_HOGP(1, "reconnecting in %d "
					    "seconds...", c->reconnect_delay);
					c->reconnect_timer =
					    blued_next_timer_id++;
					EV_SET(&rkev, c->reconnect_timer,
					    EVFILT_TIMER,
					    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
					    c->reconnect_delay, c);
					(void)kevent(blued_g.kq, &rkev, 1,
					    NULL, 0, NULL);

					c->reconnect_delay *= 2;
					if (c->reconnect_delay >
					    blued_reconnect_max_delay)
						c->reconnect_delay =
						    blued_reconnect_max_delay;
				}
				continue;
			}
			if (atomic_load_explicit(&c->needs_readvertise,
			    memory_order_acquire)) {
				atomic_store(&c->needs_readvertise, false);
				blued_periph_readvertise();
			}
			/*
			 * A setup thread transitioned this connection to ACTIVE
			 * (findings C1/C2): push EVENT CONNECTED once, now that
			 * the LE link + ATT channel are really up, carrying the
			 * negotiated MTU (finding C5).
			 */
			if (!c->announced && c->con_handle_valid &&
			    atomic_load_explicit(&c->state,
			    memory_order_acquire) == BLUED_CONN_ACTIVE) {
				c->announced = true;
				blued_ctl_broadcast_conn_event(&c->dst,
				    c->role, c->addr_type, (uint8_t)c->adapter->index,
				    c->con_handle,
				    c->att != NULL ? c->att->mtu : 0,
				    true, 0);
			}
		}
		return;
	}

	if (ev->udata == BLUED_KQ_CTL_LISTEN) {
		blued_ctl_accept();
		return;
	}

	/*
	 * switchboard supervisor fd: readable/EV_EOF means the switchboard
	 * connection is gone.  Log the loss once and drop the registration;
	 * the level-triggered event would otherwise busy-spin the loop.
	 * The real stop path remains SIGTERM/pdkill.
	 */
	if (ev->udata == BLUED_KQ_SUPERVISOR) {
		struct kevent kev;

		warnx("switchboard supervisor connection lost; continuing "
		    "unsupervised");
		EV_SET(&kev, ev->ident, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		return;
	}

	/*
	 * AcquireNotify/AcquireWrite daemon-side SEQPACKET fd: a WRITE acquire's
	 * client datagrams become ATT writes here; client-close (EV_EOF) tears
	 * the acquire down.  Keyed by fd inside ctl_acquire_dispatch.
	 */
	if (ev->udata == BLUED_KQ_ACQUIRE) {
		ctl_acquire_dispatch(ev);
		return;
	}

	/*
	 * A bonded peripheral peer sent a Pairing Request after its connection
	 * was already up (key loss, or answering a Security Request).  The
	 * responder blocks for the whole handshake, so it is dispatched to a
	 * worker thread; keyed by fd, never by conn udata.
	 */
	if (ev->udata == BLUED_KQ_SMP) {
		blued_periph_smp_late_event((int)ev->ident,
		    (ev->flags & EV_EOF) != 0);
		return;
	}

	/* Check if it's a vhid Output report */
	if (ev->udata == BLUED_KQ_VHID_OUTPUT) {
		struct blued_conn *vc;

		/*
		 * Find the central HOGP connection that owns this vhid fd
		 * by matching the kqueue event ident to the hogp vhid_fd.
		 */
		struct hogp_device *vhogp = NULL;

		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(vc, &blued_g.conns, entries) {
			if (vc->hogp != NULL &&
			    vc->hogp->vhid_fd == (int)ev->ident) {
				vhogp = vc->hogp;
				break;
			}
		}
		pthread_rwlock_unlock(&blued_g.conns_lock);
		if (vhogp != NULL) {
			hogp_handle_vhid_output(vhogp);
			return;
		}
		LOG_HOGP(2, "vhid output event for unknown fd %lu",
		    (unsigned long)ev->ident);
		return;
	}

	/* Check if it's a control client */
	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		/*
		 * Require the ident to still be this client's fd: a stale
		 * event whose udata aliases a freed client's recycled
		 * allocation must not dispatch (or tear down) the new
		 * client through the wrong descriptor.
		 */
		if (ev->udata == client && (int)ev->ident == client->fd) {
			if ((ev->flags & EV_EOF) ||
			    blued_ctl_dispatch(client) < 0) {
				/* Client disconnected or error */
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
				blued_ctl_client_reap(client);
				blued_ctl_client_retire(client);
				return;
			}
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			return;
		}
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);

	/* Check if it's a device connection */
	pthread_rwlock_rdlock(&blued_g.conns_lock);
	LIST_FOREACH(conn, &blued_g.conns, entries) {
		if (ev->udata == conn) {
			pthread_rwlock_unlock(&blued_g.conns_lock);
			/*
			 * This event may have been returned by kevent immediately before a
			 * control request transferred receive ownership to a synchronous
			 * GATT worker.  EV_DISABLE does not revoke an already-returned event;
			 * never let that stale event consume the worker's correlated ATT
			 * response (on either fixed ATT or EATT).
			 */
			if (!blued_conn_att_event_ready(conn))
				return;
			if (conn->att != NULL &&
			    (int)ev->ident != conn->att_fd) {
				/*
				 * Readable event on an Enhanced ATT (EATT)
				 * bearer — a dynamic L2CAP CoC channel that
				 * carries ATT PDUs in parallel with the fixed
				 * ATT channel (Core Spec Vol 3 Part G §5.3).
				 * Dispatch on the bearer's own fd/MTU so the
				 * response returns on the same bearer; on EOF
				 * tear down only that bearer, not the whole
				 * connection.
				 */
				int bfd = (int)ev->ident;
				int bi;
				uint16_t bmtu = ATT_DEFAULT_MTU;

				for (bi = 0; bi < conn->att->eatt_count; bi++) {
					if (conn->att->eatt[bi].fd == bfd) {
						bmtu = conn->att->eatt[bi].mtu;
						break;
					}
				}
				/* A conn-tagged non-primary fd must be a live bearer. */
				if (bi == conn->att->eatt_count)
					return;

				if (ev->flags & EV_EOF) {
					att_eatt_remove_bearer(conn->att, bfd);
					return;
				}

				if (conn->role == BLUED_ROLE_CENTRAL) {
					if (hogp_event_loop_bearer(conn, bfd,
					    bmtu) < 0)
						att_eatt_remove_bearer(conn->att,
						    bfd);
					else
						blued_idle_arm(conn);
				} else {
					uint8_t fixed[ATT_PDU_BUF_SIZE], *buf;
					ssize_t nr;

					buf = bmtu <= sizeof(fixed) ? fixed : malloc(bmtu);
					if (buf == NULL) {
						att_eatt_remove_bearer(conn->att, bfd);
						return;
					}

					nr = att_recv_record(bfd, buf, bmtu);
					if (nr <= 0) {
						if (buf != fixed)
							free(buf);
						att_eatt_remove_bearer(
						    conn->att, bfd);
					} else {
						/*
						 * C3-D28: the same
						 * was_pending / disarm bracket
						 * the primary bearer uses
						 * below.  ind_pending and the
						 * 30 s indication timer are
						 * per-connection, not
						 * per-bearer, so a Handle
						 * Value Confirmation arriving
						 * over EATT cleared the flag
						 * but left the timer armed --
						 * and it later disconnected a
						 * perfectly healthy link.
						 */
						bool was_pending =
						    conn->att->ind_pending;

						pthread_mutex_lock(
						    &blued_g.gatt_db_lock);
						att_server_handle(conn->att,
						    conn->gatt_db, buf,
						    (size_t)nr, bfd, bmtu);
						pthread_mutex_unlock(
						    &blued_g.gatt_db_lock);
						if (buf != fixed)
							free(buf);
						if (was_pending &&
						    !conn->att->ind_pending)
							blued_ind_disarm_timeout(
							    conn);
						blued_idle_arm(conn);
					}
				}
				return;
			}
			if (ev->flags & EV_EOF) {
				blued_conn_disconnect(conn);
			} else if (conn->role == BLUED_ROLE_PERIPHERAL) {
				uint8_t buf[ATT_PDU_BUF_SIZE];
				ssize_t nr;

				/*
				 * The ATT state is required to service this
				 * readable event; every other peripheral path
				 * in this file guards it.  If it is absent the
				 * channel is unusable — tear the connection
				 * down rather than dereference a NULL att.
				 */
				if (conn->att == NULL) {
					blued_conn_disconnect(conn);
					return;
				}

				nr = att_recv_record(conn->att_fd, buf, sizeof(buf));
				if (nr <= 0) {
					LOG_ATT(1, "peripheral recv: %s",
					    nr == 0 ? "closed" :
					    strerror(errno));
					blued_conn_disconnect(conn);
				} else {
					bool was_pending =
					    conn->att->ind_pending;
					pthread_mutex_lock(
					    &blued_g.gatt_db_lock);
					att_server_handle(conn->att,
					    conn->gatt_db, buf, (size_t)nr,
					    -1, 0);
					pthread_mutex_unlock(
					    &blued_g.gatt_db_lock);
					/* Disarm timeout on confirmation */
					if (was_pending &&
					    !conn->att->ind_pending)
						blued_ind_disarm_timeout(conn);
					/* Reset idle timer on activity */
					blued_idle_arm(conn);
				}
			} else {
				hogp_event_loop_once(conn);
			}
			return;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);

	LOG_HOGP(1, "unhandled kqueue event: fd=%lu filter=%d flags=0x%x "
	    "udata=%p", (unsigned long)ev->ident, ev->filter,
	    ev->flags, ev->udata);
}

static void
blued_handle_writable(struct kevent *ev)
{
	struct blued_ctl_client *client;

	pthread_mutex_lock(&blued_g.ctl_clients_lock);
	LIST_FOREACH(client, &blued_g.ctl_clients, entries) {
		/* Stale-event defense: ident must match the fd (see the
		 * readable-path client match). */
		if (ev->udata != client || (int)ev->ident != client->fd)
			continue;
		if ((ev->flags & EV_EOF) || blued_ctl_flush(client) < 0) {
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			blued_ctl_client_reap(client);
			blued_ctl_client_retire(client);
			return;
		}
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

/*
 * Open a fresh kevent batch: clients reaped while processing the PREVIOUS one
 * can no longer be aliased by any event in it, so their memory is releasable
 * now (C3-M9), and the acquire registry gets a new identity epoch (C3-L17).
 * Both must happen before a single event of this batch is dispatched.
 */
void
blued_event_batch_begin(void)
{

	blued_ctl_reaped_free();
	ctl_acquire_batch_begin();
}

/*
 * Dispatch one kevent batch.  Returns false when the batch asked the daemon to
 * stop (a non-SIGHUP signal event, or `running' cleared by a handler); the
 * caller then releases the reaped clients and leaves the loop.
 *
 * Split out of blued_event_loop() so the batch -- which is a pure function of
 * (event array, current daemon state) -> (actions) -- can be driven from a
 * test with a synthetic array: the stale-descriptor, recycled-allocation and
 * intra-batch ordering cases are otherwise unreachable without racing a real
 * controller.
 */
bool
blued_event_dispatch_batch(struct kevent *events, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		if (events[i].filter == EVFILT_SIGNAL) {
			if (events[i].ident == SIGHUP) {
				LOG_HOGP(1, "SIGHUP received, "
				    "reloading configuration");
				blued_reload_config();
				continue;
			}
			LOG_HOGP(1, "signal %lu, shutting down",
			    (unsigned long)events[i].ident);
			running = 0;
			return (false);
		}
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_IDLE_TIMEOUT) {
			/*
			 * Idle connection timeout.  Disconnect
			 * peripheral clients that send no ATT
			 * PDUs for BLUED_IDLE_TIMEOUT_SEC.
			 */
			struct blued_conn *ic;
			uintptr_t tident = events[i].ident;
			bool found = false;

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(ic, &blued_g.conns, entries) {
				if (ic->idle_timer == tident) {
					found = true;
					break;
				}
			}
			if (found) {
				LOG_ATT(1, "idle timeout "
				    "(%ds), disconnecting",
				    BLUED_IDLE_TIMEOUT_SEC);
				ic->idle_timer = 0;
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
			if (found)
				blued_conn_disconnect(ic);
			continue;
		}
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_IND_TIMEOUT) {
			/*
			 * ATT indication timeout (30s).
			 * Core Spec Vol 3 Part F 3.3.3:
			 * disconnect the bearer.
			 */
			struct blued_conn *ic;
			uintptr_t tident = events[i].ident;
			bool found_ind = false;

			pthread_rwlock_wrlock(&blued_g.conns_lock);
			LIST_FOREACH(ic, &blued_g.conns, entries) {
				if (ic->att != NULL &&
				    ic->att->ind_timer == tident) {
					found_ind = true;
					break;
				}
			}
			if (found_ind) {
				LOG_ATT(1, "indication "
				    "timeout (30s), "
				    "disconnecting");
				ic->att->ind_pending = false;
				ic->att->ind_timer = 0;
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);
			if (found_ind)
				blued_conn_disconnect(ic);
			continue;
		}
		if (events[i].filter == EVFILT_TIMER &&
		    (events[i].udata == BLUED_KQ_RPA_TIMER ||
		    events[i].udata == BLUED_KQ_RPA_RETRY)) {
			/*
			 * RPA rotation timer fired.  Generate a
			 * new RPA from the local IRK and update
			 * the advertising address.
			 */
			struct blued_adapter *ra;
			uint8_t rpa[6];
			bool retry_event, need_retry = false;

			retry_event = events[i].udata == BLUED_KQ_RPA_RETRY;
			if (retry_event)
				blued_rpa_retry_timer = 0;

			LIST_FOREACH(ra, &blued_g.adapters, entries) {
				if (!ra->active || !ra->powered || !ra->privacy)
					continue;
				/*
				 * The retry timer is daemon-wide.  Only revisit
				 * adapters with unfinished domains; starting a new
				 * rotation here would rerotate adapters that already
				 * completed while another adapter was backpressured.
				 */
				if (retry_event && !ra->rpa_pending)
					continue;
				if (!retry_event && ra->rpa_pending)
					ra->rpa_retry_count = 0;
				/*
				 * One address PER ADAPTER, generated inside
				 * the loop.  Handing the same resolvable
				 * private address to every adapter would have
				 * them advertise, scan and initiate from an
				 * identical address at the same time, and an
				 * observer that sees both sees one device --
				 * which is precisely the linkability the
				 * address exists to prevent (Core Vol 3 Part C
				 * §10.7).
				 *
				 * A crypto failure skips this rotation rather
				 * than airing a predictable all-zero RPA; the
				 * timer fires again for a fresh attempt.
				 */
				if (smp_generate_rpa(blued_local_irk, rpa) != 0) {
					LOG_HCI(1, "RPA rotation skipped: "
					    "ah() failed");
					if (ra->rpa_pending &&
					    ra->rpa_retry_count < 5)
						need_retry = true;
					continue;
				}
				if (blued_adapter_rotate_rpa(ra, rpa) == 0) {
					LOG_HCI(1, "RPA rotated: "
					    "%02x:%02x:%02x:%02x:%02x:%02x",
					    rpa[5], rpa[4], rpa[3],
					    rpa[2], rpa[1], rpa[0]);
				} else {
					if (retry_event)
						ra->rpa_retry_count++;
					if (ra->rpa_retry_count < 5)
						need_retry = true;
				}
			}
			if (need_retry)
				(void)blued_rpa_retry_arm();
			else if (!retry_event)
				blued_rpa_retry_cancel();
			explicit_bzero(rpa, sizeof(rpa));
			continue;
		}
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_READVERTISE) {
			(void)blued_periph_readvertise_timer_fired(
			    events[i].ident);
			continue;
		}
		/* Finding C-m1: fd-exhaustion listener backoff elapsed. */
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_CTL_ACCEPT_RETRY) {
			blued_ctl_accept_retry_enable();
			continue;
		}
		/*
		 * C3-H2: periodic write-out of Signed-Write replay
		 * floors advanced in memory since the last tick.
		 */
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_SIGNCTR_FLUSH) {
			blued_sign_counter_flush();
			continue;
		}
		/* Legacy mesh adv burst airtime elapsed: stop it. */
		if (events[i].filter == EVFILT_TIMER &&
		    events[i].udata == BLUED_KQ_MESH_LEGACY_STOP) {
			blued_mesh_adv_legacy_timeout();
			continue;
		}
		if (events[i].filter == EVFILT_TIMER &&
		    blued_discoverable_timer_fired(events[i].ident)) {
			/* Discoverable auto-off timeout expired. */
			continue;
		}
		if (events[i].filter == EVFILT_TIMER) {
			/*
			 * Reconnect timer: udata is a blued_conn*.
			 * Validate by looking it up in blued_g.conns
			 * before dereferencing, in case the conn was
			 * freed between timer arm and fire.
			 */
			struct blued_conn *tconn = NULL;
			struct blued_conn *tc;

			pthread_rwlock_rdlock(&blued_g.conns_lock);
			LIST_FOREACH(tc, &blued_g.conns, entries) {
				if (tc == events[i].udata) {
					tconn = tc;
					break;
				}
			}
			pthread_rwlock_unlock(&blued_g.conns_lock);

			if (tconn == NULL) {
				LOG_HOGP(1, "reconnect timer for "
				    "unknown conn, ignoring");
				continue;
			}
			/*
			 * Defense against a recycled allocation: the
			 * pointer-equality scan above can match a NEW
			 * conn allocated at the address of a freed one
			 * whose timer was still armed.  Only a central
			 * conn actually awaiting reconnect may be
			 * (re)connected from here.
			 */
			if (atomic_load(&tconn->state) !=
			    BLUED_CONN_RECONNECTING ||
			    tconn->role != BLUED_ROLE_CENTRAL) {
				LOG_HOGP(1, "reconnect timer for conn "
				    "not awaiting reconnect, ignoring");
				continue;
			}
			/*
			 * Same recycled-allocation defense, second
			 * key: the ident must be the timer THIS conn
			 * armed, not a stale ONESHOT from a freed
			 * conn that happens to alias its address.
			 * Consume the id on the genuine fire so a
			 * late duplicate cannot match again.
			 */
			if (events[i].ident != tconn->reconnect_timer) {
				LOG_HOGP(1, "stale reconnect timer "
				    "ident, ignoring");
				continue;
			}
			tconn->reconnect_timer = 0;

			{
				pthread_t tid;
				pthread_attr_t attr;

				pthread_attr_init(&attr);
				pthread_attr_setdetachstate(&attr,
				    PTHREAD_CREATE_DETACHED);
				/* Reset the prior link before this attempt can start. */
				tconn->local_own_addr_type =
				    tconn->adapter->privacy ? 0x03 : 0x00;
				blued_conn_reset_local(tconn);
				blued_conn_set_state(tconn,
				    BLUED_CONN_CONNECTING);
				/*
				 * Reference held by the setup thread
				 * for its lifetime.
				 */
				blued_conn_ref(tconn);
				blued_setup_worker_start(tconn);
				if (pthread_create(&tid, &attr,
				    blued_conn_setup_central,
				    tconn) != 0) {
					warn("reconnect thread");
					blued_setup_worker_finish(tconn);
					blued_conn_unref(tconn);
					blued_conn_set_state(tconn,
					    BLUED_CONN_RECONNECTING);
					{
						struct kevent tkev;
						tconn->reconnect_timer =
						    blued_next_timer_id++;
						EV_SET(&tkev,
						    tconn->reconnect_timer,
						    EVFILT_TIMER,
						    EV_ADD | EV_ONESHOT,
						    NOTE_SECONDS,
						    tconn->reconnect_delay,
						    tconn);
						(void)kevent(blued_g.kq,
						    &tkev, 1, NULL, 0,
						    NULL);
					}
				}
				pthread_attr_destroy(&attr);
			}
			continue;
		}
		if (events[i].filter == EVFILT_READ)
			blued_handle_readable(&events[i]);
		else if (events[i].filter == EVFILT_WRITE)
			blued_handle_writable(&events[i]);
		/* Stop processing stale events after disconnect */
		if (!running)
			return (false);
	}
	return (true);
}

void
blued_event_loop(void)
{
	struct kevent events[32];
	int n;

	for (;;) {
		if (!running) {
			blued_ctl_reaped_free();
			return;
		}
		n = kevent(blued_g.kq, NULL, 0, events,
		    (int)nitems(events), NULL);
		blued_event_batch_begin();
		if (n < 0) {
			if (errno == EINTR)
				continue;
			warn("kevent");
			break;
		}
		if (!blued_event_dispatch_batch(events, n)) {
			blued_ctl_reaped_free();
			return;
		}
	}
	blued_ctl_reaped_free();
}

/*
 * Central-role teardown (findings 59, 60, 89, 93).
 *
 * blued_conn_free()/blued_conn_destroy() (conn.c) only know how to release a
 * peripheral connection's att_owned server bearer.  A CENTRAL connection's ATT
 * transport, SMP, report map and vhid live in conn->hogp, which conn.c never
 * touches — so every path that reaches conn teardown through blued_conn_free
 * (the APTO sweep, non-reconnect setup failure, shutdown) leaks the whole
 * hogp_device and, worse, leaves conn->att_fd and hogp->vhid_fd registered in
 * the kqueue with udata pointing at the freed conn: the stale registration
 * fires forever ("unhandled kqueue event" spin / 100% CPU).  This helper is the
 * single central-role teardown: it removes those registrations, closes the fds
 * and frees the hogp.  Idempotent and a no-op for a peripheral conn (hogp NULL).
 */
void
blued_conn_central_teardown(struct blued_conn *conn)
{
	struct hogp_device *dev;
	struct kevent kev;

	if (conn == NULL || conn->hogp == NULL)
		return;
	dev = conn->hogp;

	/* Drop the fixed + EATT kqueue registrations before the fds close. */
	blued_conn_unregister_att(conn);

	/* Deregister and close the vhid fd (kernel Output-report source). */
	if (dev->vhid_fd >= 0) {
		if (blued_g.kq >= 0) {
			EV_SET(&kev, dev->vhid_fd, EVFILT_READ, EV_DELETE,
			    0, 0, NULL);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
		}
	}

	att_close(&dev->att);
	if (dev->smp.fd >= 0)
		smp_close(&dev->smp);
	if (dev->vhid_fd >= 0) {
		close(dev->vhid_fd);
		dev->vhid_fd = -1;
	}
	conn->att = NULL;
	conn->att_fd = -1;
	free(dev->report_map);
	free(dev);
	conn->hogp = NULL;
}

/*
 * Persist a departing peripheral peer's per-connection CCCD state into its
 * bond record.  Shared by blued_conn_disconnect and the needs_cleanup
 * terminal sweep so a setup-failure teardown does not lose CCCD writes.
 */
static void
blued_periph_save_cccds(struct blued_conn *conn)
{

	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL && conn->att_owned != NULL) {
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond != NULL) {
			struct smp_bond previous = *bond;

			smp_bond_save_cccds(bond, conn->att_owned);
			if (smp_bond_db_commit_bond(blued_g.bond_db,
			    bond, &previous) == 0)
				LOG_HOGP(1, "saved %d CCCD(s) for "
				    "bonded device", bond->num_cccds);
			else
				warnx("saving bonded-device CCCDs");
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
}

/*
 * Handle device disconnection detected by kqueue EV_EOF.
 * For peripheral: save CCCDs, free resources, re-enable advertising.
 * For central: if reconnect enabled, schedule reconnect timer.
 */
void
blued_conn_disconnect(struct blued_conn *conn)
{
	struct kevent kev;
	char addr_str[18];

	/* Guard against double-disconnect (EV_EOF + timer, etc.) */
	if (atomic_load(&conn->state) == BLUED_CONN_IDLE)
		return;
	/*
	 * Finding 86: a CONNECTING conn is owned by a detached setup thread
	 * that is still dereferencing conn/hogp through blocking discovery and
	 * pairing.  Tearing it down here (adapter loss, POWER-off, duplicate
	 * accept, the peripheral setup thread's own indication timeout) would
	 * free state under that thread — a use-after-free on the non-refcounted
	 * hogp_device.  Defer: flag the disconnect and let the setup thread
	 * observe it at its handoff barrier.
	 */
	if (atomic_load(&conn->state) == BLUED_CONN_CONNECTING) {
		atomic_store_explicit(&conn->disconnect_pending, true,
		    memory_order_release);
		return;
	}
	/*
	 * Finding 45: a central conn already awaiting its reconnect timer is
	 * fully torn down and scheduled to retry.  A second disconnect trigger
	 * in the same kevent batch must not overwrite reconnect_timer (leaking
	 * the armed ONESHOT) nor spawn a second setup thread over the same
	 * non-refcounted hogp_device.  A reconnect=false teardown (adapter
	 * loss) is still allowed through to finalize the conn.
	 */
	if (atomic_load(&conn->state) == BLUED_CONN_RECONNECTING &&
	    conn->reconnect)
		return;
	/*
	 * C3-M1: store disconnect_pending BEFORE reading att_ops_active
	 * (store-then-load), mirroring the needs_cleanup sweep at :1125.  A
	 * worker retiring right now re-signals the setup pipe only while
	 * disconnect_pending is already set (blued_conn_att_ops_end /
	 * ctl_gatt_job_run); the previous load-then-store let a worker retire
	 * in the window between the load and the store, so nobody signalled the
	 * pipe and the deferred disconnect was stranded (indication timeout,
	 * conn up forever).  If no op is in flight, clear the flag and proceed.
	 *
	 * The store+load pair MUST be seq_cst: this is a store-buffering (Dekker)
	 * handshake against the worker's own store(att_ops_active=0)+load(
	 * disconnect_pending) pair, and release/acquire on two DISTINCT atomics
	 * does not forbid the StoreLoad reordering where each side misses the
	 * other's store (observable on amd64 TSO / aarch64), re-stranding the
	 * teardown.  Both sides use memory_order_seq_cst so a single total order
	 * guarantees at least one side observes the other's write.
	 */
	atomic_store_explicit(&conn->disconnect_pending, true,
	    memory_order_seq_cst);
	if (atomic_load_explicit(&conn->att_ops_active,
	    memory_order_seq_cst) != 0)
		return;
	(void)atomic_exchange_explicit(&conn->disconnect_pending, false,
	    memory_order_acq_rel);

	bt_ntoa(&conn->dst, addr_str);
	LOG_HOGP(1, "device %s disconnected (role=%s handle=%04x)",
	    addr_str,
	    conn->role == BLUED_ROLE_PERIPHERAL ? "peripheral" : "central",
	    conn->con_handle);
	BLUED_PROBE_CONN_CLOSE(addr_str, 0);

	/*
	 * Push EVENT DISCONNECTED to push-events clients (findings C1/C2) and
	 * clear the announce latch so that a subsequent auto-reconnect of the
	 * same connection re-announces EVENT CONNECTED.  Emitted only if this
	 * connection was previously announced up, so a failed setup that never
	 * reached ACTIVE does not produce a spurious DISCONNECTED.
	 */
	if (conn->announced) {
		conn->announced = false;
		blued_ctl_broadcast_conn_event(&conn->dst, conn->role,
		    conn->addr_type, (uint8_t)conn->adapter->index,
		    conn->con_handle, 0, false, 0);
	}

	/* Release any AcquireNotify/Write fds bound to this peer. */
	ctl_acquire_conn_gone(conn);
	/* CCCDs and their local notification routes are connection-scoped. */
	ctl_gatt_conn_gone(conn);

	/* Disarm idle and indication timers */
	blued_idle_disarm(conn);
	blued_ind_disarm_timeout(conn);

	/* Deregister the fixed and all enhanced bearers before closing them. */
	blued_conn_unregister_att(conn);

	/* Deregister vhid fd from kqueue */
	if (conn->hogp != NULL && conn->hogp->vhid_fd >= 0) {
		EV_SET(&kev, conn->hogp->vhid_fd, EVFILT_READ,
		    EV_DELETE, 0, 0, NULL);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}

	if (conn->role == BLUED_ROLE_PERIPHERAL) {
		/* Save per-connection CCCDs for bonded device */
		blued_periph_save_cccds(conn);

		/* blued_conn_free closes att_owned fd and frees att_owned */
		blued_conn_free(conn);

		/* Re-enable advertising */
		blued_periph_readvertise();
	} else {
		/* Central role */
		if (conn->reconnect) {
			/* Schedule reconnect via EVFILT_TIMER */
			blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
			if (conn->reconnect_delay == 0)
				conn->reconnect_delay = 3;
			LOG_HOGP(1, "reconnecting in %d seconds...",
			    conn->reconnect_delay);

			/* Close the old ATT fd */
			if (conn->att_fd >= 0) {
				close(conn->att_fd);
				conn->att_fd = -1;
			}
			if (conn->hogp != NULL) {
				/*
				 * att.fd is the same fd as conn->att_fd
				 * (already closed above); mark it invalid
				 * to prevent att_close from double-closing.
				 */
				conn->hogp->att.fd = -1;
				att_close(&conn->hogp->att);
				if (conn->hogp->smp.fd >= 0)
					smp_close(&conn->hogp->smp);
				free(conn->hogp->report_map);
				conn->hogp->report_map = NULL;
				conn->hogp->nreports = 0;
			}
			/*
			 * Finding H-M1: the old link handle is dead the moment we
			 * enter reconnect backoff.  Clear con_handle_valid and
			 * NULL conn->att now (not only when the reconnect timer
			 * fires) so the Encryption-Change / Key-Refresh / APTO
			 * handlers — which match purely on
			 * con_handle_valid && con_handle == handle — cannot act
			 * on this conn using a stale handle a controller may
			 * reassign during the backoff window.
			 */
			conn->con_handle_valid = false;
			conn->att = NULL;

			conn->reconnect_timer = blued_next_timer_id++;
			EV_SET(&kev, conn->reconnect_timer,
			    EVFILT_TIMER,
			    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
			    conn->reconnect_delay, conn);
			(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

			/* Exponential backoff */
			conn->reconnect_delay *= 2;
			if (conn->reconnect_delay > blued_reconnect_max_delay) {
				conn->reconnect_delay =
				    blued_reconnect_max_delay;
				LOG_HOGP(1, "reconnect backoff at maximum "
				    "(%d seconds), retries will not "
				    "accelerate", blued_reconnect_max_delay);
			}
		} else {
			/* No reconnect -- clean up (single central teardown). */
			blued_conn_central_teardown(conn);
			blued_conn_free(conn);
		}
	}
}
