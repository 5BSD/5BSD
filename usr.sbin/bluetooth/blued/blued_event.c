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

/*
 * Validate an entire multi-report advertising event before exposing any AD
 * field to the Mesh broker.  HCI permits several reports in one event; a
 * malformed later report must not cause an earlier prefix to be forwarded.
 */
static bool
blued_mesh_adv_event_valid(const uint8_t *buf, size_t len, uint8_t subevent)
{
	struct ble_scan_result scratch;
	size_t off, consumed;
	uint8_t nreports, r;

	if (len < 5)
		return (false);
	nreports = buf[4];
	if ((subevent == NG_HCI_LEEV_ADVREP &&
	    (nreports == 0 || nreports > 25)) ||
	    (subevent == NG_HCI_LEEV_EXT_ADVREP &&
	    (nreports == 0 || nreports > 10)))
		return (false);

	off = 5;
	for (r = 0; r < nreports; r++) {
		if (subevent == NG_HCI_LEEV_EXT_ADVREP) {
			memset(&scratch, 0, sizeof(scratch));
			consumed = hci_parse_ext_adv_report(buf + off,
			    len - off, &scratch);
			if (consumed == 0)
				return (false);
		} else {
			uint8_t dlen;
			int8_t rssi;

			if (len - off < 10 || buf[off] > 0x04 ||
			    buf[off + 1] > 0x03)
				return (false);
			dlen = buf[off + 8];
			if (dlen > 31 || len - off < (size_t)10 + dlen)
				return (false);
			rssi = (int8_t)buf[off + 9 + dlen];
			if (rssi != 0x7f && (rssi < -127 || rssi > 20))
				return (false);
			consumed = (size_t)10 + dlen;
		}
		off += consumed;
	}
	return (off == len);
}

static void
blued_mesh_demux_adv_event(const uint8_t *buf, uint8_t subevent)
{
	size_t off;
	uint8_t r;

	off = 5;
	for (r = 0; r < buf[4]; r++) {
		size_t hdr = subevent == NG_HCI_LEEV_ADVREP ? 8 : 23;
		uint8_t dlen = buf[off + hdr];

		blued_mesh_demux_report(buf + off + hdr + 1, dlen);
		off += hdr + 1 + dlen +
		    (subevent == NG_HCI_LEEV_ADVREP ? 1 : 0);
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

	if (conn->idle_timer == 0)
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
			if (!blued_mesh_adv_event_valid(buf, (size_t)n, subevent))
				return;
			blued_mesh_demux_adv_event(buf, subevent);
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
						pthread_mutex_lock(
						    &blued_g.bond_db_lock);
						bond = smp_find_bond(
						    blued_g.bond_db,
						    (const uint8_t *)&conn->dst,
						    conn->addr_type);
						if (bond != NULL &&
						    bond->has_ltk) {
							/*
							 * For legacy pairing,
							 * validate EDIV/Rand.
							 * SC bonds always use
							 * EDIV=0, Rand=0.
							 */
							if (!bond->is_sc &&
							    (bond->ediv != ediv ||
							    memcmp(&bond->rand,
							    &rand_val, 8) != 0)) {
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
				if (has_ltk) {
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

	warnx("BLE: controller %s lost (HCI fd EOF); tore down %d "
	    "connection(s), entering degraded state -- restart the daemon "
	    "to recover the controller", a->name, torn);
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

		(void)read(blued_g.setup_pipe[0], buf, sizeof(buf));

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
				blued_conn_central_teardown(c);
				blued_conn_free(c);
				continue;
			}
			if (atomic_exchange_explicit(&c->disconnect_pending, false,
			    memory_order_acq_rel)) {
				blued_conn_disconnect(c);
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
	 * AcquireNotify/AcquireWrite daemon-side SEQPACKET fd: a WRITE acquire's
	 * client datagrams become ATT writes here; client-close (EV_EOF) tears
	 * the acquire down.  Keyed by fd inside ctl_acquire_dispatch.
	 */
	if (ev->udata == BLUED_KQ_ACQUIRE) {
		ctl_acquire_dispatch(ev);
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
		if (ev->udata == client) {
			if ((ev->flags & EV_EOF) ||
			    blued_ctl_dispatch(client) < 0) {
				/* Client disconnected or error */
				int dead_fd = client->fd;
				/* Release the client's AcquireNotify/Write fds. */
				ctl_acquire_client_gone(client);
				blued_ctl_client_mesh_gone(client);
				LIST_REMOVE(client, entries);
				pthread_mutex_unlock(&blued_g.ctl_clients_lock);
				blued_ctl_reset_owner(dead_fd);
				ctl_gatt_client_gone(client);
				close(dead_fd);
				blued_ctl_client_fini(client);
				free(client);
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
						pthread_mutex_lock(
						    &blued_g.gatt_db_lock);
						att_server_handle(conn->att,
						    conn->gatt_db, buf,
						    (size_t)nr, bfd, bmtu);
						pthread_mutex_unlock(
						    &blued_g.gatt_db_lock);
						if (buf != fixed)
							free(buf);
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
		if (ev->udata != client)
			continue;
		if ((ev->flags & EV_EOF) || blued_ctl_flush(client) < 0) {
			int dead_fd = client->fd;

			ctl_acquire_client_gone(client);
			blued_ctl_client_mesh_gone(client);
			LIST_REMOVE(client, entries);
			pthread_mutex_unlock(&blued_g.ctl_clients_lock);
			blued_ctl_reset_owner(dead_fd);
			ctl_gatt_client_gone(client);
			close(dead_fd);
			blued_ctl_client_fini(client);
			free(client);
			return;
		}
		pthread_mutex_unlock(&blued_g.ctl_clients_lock);
		return;
	}
	pthread_mutex_unlock(&blued_g.ctl_clients_lock);
}

void
blued_event_loop(void)
{
	struct kevent events[32];
	int n, i;

	for (;;) {
		if (!running)
			return;
		n = kevent(blued_g.kq, NULL, 0, events,
		    (int)nitems(events), NULL);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			warn("kevent");
			break;
		}
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
				return;
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

				if (smp_generate_rpa(blued_local_irk, rpa) != 0) {
					/*
					 * Crypto failure: skip this rotation
					 * rather than advertise a predictable
					 * all-zero RPA.  The timer will fire
					 * again for a fresh attempt.
					 */
					LOG_HCI(1, "RPA rotation skipped: "
					    "ah() failed");
					LIST_FOREACH(ra, &blued_g.adapters, entries)
						if (ra->active && ra->powered && ra->privacy &&
						    ra->rpa_pending &&
						    ra->rpa_retry_count < 5) {
							(void)blued_rpa_retry_arm();
							break;
						}
					continue;
				}
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
				return;
		}
	}
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
	if (atomic_load_explicit(&conn->att_ops_active, memory_order_acquire) != 0) {
		atomic_store_explicit(&conn->disconnect_pending, true,
		    memory_order_release);
		return;
	}

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
