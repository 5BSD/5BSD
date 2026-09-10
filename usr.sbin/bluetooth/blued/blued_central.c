/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued central (client) role: connection setup thread, HOGP discovery,
 * HOGP event loop, reconnection logic with exponential backoff,
 * ATT security retry, vhid device management.
 */

#include "blued_internal.h"

/*
 * Central connection setup thread -- failure cleanup.
 *
 * Closes ATT/SMP, frees partial state.  If reconnect is enabled,
 * flags the conn so the main thread arms the retry EVFILT_TIMER.
 * Otherwise flags the conn for cleanup by the main thread (via the
 * self-pipe handler) to avoid a data race on blued_g.conns.
 */
void
blued_central_setup_fail(struct blued_conn *conn)
{
	struct hogp_device *dev = conn->hogp;

	if (dev != NULL) {
		att_close(&dev->att);
		if (dev->smp.fd >= 0)
			smp_close(&dev->smp);
		free(dev->report_map);
		dev->report_map = NULL;
		dev->nreports = 0;
	}
	conn->att_fd = -1;
	conn->att = NULL;

	if (conn->reconnect) {
		/*
		 * C3-H3: invalidate the stale connection handle before the
		 * (up to max) backoff, matching blued_conn_disconnect.  Leaving
		 * con_handle_valid true through the RECONNECTING window let a
		 * post-handle setup failure keep a dead handle live: LTK Request
		 * events would reply the wrong peer's LTK, an APTO sweep could
		 * free the RECONNECTING conn, and an Enhanced Connection Complete
		 * for a reused handle could be hijacked onto this conn.
		 */
		conn->con_handle_valid = false;

		blued_conn_set_state(conn, BLUED_CONN_RECONNECTING);
		LOG_HOGP(1, "setup failed, scheduling reconnect...");

		/*
		 * Do NOT arm the reconnect timer from this (setup) thread:
		 * arming a ONESHOT with udata=conn here races the main
		 * thread's teardown of a RECONNECTING conn — the conn can be
		 * freed with the timer still armed, and the fire handler's
		 * pointer-equality scan of blued_g.conns can then match a
		 * recycled allocation.  Instead flag the request and let the
		 * main thread's setup-pipe sweep arm the timer (and apply the
		 * backoff), so arm and teardown are serialized on one thread.
		 */
		atomic_store_explicit(&conn->needs_reconnect_arm, true,
		    memory_order_release);
	} else {
		blued_conn_set_state(conn, BLUED_CONN_IDLE);
		atomic_store_explicit(&conn->needs_cleanup, true,
		    memory_order_release);
	}
	(void)write(blued_g.setup_pipe[1], "x", 1);
}

static bool
hogp_bond_snapshot(struct hogp_device *dev, struct smp_bond *out)
{
	struct smp_bond *bond;
	bool found = false;

	if (dev->bond_db == NULL)
		return (false);
	pthread_mutex_lock(&blued_g.bond_db_lock);
	bond = smp_find_bond(dev->bond_db, dev->addr, dev->addr_type);
	if (bond != NULL) {
		*out = *bond;
		found = true;
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	return (found);
}

static int
hogp_bond_commit_metadata(struct hogp_device *dev, const struct smp_bond *src)
{
	struct smp_bond *dst;
	int rc = -1;

	pthread_mutex_lock(&blued_g.bond_db_lock);
	dst = smp_find_bond(dev->bond_db, dev->addr, dev->addr_type);
	if (dst != NULL) {
		struct smp_bond previous = *dst;

		strlcpy(dst->name, src->name, sizeof(dst->name));
		dst->has_name = src->has_name;
		memcpy(dst->db_hash, src->db_hash, sizeof(dst->db_hash));
		dst->has_db_hash = src->has_db_hash;
		dst->has_handle_cache = src->has_handle_cache;
		dst->hid_svc_start = src->hid_svc_start;
		dst->hid_svc_end = src->hid_svc_end;
		dst->bat_svc_start = src->bat_svc_start;
		dst->bat_svc_end = src->bat_svc_end;
		dst->report_map_handle = src->report_map_handle;
		dst->hid_info_handle = src->hid_info_handle;
		dst->protocol_mode_handle = src->protocol_mode_handle;
		/* Finding 68: HID Control Point + multi-instance report maps. */
		dst->hid_ctrl_handle = src->hid_ctrl_handle;
		dst->num_report_maps = src->num_report_maps;
		memcpy(dst->report_map_handles, src->report_map_handles,
		    sizeof(dst->report_map_handles));
		memcpy(dst->report_handles, src->report_handles,
		    sizeof(dst->report_handles));
		memcpy(dst->report_cccd_handles, src->report_cccd_handles,
		    sizeof(dst->report_cccd_handles));
		memcpy(dst->report_types, src->report_types,
		    sizeof(dst->report_types));
		memcpy(dst->report_ids, src->report_ids,
		    sizeof(dst->report_ids));
		dst->num_reports = src->num_reports;
		dst->battery_level_handle = src->battery_level_handle;
		dst->battery_cccd_handle = src->battery_cccd_handle;
		rc = smp_bond_db_commit_bond(dev->bond_db, dst, &previous);
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	if (rc != 0)
		warn("saving bond metadata");
	return (rc);
}

/*
 * hogp_report.c spells the Battery Service UUID itself so that unit does not
 * depend on this daemon's private header; bind the two so they cannot drift.
 */
_Static_assert(HOGP_UUID_BATTERY_SERVICE == UUID_BATTERY_SERVICE,
    "Battery Service UUID must agree between hogp_report.h and blued_internal.h");

/*
 * Discard the cached attribute-handle set and the Database Hash it was
 * validated against.
 *
 * Core Vol 3 Part G §2.5.2.1 lines 72375-72378 obliges a client that receives
 * Database Out Of Sync (0x12) to consider its attribute cache invalid and not
 * use the cached information until it has rediscovered.  Clearing has_db_hash
 * as well as has_handle_cache is what stops the next reconnect from taking the
 * cache-valid path against a hash the peer has already moved past.
 */
static void
hogp_invalidate_attr_cache(struct hogp_device *dev)
{
	struct smp_bond bond;

	if (hogp_bond_snapshot(dev, &bond)) {
		bond.has_handle_cache = false;
		bond.has_db_hash = false;
		(void)hogp_bond_commit_metadata(dev, &bond);
	}
}

/*
 * Become, and stay, a change-aware bonded caching client.
 *
 * Two writes, in this order, and the order is the point:
 *
 *   1. Client Supported Features (0x2B29), Robust Caching bit.  Core Vol 3
 *      Part G §2.5.2.1 line 72351 sends Database Out Of Sync (0x12) only to a
 *      client that has set this bit, so without the write a conformant server
 *      never tells us our cache is stale and the 0x12 recovery path above can
 *      never fire.  Lines 72371-72372 add the other half: the server also
 *      withholds notifications from a change-unaware client, a guarantee a
 *      caching client should not decline.
 *
 *   2. The Service Changed (0x2A05) client configuration.  Core Vol 3 Part G
 *      §7.1 lines 74975-74979: "This Characteristic Value shall be configured
 *      to be indicated using the Client Characteristic Configuration descriptor
 *      by a client", and indications caused by changes "shall be considered
 *      lost if the client has erroneously not enabled indications".  blued
 *      persists a handle cache across bonds (hogp_cache_save()), so this is the
 *      mechanism that tells us the database moved while we were away.
 *
 * Neither lookup depends on HOGP discovery state, so this runs identically on
 * a full-discovery connection and on a cache-hit reconnect — which also gives
 * the cache path a Service Changed value handle, previously left at zero so
 * an indication could never invalidate anything.
 *
 * Every failure here is soft: a peer without a GATT Service, or one that
 * rejects the writes, is still usable, just without robust caching.
 */
static void
hogp_enable_change_awareness(struct hogp_device *dev)
{
	struct gatt_service gatt_svc;
	struct gatt_char chars[GATT_MAX_CHARS];
	uint16_t value_handle, cccd_handle, char_end;
	int i, nsvcs, nchars, ret;

	ret = gatt_set_client_supported_features(&dev->att,
	    GATT_CSF_ROBUST_CACHING);
	if (ret == ENOENT)
		LOG_HOGP(1, "peer exposes no Client Supported Features "
		    "characteristic; robust caching unavailable");
	else if (ret != 0)
		warnx("Client Supported Features write failed (%d); "
		    "Database Out Of Sync will not be reported to us", ret);

	/*
	 * Locate Service Changed by discovery, NOT by Read Using
	 * Characteristic UUID: HIDS-style read-by-type works for Client
	 * Supported Features (which is readable) but the Service Changed
	 * characteristic has no Read property, so a read-by-type would be
	 * answered with Read Not Permitted and the handle would be lost.
	 */
	nsvcs = 0;
	if (gatt_discover_primary_service_by_uuid(&dev->att,
	    GATT_UUID_GATT_SERVICE, &gatt_svc, 1, &nsvcs) != 0 || nsvcs < 1) {
		LOG_HOGP(1, "peer exposes no GATT Service (0x1801)");
		return;
	}
	nchars = 0;
	if (gatt_discover_characteristics(&dev->att, gatt_svc.start_handle,
	    gatt_svc.end_handle, chars, GATT_MAX_CHARS, &nchars) != 0)
		return;
	value_handle = 0;
	char_end = gatt_svc.end_handle;
	for (i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != GATT_UUID_SERVICE_CHANGED)
			continue;
		value_handle = chars[i].value_handle;
		if (i + 1 < nchars)
			char_end = (uint16_t)(chars[i + 1].decl_handle - 1);
		break;
	}
	if (value_handle == 0) {
		LOG_HOGP(1, "no Service Changed characteristic");
		return;
	}
	dev->svc_changed_handle = value_handle;
	LOG_HOGP(1, "Service Changed value handle %04x", value_handle);

	ret = gatt_find_cccd(&dev->att, value_handle, char_end, &cccd_handle);
	if (ret != 0) {
		warnx("Service Changed characteristic has no client "
		    "configuration descriptor; indications cannot be enabled");
		return;
	}
	ret = gatt_write_cccd(&dev->att, cccd_handle, GATT_CCCD_INDICATION);
	if (ret != 0)
		warnx("enabling Service Changed indications failed (%d)", ret);
	else
		LOG_HOGP(1, "Service Changed indications enabled (cccd=%04x)",
		    cccd_handle);
}

/*
 * Start (or restart) an SMP pairing with a connected peer over the existing
 * link.  Both the reactive auth-error path and the operator-driven REKEY verb
 * funnel through here so the start-pairing logic lives in one place.
 *
 * A completed exchange distributes fresh LTK/IRK/CSRK; the SMP key-distribution
 * flow replaces the peer's bond keys in place (Core Spec Vol 3 Part H §2.4)
 * without disturbing the peer record.  On success the ATT security gate is
 * (re)opened, and the peer's controller resolving-list entry is re-programmed
 * remove-then-add so a rotated IRK takes effect for RPA resolution (Core Spec
 * Vol 4 Part E §7.8.38); an unchanged IRK is idempotent and a first bond is a
 * plain add.  The new keys land only on completion, so a failed re-pair leaves
 * the old bond intact.
 */
int
blued_central_start_pairing(struct hogp_device *dev, struct blued_conn *conn)
{
	struct smp_bond pb;
	bool have_pb;
	uint8_t local_addr[6], local_type;

	/* Pairing may also be entered by REKEY after initial setup. */
	blued_conn_apply_cached_local(conn);
	blued_conn_local_from_socket(conn, dev->att.fd);
	if (!blued_conn_get_local(conn, local_addr, &local_type)) {
		warnx("SMP local address unresolved");
		return (-1);
	}
	if (smp_open(&dev->smp, dev->addr, dev->addr_type,
	    local_addr, local_type,
	    dev->hci_fd, dev->con_handle, dev->bond_db) < 0) {
		warnx("SMP open failed");
		return (-1);
	}
	dev->smp.passkey_cb = passkey_display;
	dev->smp.passkey_cb_arg = conn;
	dev->smp.numcmp_cb = numcmp_confirm;
	dev->smp.numcmp_cb_arg = conn;
	dev->smp.keypress_cb = blued_keypress_notify;
	dev->smp.keypress_cb_arg = &conn->dst;
	/*
	 * A registered pairing agent's IO capability overrides the static
	 * config for this pairing (the common pairing-agent model; Core Spec Vol 3 Part H
	 * §2.3.5.1 IO cap -> association model).
	 */
	dev->smp.io_capability =
	    blued_ctl_effective_io_cap(blued_cfg.io_capability);
	dev->smp.min_key_size = blued_cfg.min_key_size;
	dev->att.min_key_size = blued_cfg.min_key_size;
	dev->smp.sc_only = blued_cfg.sc_mode == BLUED_SC_ONLY;
	dev->smp.min_pairing_security = blued_cfg.min_pairing_security;
	/* De-hardcoded AuthReq / key-distribution policy (config-seeded). */
	dev->smp.require_mitm = blued_cfg.mitm;
	dev->smp.bondable = blued_cfg.bondable;
	dev->smp.keypress = blued_cfg.keypress;
	dev->smp.sc_enabled = (blued_cfg.sc_mode != BLUED_SC_OFF);
	dev->smp.our_key_dist = blued_cfg.key_dist;
	dev->smp.their_key_dist = blued_cfg.key_dist;

	/*
	 * Consume any operator-injected OOB pairing data for this peer
	 * (OOB_INJECT).  The storage lives on this stack frame for the
	 * duration of smp_pair(); dev->smp.oob is detached afterwards.
	 */
	struct smp_oob_legacy oob_lg;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob_data;
	bool have_lg = false, have_sc = false;

	if (blued_oob_take((const uint8_t *)&dev->addr, &oob_lg, &have_lg,
	    &oob_sc, &have_sc) && (have_lg || have_sc)) {
		memset(&oob_data, 0, sizeof(oob_data));
		oob_data.legacy = have_lg ? &oob_lg : NULL;
		oob_data.sc = have_sc ? &oob_sc : NULL;
		dev->smp.oob = &oob_data;
	}

	if (smp_pair(&dev->smp) < 0) {
		dev->smp.oob = NULL;
		explicit_bzero(&oob_lg, sizeof(oob_lg));
		explicit_bzero(&oob_sc, sizeof(oob_sc));
		/*
		 * C1-H2: the SC-OOB ephemeral is cleared only now, after
		 * smp_pair() has consumed it (blued_oob_take no longer clears
		 * it early), so the published PKa survived through pairing.
		 * Clear on the failure path too so a stale ephemeral never
		 * leaks into the next attempt.
		 */
		if (have_sc)
			smp_sc_oob_clear_local();
		warnx("SMP pairing failed");
		return (-1);
	}
	dev->smp.oob = NULL;
	explicit_bzero(&oob_lg, sizeof(oob_lg));
	explicit_bzero(&oob_sc, sizeof(oob_sc));
	/* C1-H2: clear the SC-OOB ephemeral now that pairing has consumed it. */
	if (have_sc)
		smp_sc_oob_clear_local();

	/*
	 * C3-H1: smp_pair() already waits for and consumes the HCI Encryption
	 * Change event INTERNALLY on every success sub-path (SC JW/NC, SC
	 * passkey, legacy) and returns <0 if encryption did not turn on
	 * (smp_sc.c:1095, smp_sc.c:594, smp.c:1436).  A redundant outer
	 * hci_wait_encryption() here would wait on that already-consumed
	 * one-shot event and inevitably time out, mapping a completed pairing
	 * to failure (Finding 119).  smp_pair() returning 0 therefore already
	 * means encryption is on; proceed straight to the ATT-gate / IRK
	 * programming path.
	 *
	 * Open the ATT gate only if the pairing just stored a real LTK
	 * for this peer.
	 */
	have_pb = hogp_bond_snapshot(dev, &pb);
	/*
	 * Finding 95: the ATT security triple (encrypted/authenticated/
	 * enc_key_size) must be written under att_sec_lock -- the main loop's
	 * Encryption-Change / Key-Refresh handlers write the same fields for
	 * this handle, and att_check_security_perms reads them lock-free.  This
	 * post-pairing write runs on the pairing worker after hci_devreq_mutex
	 * is released, so without the lock it can interleave with a main-thread
	 * update and leave a mixed security state on a live link.
	 */
	pthread_mutex_lock(&blued_g.att_sec_lock);
	if (!att_conn_apply_encryption(&dev->att,
	    have_pb && pb.has_ltk, have_pb && pb.is_mitm,
	    have_pb ? pb.key_size : 0, 16))
		LOG_HOGP(1, "post-pairing encryption not backed by stored bond; "
		    "ATT gate stays closed");
	pthread_mutex_unlock(&blued_g.att_sec_lock);

	if (have_pb) {
		blued_reslist_sync_remove(dev->hci_fd, pb.addr, pb.addr_type);
		blued_reslist_sync_add(dev->hci_fd, &pb);
	}
	return (0);
}

/*
 * Finding 33: run an operator-driven (re)pairing on a detached worker instead
 * of on the ctl dispatch thread.
 *
 * blued_central_start_pairing() calls the blocking smp_pair() +
 * hci_wait_encryption().  Invoked directly from the REKEY / PAIR verb handler
 * it stalls the whole event loop — and if the pairing needs a passkey/numcmp,
 * the reply can only be delivered by another dispatch call on that very
 * (blocked) event-loop thread, so it can never complete: a daemon-wide hang
 * until the 30 s SMP timeout.  Every other pairing path already runs on a
 * setup thread; funnel REKEY/PAIR through one too.  The worker holds a conn
 * reference for its lifetime so the connection cannot be freed under it.
 */
static void *
blued_central_pairing_worker(void *arg)
{
	struct blued_conn *conn = arg;

	/*
	 * Finding H-H1 / C3-H2: this detached worker dereferences conn->hogp
	 * (dev->smp / dev->att) throughout the blocking smp_pair().  A conn
	 * refcount alone does not protect the hogp_device:
	 * blued_conn_central_teardown frees it independently of the refcount.
	 *
	 * The ATT-ops in-flight guard (att_ops_active) is now bumped on the
	 * MAIN thread by blued_central_start_pairing_async() BEFORE this worker
	 * is spawned — closing the TOCTOU window where the worker could be
	 * descheduled between a `hogp != NULL` check here and att_ops_begin(),
	 * during which a disconnect on the main thread would read
	 * att_ops_active == 0, free dev, and leave this worker dereferencing
	 * freed memory.  With begin() done before spawn, hogp is guaranteed
	 * live here; balance that begin() with a single end() below.
	 */
	(void)blued_central_start_pairing(conn->hogp, conn);
	blued_conn_att_ops_end(conn);
	blued_setup_worker_finish(conn);
	blued_conn_unref(conn);
	return (NULL);
}

int
blued_central_start_pairing_async(struct blued_conn *conn)
{
	pthread_t tid;
	pthread_attr_t attr;

	if (conn == NULL || conn->hogp == NULL)
		return (-1);
	/*
	 * C3-H2: refuse a second pairing/setup worker on the same conn.  Two
	 * detached workers would both drive dev->smp / dev->att concurrently,
	 * and the att_ops accounting could not be balanced cleanly against a
	 * single teardown.  This runs on the main dispatch thread, which is the
	 * only spawner, so the check-then-start is not racy.
	 */
	if (atomic_load(&conn->setup_worker_count) != 0)
		return (-1);
	if (pthread_attr_init(&attr) != 0)
		return (-1);
	(void)pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	blued_conn_ref(conn);
	blued_setup_worker_start(conn);
	/*
	 * C3-H2: bump att_ops_active HERE, on the main (dispatch) thread,
	 * BEFORE the detached worker can run, so a disconnect racing the
	 * about-to-run worker observes att_ops_active != 0 and defers the free
	 * of dev.  Re-validate hogp after begin() — still on the main thread,
	 * so teardown (also main-thread) cannot race this check.
	 */
	blued_conn_att_ops_begin(conn);
	if (conn->hogp == NULL) {
		blued_conn_att_ops_end(conn);
		blued_setup_worker_finish(conn);
		blued_conn_unref(conn);
		(void)pthread_attr_destroy(&attr);
		return (-1);
	}
	if (pthread_create(&tid, &attr, blued_central_pairing_worker,
	    conn) != 0) {
		blued_conn_att_ops_end(conn);
		blued_setup_worker_finish(conn);
		blued_conn_unref(conn);
		(void)pthread_attr_destroy(&attr);
		return (-1);
	}
	(void)pthread_attr_destroy(&attr);
	return (0);
}

/* Forward declarations for static functions */
static int	hogp_discover(struct hogp_device *dev);
static int	hogp_discover_cached(struct hogp_device *dev,
		    struct smp_bond *bond, bool hash_valid);
static void	hogp_cache_save(struct hogp_device *dev, struct smp_bond *bond);
static int	hogp_cache_restore(struct hogp_device *dev, struct smp_bond *bond);
static int	hogp_setup_vhid(struct hogp_device *dev);
static int	hogp_process_pdu(struct blued_conn *, int, const uint8_t *,
		    size_t, uint16_t);
static void	hogp_unsolicited(struct att_conn *, int, const uint8_t *,
		    size_t, void *);

/*
 * Central connection setup worker.
 *
 * Performs the blocking ATT connect, MTU exchange, bond/pair,
 * HOGP discovery, and vhid setup.  On success, registers the
 * connection with the kqueue event loop via the self-pipe.
 */
static void *
blued_conn_setup_central_impl(void *arg)
{
	struct blued_conn *conn = arg;
	struct hogp_device *dev;
	int ret;

	/*
	 * Connection limit is now enforced atomically in
	 * blued_conn_alloc() under the write lock.
	 */

	dev = conn->hogp;
	if (dev == NULL) {
		blued_central_setup_fail(conn);
		return (NULL);
	}

	dev->att.fd = -1;
	dev->smp.fd = -1;

	/* Connect ATT */
	{
		char addr_str[18];
		bt_ntoa((bdaddr_t *)dev->addr, addr_str);
		LOG_HOGP(1, "connecting to %s...", addr_str);
	}

	{
		int att_fd;
		char addr_str_pool[18];

		att_fd = blued_socket_broker_take();
		if (att_fd >= 0) {
			ret = att_open_fd(&dev->att, att_fd,
			    (const uint8_t *)&conn->adapter->addr,
			    conn->local_own_addr_type, dev->addr,
			    dev->addr_type);
		} else {
			ret = att_open(&dev->att,
			    (const uint8_t *)&conn->adapter->addr,
			    conn->local_own_addr_type, dev->addr,
			    dev->addr_type);
		}

		if (ret < 0) {
			bt_ntoa((bdaddr_t *)dev->addr, addr_str_pool);
			if (att_fd >= 0) {
				warn("ATT connect failed for %s",
				    addr_str_pool);
				/*
				 * att_open_fd() leaves the caller-owned pool
				 * fd open on failure; close it to avoid a
				 * pool fd leak.
				 */
				close(att_fd);
			}
			blued_central_setup_fail(conn);
			return (NULL);
		}
		blued_conn_apply_cached_local(conn);
		blued_conn_local_from_socket(conn, dev->att.fd);
		blued_conn_get_local(conn, dev->local_addr, NULL);
	}
	att_set_unsolicited_handler(&dev->att, hogp_unsolicited, conn);

	/* Check for daemon shutdown between blocking steps */
	if (atomic_load(&blued_shutting_down)) {
		blued_central_setup_fail(conn);
		return (NULL);
	}

	LOG_HOGP(1, "connected, exchanging MTU");

	/* Get connection handle -- poll with exponential backoff */
	{
		int retries;
		useconds_t delay = CON_HANDLE_POLL_INIT_USEC;

		for (retries = 0; retries < CON_HANDLE_POLL_RETRIES;
		    retries++) {
			if (hci_get_con_handle(dev->hci_fd, dev->addr,
			    dev->addr_type, &dev->con_handle) == 0)
				break;
			usleep(delay);
			delay *= 2;
		}
		if (retries == CON_HANDLE_POLL_RETRIES) {
			warnx("could not get HCI connection handle");
			blued_central_setup_fail(conn);
			return (NULL);
		}
		LOG_HOGP(1, "connection handle=%04x", dev->con_handle);
		conn->con_handle = dev->con_handle;
		conn->con_handle_valid = true;
		dev->att.con_handle = dev->con_handle;
	}
	blued_conn_apply_cached_local(conn);
	blued_conn_get_local(conn, dev->local_addr, NULL);

	/* Request optimal link parameters */
	if (dev->le_features & LE_FEAT_DATA_LENGTH_EXT)
		hci_le_set_data_length(dev->hci_fd, dev->con_handle,
		    0x00FB, 0x0848);
	/*
	 * PHY preference: an operator-supplied CONNECT tx_phy=/rx_phy= wins;
	 * otherwise default to 2M when the controller advertises it.  A zero
	 * mask means "no preference", encoded via the all_phys bits.
	 */
	if (conn->has_req_phy) {
		uint8_t all_phys = 0;

		if (conn->req_tx_phys == 0)
			all_phys |= 0x01;
		if (conn->req_rx_phys == 0)
			all_phys |= 0x02;
		hci_le_set_phy(dev->hci_fd, dev->con_handle, all_phys,
		    conn->req_tx_phys, conn->req_rx_phys, 0x0000);
	} else if (dev->le_features & LE_FEAT_2M_PHY) {
		hci_le_set_phy(dev->hci_fd, dev->con_handle, 0x00,
		    0x02, 0x02, 0x0000);
	}

	/*
	 * Initial connection parameters.  An operator-requested CONNECT
	 * itvl=/latency=/timeout= is applied as asked; absent that, we issue
	 * NOTHING and keep the parameters the Link Layer already chose when it
	 * created the connection (Core Spec Vol 4 Part E §7.8.12).
	 *
	 * This used to push a fixed 6..12 (7.5-15ms) interval with peripheral
	 * latency 4 onto every link the instant it came up.  Nothing in the
	 * specification asks a Central to do that: Vol 3 Part C §9.3.9 defines
	 * the Connection Parameter Update procedure as something either side
	 * initiates "with the required connection parameters", and there is no
	 * requirement to initiate it at all.  What the specification does say
	 * (§9.3.9) is that a peer finding the parameters unacceptable "may
	 * disconnect the connection with the error code 0x3B (Unacceptable
	 * Connection Parameters)" -- which is exactly what phones answer to a
	 * 7.5ms interval, because that is a power budget no general-purpose
	 * peripheral will accept unprompted.
	 *
	 * All three reference stacks agree that a Central stays quiet here:
	 *
	 *   BlueZ    issues no unprompted update.  It only acts after reading
	 *            the peer's GATT Peripheral Preferred Connection Parameters
	 *            characteristic (profiles/gap/gas.c, read_ppcp_cb), and
	 *            even then hands the values to the kernel rather than
	 *            sending an update itself.  Its substituted defaults when
	 *            the peer states no preference are 0x0018..0x0028
	 *            (30-50ms) with latency 0.
	 *   Zephyr   arms its parameter-update work only for the PERIPHERAL
	 *            role (host/conn.c, BT_CONN_CONNECTED); as Central
	 *            deferred_work() returns immediately.  Its peripheral
	 *            preferred defaults are likewise 24..40 (30-50ms),
	 *            latency 0, timeout 42.
	 *   NimBLE   connects with 30-50ms, latency 0, and performs no
	 *            automatic post-connect update at all.
	 *
	 * The 30-50ms/latency-0 range those three converge on is already
	 * exactly what this stack connects with: ng_hci_lp_le_con_req() fills
	 * LE Create Connection from NG_HCI_LE_CONN_INTERVAL_MIN/MAX_DEFAULT
	 * and NG_HCI_LE_CONN_LATENCY_DEFAULT, which are 0x0018, 0x0028 and 0
	 * (sys/netgraph/bluetooth/include/ng_hci.h) -- the same numbers, to
	 * the octet.  The link therefore comes up on the consensus parameters
	 * and the old unprompted update did nothing but tear them down, so the
	 * correct action is to leave it alone.  A peer that wants something else asks, and
	 * blued_event.c answers that request under
	 * hci_le_conn_param_req_acceptable() policy.
	 */
	if (conn->has_req_conn_params)
		hci_le_connection_update(dev->hci_fd, dev->con_handle,
		    conn->req_itvl_min, conn->req_itvl_max,
		    conn->req_latency, conn->req_timeout);

	/*
	 * Request the operator-preferred ATT MTU (SET_MTU; Core Spec Vol 3
	 * Part F §3.4.2), falling back to the largest supported fixed-CID value
	 * when unset.  EATT MTUs are negotiated by L2CAP, not Exchange MTU.
	 */
	if (att_exchange_mtu(&dev->att, blued_g.att_preferred_mtu != 0 ?
	    blued_g.att_preferred_mtu : ATT_UNENHANCED_MAX_MTU) < 0)
		warn("MTU exchange failed, using default %d",
		    ATT_DEFAULT_MTU);
	else
		LOG_HOGP(1, "MTU=%d", dev->att.mtu);

	/* Attempt encryption with existing bond, or pair */
	{
		struct smp_bond bond;

		/*
		 * The bond snapshot also settles the Table 10.2 column used by
		 * ATT error selection for as long as this link stays
		 * unencrypted (att.h, att_check_read_perm()).  Assigned on both
		 * arms so a reused hogp_device cannot carry a previous link's
		 * answer into an unbonded one.
		 */
		if (hogp_bond_snapshot(dev, &bond)) {
			dev->att.has_peer_key = bond.has_ltk;
			LOG_HOGP(1, "found existing bond, encrypting...");
			dev->smp.hci_fd = dev->hci_fd;
			dev->smp.con_handle = dev->con_handle;
			if (smp_encrypt_with_ltk(&dev->smp, &bond) < 0) {
				warn("bonded encryption failed");
			} else {
				LOG_HOGP(1, "waiting for encryption...");
				if (hci_wait_encryption(dev->hci_fd,
				    dev->con_handle, 10) < 0)
					warn("encryption timeout");
				else {
					/*
					 * Reconnection encryption is
					 * honored only because it is backed by
					 * this peer's stored bond LTK.
					 */
					(void)att_conn_apply_encryption(
					    &dev->att,
					    bond.has_ltk, bond.is_mitm,
					    bond.key_size, 16);
					LOG_HOGP(1, "encrypted");
				}
			}
		} else {
			dev->att.has_peer_key = false;

			/*
			 * HOGP §7 line 2083, verbatim: "The HID Host, which
			 * must be a Central as per Section 2.4, shall perform
			 * the Bonding procedure with the HID Device, as defined
			 * in [2] Volume 3, Part C, Section 9.4.4."
			 *
			 * Unconditional, and before any characteristic is
			 * touched.  Bonding used to be reactive — entered only
			 * when a read returned Insufficient Authentication —
			 * which works only because a conformant device gates
			 * its characteristics (§7 line 2073).  Against a device
			 * that does not, the Report Map, the Report Reference
			 * descriptors and the HID Information were read and
			 * notifications enabled entirely in the clear, and no
			 * pairing ever happened.  Keystrokes readable by a
			 * passive listener are the exact failure §7 exists to
			 * prevent, so this fails closed.
			 *
			 * Note this path is HID-only: discovery below requires
			 * a HID Service (0x1812) and fails with ENOENT
			 * otherwise.
			 */
			LOG_HOGP(1, "no bond for this device; bonding before "
			    "reading characteristics (HOGP section 7)");
			if (blued_central_start_pairing(dev, conn) < 0) {
				warnx("HOGP requires bonding with the HID "
				    "device; setup aborted");
				blued_central_setup_fail(conn);
				return (NULL);
			}
		}
	}

	/*
	 * Opt into robust caching and subscribe to Service Changed BEFORE
	 * anything consults the handle cache: writing the Client Supported
	 * Features bit is what makes the peer report a stale cache at all
	 * (Core Vol 3 Part G §2.5.2.1), and the Database Hash read below is
	 * what then makes us change-aware again (§7.3.1).
	 */
	hogp_enable_change_awareness(dev);

	/*
	 * Check GATT Database Hash before discovery.
	 * Per Core Spec Vol 3 Part G 7.3.1 (Robust Caching), if the
	 * hash matches the bonded value, attribute handles are unchanged
	 * and we can use cached handles to skip full GATT discovery.
	 */
	{
		uint8_t remote_hash[16];
		struct smp_bond bond_store, *bond = NULL;
		bool hash_valid = false;

		if (hogp_bond_snapshot(dev, &bond_store))
			bond = &bond_store;
		if (bond != NULL && bond->has_db_hash) {
			if (gatt_read_database_hash(&dev->att,
			    remote_hash) == 0) {
				if (memcmp(bond->db_hash, remote_hash,
				    16) == 0) {
					LOG_HOGP(1, "GATT DB hash "
					    "unchanged, cache valid");
					hash_valid = true;
				} else {
					LOG_HOGP(1, "GATT DB hash "
					    "changed, full discovery "
					    "needed");
					memcpy(bond->db_hash, remote_hash,
					    16);
					bond->has_handle_cache = false;
					(void)hogp_bond_commit_metadata(dev, bond);
				}
			}
		} else if (bond != NULL && bond->has_handle_cache) {
			/*
			 * PC8: the in-memory bond blob carries a handle cache
			 * but no Database Hash; the GATT cache restored from
			 * persistent storage may still hold one.  If it matches
			 * the freshly read hash, reuse the cached handles.
			 */
			if (gatt_read_database_hash(&dev->att,
			    remote_hash) == 0 &&
			    blued_persist_gattcache_reuse(dev->addr,
			    dev->addr_type, remote_hash)) {
				LOG_HOGP(1, "persisted GATT cache hash match, "
				    "cache valid");
				hash_valid = true;
			}
		}

		ret = hogp_discover_cached(dev, bond, hash_valid);
	}

	/*
	 * Handle Database Out Of Sync -- full rediscovery.
	 *
	 * Core Vol 3 Part G §2.5.2.1 lines 72375-72378: a client receiving 0x12
	 * "shall consider its attribute cache invalid and shall not make use of
	 * the cached information until it has performed service discovery".
	 * Lines 72356-72360 make clear the error can arrive on essentially any
	 * request, so this must not be a single-site check: hogp_discover() and
	 * hogp_subscribe() propagate 0x12 out of the Report Map read, the
	 * Report Reference descriptor reads, the HID Information read and the
	 * CCCD writes, and every one of them lands here.
	 */
	if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
		LOG_HOGP(1, "ATT Database Out Of Sync, full rediscovery");
		hogp_invalidate_attr_cache(dev);
		ret = hogp_discover(dev);
	}

	/* Handle auth errors -- pair and retry */
	{
		if (ret == ATT_ERR_INSUFF_AUTHEN ||
		    ret == ATT_ERR_INSUFF_AUTHOR ||
		    ret == ATT_ERR_INSUFF_ENCRYPTION ||
		    ret == ATT_ERR_INSUFF_ENC_KEY_SIZE) {
			LOG_HOGP(1, "device requires pairing");

			if (blued_central_start_pairing(dev, conn) < 0) {
				blued_central_setup_fail(conn);
				return (NULL);
			}

			LOG_HOGP(1, "pairing complete, retrying discovery");

			ret = hogp_discover(dev);
		}
		/*
		 * The post-pairing rediscovery can itself be answered with
		 * 0x12 -- a server is free to change its database while we
		 * pair -- and that used to fall straight through to the fatal
		 * warnx() below, dropping the connection instead of doing what
		 * §2.5.2.1 asks.  One further recovery round is enough: a peer
		 * that answers a from-scratch discovery with 0x12 again is not
		 * converging.
		 */
		if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
			LOG_HOGP(1, "ATT Database Out Of Sync after pairing, "
			    "rediscovering");
			hogp_invalidate_attr_cache(dev);
			ret = hogp_discover(dev);
		}
		if (ret != 0) {
			warnx("HOGP discovery failed: %d", ret);
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	/* Update GATT Database Hash and handle cache after discovery */
	{
		uint8_t remote_hash[16];
		struct smp_bond bond;

		if (hogp_bond_snapshot(dev, &bond)) {
			if (!bond.has_db_hash) {
				if (gatt_read_database_hash(&dev->att,
				    remote_hash) == 0) {
					memcpy(bond.db_hash, remote_hash, 16);
					bond.has_db_hash = true;
				}
			}
			hogp_cache_save(dev, &bond);
			(void)hogp_bond_commit_metadata(dev, &bond);
			LOG_HOGP(1, "GATT DB hash and handle cache saved");
		}
	}

	/* Save device name to bond */
	if (dev->has_device_name) {
		struct smp_bond bond;
		if (hogp_bond_snapshot(dev, &bond) && !bond.has_name) {
			strlcpy(bond.name, dev->device_name, sizeof(bond.name));
			bond.has_name = true;
			(void)hogp_bond_commit_metadata(dev, &bond);
		}
	}

	/* Set up vhid device */
	if (dev->vhid_fd < 0) {
		if (hogp_setup_vhid(dev) != 0) {
			warnx("vhid setup failed");
			blued_central_setup_fail(conn);
			return (NULL);
		}
	}

	/* Subscribe to report notifications */
	ret = hogp_subscribe(dev);
	if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
		uint8_t *old_map;
		size_t old_len;
		bool same_map;

		/*
		 * A CCCD write answered with 0x12.  The cache is invalid
		 * (§2.5.2.1) and rediscovery is mandatory; but the vhid unit
		 * above was already configured with a Report Map, so recover in
		 * place only if the rediscovered descriptor is byte-identical.
		 * If it changed, the virtual HID device is wrong and cannot be
		 * re-described through an attached unit — fail the setup so the
		 * reconnect rebuilds it from an invalidated cache.
		 */
		LOG_HOGP(1, "ATT Database Out Of Sync while subscribing");
		hogp_invalidate_attr_cache(dev);
		old_map = dev->report_map;
		old_len = dev->report_map_len;
		dev->report_map = NULL;
		dev->report_map_len = 0;
		ret = hogp_discover(dev);
		same_map = (ret == 0 && dev->report_map != NULL &&
		    old_map != NULL && dev->report_map_len == old_len &&
		    memcmp(dev->report_map, old_map, old_len) == 0);
		free(old_map);
		if (!same_map) {
			warnx("HID Report Map changed under Database Out Of "
			    "Sync; dropping the link to rebuild the HID "
			    "device");
			blued_central_setup_fail(conn);
			return (NULL);
		}
		ret = hogp_subscribe(dev);
	}
	if (ret != 0) {
		warnx("HOGP subscribe failed");
		blued_central_setup_fail(conn);
		return (NULL);
	}

	/* Write Exit Suspend to HID Control Point */
	if (dev->hid_ctrl_handle != 0) {
		uint8_t exit_suspend = 0x01;
		att_write_cmd(&dev->att, dev->hid_ctrl_handle,
		    &exit_suspend, 1);
	}

	/* Close SMP -- not needed during active session */
	smp_close(&dev->smp);

	/*
	 * Prepare the connection for the event loop.  Everything that
	 * touches conn or dev MUST happen before blued_conn_register()
	 * below: registering conn->att_fd on the shared kqueue exposes
	 * conn to the main loop, which can free it (EV_EOF disconnect) at
	 * any time afterwards.  This detached thread has no join barrier,
	 * so any post-register use of conn/dev would be a use-after-free.
	 */
	conn->att_fd = dev->att.fd;
	conn->att = &dev->att;
	conn->con_handle = dev->con_handle;
	conn->con_handle_valid = true;

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		BLUED_PROBE_CONN_OPEN(addr_str, 0 /* central */);
	}

	/* Reset backoff on successful connection */
	conn->reconnect_delay = 0;

	/* Log negotiated PHY for diagnostics */
	{
		uint8_t tx_phy, rx_phy;

		if (hci_le_read_phy(dev->hci_fd, dev->con_handle,
		    &tx_phy, &rx_phy) == 0)
			LOG_HCI(1, "PHY: tx=%s rx=%s",
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
	}

	/* Log TX power for link quality diagnostics */
	if (dev->le_features & LE_FEAT_POWER_CONTROL) {
		int8_t cur_lvl, max_lvl;

		if (hci_le_enhanced_read_tx_power_level(dev->hci_fd,
		    dev->con_handle, 0x01 /* LE */,
		    &cur_lvl, &max_lvl) == 0)
			LOG_HCI(1, "TX power: current=%d dBm max=%d dBm",
			    cur_lvl, max_lvl);
	}

	/*
	 * Proactively open EATT bearers if both sides support it.
	 * Core Spec Vol 3 Part G Section 2.4.1: enhanced bearers
	 * provide parallel GATT operations.  Only attempted after
	 * encryption is active (EATT requires security).
	 */
	if (blued_cfg.eatt && dev->att.encrypted && !cap_sandboxed()) {
		int eatt_opened;

		/*
		 * Finding 95: this conn is already on blued_g.conns with a valid
		 * con_handle, so the event loop's Encryption-Change/Key-Refresh
		 * handler can find it and call att_close_eatt() concurrently.
		 * Serialise the bearer append against that teardown with
		 * att_sec_lock so the eatt array is never mutated by both.
		 */
		pthread_mutex_lock(&blued_g.att_sec_lock);
		eatt_opened = att_open_eatt(&dev->att,
		    (const uint8_t *)&conn->local_addr,
		    dev->addr, dev->addr_type, blued_cfg.eatt_bearers);
		pthread_mutex_unlock(&blued_g.att_sec_lock);
		if (eatt_opened > 0) {
			int bi;

			LOG_ATT(1, "opened %d EATT bearer(s)", eatt_opened);
			/*
			 * Core Spec Vol 3 Part G Section 5.3.1: an enhanced
			 * bearer's ATT_MTU comes from the connection exchange
			 * "or the latest L2CAP_CREDIT_BASED_RECONFIGURE_REQ
			 * packets"; there is no ATT_EXCHANGE_MTU_REQ on an
			 * enhanced bearer.  A bearer that came up smaller than
			 * the ATT_MTU already agreed on the fixed bearer would
			 * otherwise silently cap every operation the bearer
			 * selector sends to it, so ask for the larger value
			 * and re-derive the cached per-bearer MTU from the
			 * channel afterwards.  Both halves are best-effort: a
			 * peer or controller that refuses just leaves the
			 * bearer at what it negotiated.
			 */
			pthread_mutex_lock(&blued_g.att_sec_lock);
			for (bi = 0; bi < dev->att.eatt_count; bi++) {
				int bfd = dev->att.eatt[bi].fd;

				if (bfd < 0 ||
				    dev->att.eatt[bi].mtu >= dev->att.mtu)
					continue;
				if (ble_ecbfc_reconfig(bfd, dev->att.mtu,
				    dev->att.mtu) == 0)
					(void)att_eatt_refresh_bearer_mtu(
					    &dev->att, bfd);
			}
			pthread_mutex_unlock(&blued_g.att_sec_lock);
		}
	}

	/*
	 * Connection Subrating (BT 5.3) is not used — this stack
	 * targets BT 5.2 max.  The HCI wrappers exist as API stubs
	 * but are intentionally not called.
	 */

	/*
	 * Register the vhid Output-report fd (LED state etc.) now, after the
	 * last ATT operation of this thread (att_open_eatt above) but BEFORE
	 * the ACTIVE/register handoff below.  Registering it earlier exposed
	 * conn to the main loop's vhid handler (hogp_handle_vhid_output ->
	 * att_write_cmd) while this setup thread was still operating on the
	 * same att_conn, racing two writers on one ATT bearer (finding 89);
	 * registering it after the handoff dereferenced the non-refcounted
	 * dev after the main thread was already free to tear it down.  In
	 * this window the conn is still CONNECTING, so the main thread
	 * defers any teardown (disconnect_pending, finding 86) and cannot
	 * free dev, and an early Output report merely finds the conn on
	 * blued_g.conns and issues a Write Command on the fully set-up
	 * bearer -- benign.  On the failure paths the fd is deregistered/
	 * closed by blued_conn_central_teardown, so it can never be leaked
	 * while registered.
	 */
	if (dev->vhid_fd >= 0) {
		struct kevent vkev;

		EV_SET(&vkev, dev->vhid_fd, EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, BLUED_KQ_VHID_OUTPUT);
		if (kevent(blued_g.kq, &vkev, 1, NULL, 0, NULL) < 0)
			warn("kevent vhid output (non-fatal)");
		else
			LOG_HOGP(1, "vhid output reports enabled");
	}

	/*
	 * Expose the connection to the event loop.  Past this point conn
	 * (and dev) may be freed at any moment by the main thread, so we
	 * do nothing but signal success on the (global) setup pipe and
	 * return -- no further conn/dev access.
	 */
	/*
	 * Register first, then go ACTIVE.  blued_conn_register() only adds
	 * the ATT/EATT fds to the kqueue and does not require ACTIVE, while
	 * flipping ACTIVE before a failed register left a residual window:
	 * an ACTIVE conn with no registered bearers, and a
	 * blued_central_setup_fail() racing main-thread teardown without
	 * the CONNECTING state's deferral protection (finding 86).  Staying
	 * CONNECTING until the register succeeds keeps dev access protected
	 * on the failure path.
	 */
	if (blued_conn_register(conn) < 0) {
		warnx("blued_conn_register failed");
		blued_central_setup_fail(conn);
		return (NULL);
	}
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);

	LOG_HOGP(1, "setup complete, entering event loop");
	(void)write(blued_g.setup_pipe[1], "x", 1);
	return (NULL);
}

/*
 * Central setup thread entry point.
 *
 * The caller acquires a reference on conn before spawning this thread
 * (blued_conn_ref); the thread drops it here on exit, so the connection
 * memory survives for the whole setup even if the main loop tears the
 * connection down concurrently.
 */
void *
blued_conn_setup_central(void *arg)
{
	void *ret;

	ret = blued_conn_setup_central_impl(arg);
	blued_setup_worker_finish((struct blued_conn *)arg);
	blued_conn_unref((struct blued_conn *)arg);
	return (ret);
}

/*
 * ATT errors that the caller can act on (pair, or invalidate the attribute
 * cache and rediscover) rather than skip past.  Core Vol 3 Part C §10.3.2 for
 * the security codes; Core Vol 3 Part G §2.5.2.1 lines 72375-72378 for
 * Database Out Of Sync, which obliges the client to consider its cache invalid
 * and rediscover no matter which request carried the error.
 */
static bool
hogp_att_error_is_actionable(int ret)
{

	return (ret == ATT_ERR_INSUFF_AUTHEN ||
	    ret == ATT_ERR_INSUFF_AUTHOR ||
	    ret == ATT_ERR_INSUFF_ENCRYPTION ||
	    ret == ATT_ERR_INSUFF_ENC_KEY_SIZE ||
	    ret == ATT_ERR_DATABASE_OUT_OF_SYNC);
}

/*
 * Classify the Report characteristics (UUID 0x2A4D) of one HID Service
 * instance into `out'.
 *
 * Each Report characteristic definition carries a Report Reference descriptor
 * (UUID 0x2908) giving Report ID and Report Type; HIDS §2.5.3.2 line 847 makes
 * it a "shall" for Report Protocol Mode.  A Report whose descriptor is absent,
 * unreadable, short, or carries a Report Type outside HIDS Table 2.7's
 * 0x01-0x03 (0x00 is Prohibited, 0x04-0xFF RFU) cannot be classified.  Such a
 * Report is DROPPED with a diagnostic rather than retained with Report Type
 * 0x00: retained, it matches no branch — it is never subscribed and never
 * routed — so the device enumerates as a HID device that delivers nothing.
 *
 * Returns 0 with *nout set, or a nonzero ATT error the caller must act on.
 */
static int
hogp_classify_reports(struct hogp_device *dev, struct gatt_discovery *disc,
    struct hogp_report *out, int maxout, int *nout)
{
	int i, j, n = 0, ret;
	size_t len;

	for (i = 0; i < disc->nchars; i++) {
		struct hogp_report rpt;
		uint16_t desc_start, desc_end;
		bool have_ref = false;

		if (disc->chars[i].uuid16 != UUID_REPORT)
			continue;
		if (n >= maxout) {
			warnx("HID Service instance has more than %d Report "
			    "characteristics; the rest are dropped", maxout);
			break;
		}

		memset(&rpt, 0, sizeof(rpt));
		rpt.value_handle = disc->chars[i].value_handle;
		rpt.properties = disc->chars[i].properties;

		desc_start = rpt.value_handle + 1;
		if (i + 1 < disc->nchars)
			desc_end = disc->chars[i + 1].decl_handle - 1;
		else
			desc_end = disc->service.end_handle;

		for (j = 0; j < disc->ndescs; j++) {
			uint16_t dh = disc->descs[j].handle;

			if (dh < desc_start || dh > desc_end)
				continue;

			if (disc->descs[j].uuid16 ==
			    GATT_UUID_REPORT_REFERENCE) {
				uint8_t ref[2];

				ret = att_read(&dev->att, dh, ref,
				    sizeof(ref), &len);
				if (ret != 0) {
					if (hogp_att_error_is_actionable(ret))
						return (ret);
					warnx("Report Reference read failed "
					    "(handle=%04x, status %d); report "
					    "at handle %04x dropped", dh, ret,
					    rpt.value_handle);
					continue;
				}
				if (len < 2) {
					warnx("Report Reference at handle "
					    "%04x is %zu octets, not 2; "
					    "report at handle %04x dropped",
					    dh, len, rpt.value_handle);
					continue;
				}
				rpt.report_id = ref[0];
				rpt.report_type = ref[1];
				have_ref = true;
			} else if (disc->descs[j].uuid16 == GATT_UUID_CCCD)
				rpt.cccd_handle = dh;
		}

		if (!have_ref) {
			warnx("Report characteristic at handle %04x has no "
			    "readable Report Reference descriptor; dropped",
			    rpt.value_handle);
			continue;
		}
		if (!hogp_report_type_is_valid(rpt.report_type)) {
			warnx("Report characteristic at handle %04x has "
			    "Report Type %#02x (HIDS Table 2.7: prohibited or "
			    "reserved); dropped", rpt.value_handle,
			    rpt.report_type);
			continue;
		}

		out[n++] = rpt;
	}

	*nout = n;
	return (0);
}

/*
 * Process a single HID Service instance: classify its Report characteristics,
 * read its Report Map, read HID Information, save the HID Control Point
 * handle.
 *
 * `instance' is the index of this HID Service in primary-service discovery
 * order; it is stamped on every admitted report so routing can tell two
 * instances apart.
 *
 * Nothing here writes the Protocol Mode characteristic.  HOGP §4.11 line 1189:
 * "There are no requirements on a Report Host to use the Protocol Mode
 * characteristic", and HIDS §2.4.1.1 line 672 already has the value reset to
 * its Report Protocol Mode default at connection establishment.  Writing
 * Report mode here and then Boot mode from the boot fallback made this host
 * act as a Report Host and a Boot Host on one connection, which HOGP §2.3
 * lines 575/577 forbids in both directions.  The role is decided once, in
 * hogp_discover().
 */
int
hogp_process_service(struct hogp_device *dev, struct gatt_discovery *disc,
    int instance)
{
	struct hogp_report cand[HOGP_MAX_REPORTS];
	int ncand = 0;
	int i, ret;
	size_t len;

	/*
	 * Classify first.  A HID Service instance is admitted or rejected as a
	 * whole, so its Report Map must not be concatenated into the virtual
	 * HID device's descriptor before the decision is made.
	 */
	ret = hogp_classify_reports(dev, disc, cand,
	    (int)nitems(cand), &ncand);
	if (ret != 0)
		return (ret);

	/*
	 * H1: several HID Service instances share one virtual HID device and
	 * one report table here.  HOGP §2.5 line 603 sanctions multi-instance
	 * composite devices and HOGP §3.1.6 guarantees device-wide Report ID
	 * uniqueness ONLY for HID ISO devices, so two instances may legally use
	 * the same (Report Type, Report ID).  Merging those would route an
	 * outbound report to the wrong instance's characteristic.  Refuse the
	 * later instance instead: one working HID device and a diagnostic beats
	 * a composite device whose LED writes land on the mouse.
	 */
	if (hogp_instance_conflicts(dev->reports, dev->nreports, cand, ncand)) {
		warnx("HID Service instance %d (handles %04x-%04x) reuses a "
		    "report identity already claimed by an earlier instance; "
		    "instance dropped (one vhid per device)", instance,
		    disc->service.start_handle, disc->service.end_handle);
		return (0);
	}
	if (dev->nreports + ncand > HOGP_MAX_REPORTS) {
		warnx("report table full (%d); HID Service instance %d "
		    "dropped", HOGP_MAX_REPORTS, instance);
		return (0);
	}

	/*
	 * Read the Report Map characteristic (UUID 0x2A4B): the HID Report
	 * Descriptor.  It can be longer than MTU-1, so continue with Read Blob.
	 */
	for (i = 0; i < disc->nchars; i++) {
		/* Heap-allocate read buffer: Report Maps can be up to
		 * 4KB; too large for the stack in a setup thread. */
		uint8_t *rmbuf;
		size_t total = 0;
		size_t rmbuf_sz = 4096;
		uint16_t handle;
		uint16_t bearer_mtu;

		if (disc->chars[i].uuid16 != UUID_REPORT_MAP)
			continue;
		handle = disc->chars[i].value_handle;

		rmbuf = malloc(rmbuf_sz);
		if (rmbuf == NULL)
			return (ENOMEM);

		ret = att_read(&dev->att, handle, rmbuf, rmbuf_sz, &len);
		if (ret != 0) {
			warnx("failed to read Report Map");
			free(rmbuf);
			return (ret);
		}
		total = len;

		/*
		 * A chunk is "full" relative to the bearer that actually
		 * carried it: att_read/att_read_blob may be routed onto an EATT
		 * bearer whose CoC MTU was negotiated independently of
		 * dev->att.mtu.  Comparing against the fixed-bearer MTU would
		 * end the loop after the first chunk and hand a truncated
		 * Report Map — a malformed vhid — to the HID layer without even
		 * tripping the size warning below.
		 */
		bearer_mtu = att_last_bearer_mtu(&dev->att);
		while (len == (size_t)(bearer_mtu - 1) &&
		    total < rmbuf_sz) {
			ret = att_read_blob(&dev->att, handle, total,
			    rmbuf + total, rmbuf_sz - total, &len);
			if (ret != 0)
				break;
			total += len;
			bearer_mtu = att_last_bearer_mtu(&dev->att);
		}
		/*
		 * The buffer filled while a full MTU-sized blob was still coming:
		 * the Report Map is longer than rmbuf_sz and has been truncated.
		 * A truncated HID descriptor yields a malformed vhid, so surface
		 * it rather than attaching it silently (finding 68).
		 */
		if (total >= rmbuf_sz && len == (size_t)(bearer_mtu - 1))
			warnx("Report Map exceeds %zu bytes; truncated",
			    rmbuf_sz);

		if (dev->report_map == NULL) {
			dev->report_map = malloc(total);
			if (dev->report_map == NULL) {
				free(rmbuf);
				return (ENOMEM);
			}
			memcpy(dev->report_map, rmbuf, total);
			dev->report_map_len = total;
		} else {
			/* Concatenate report maps from multiple services */
			uint8_t *p = realloc(dev->report_map,
			    dev->report_map_len + total);
			if (p == NULL) {
				free(rmbuf);
				return (ENOMEM);
			}
			memcpy(p + dev->report_map_len, rmbuf, total);
			dev->report_map = p;
			dev->report_map_len += total;
		}
		free(rmbuf);

		/* Record this instance's Report Map handle, in service order,
		 * for the bond handle cache (multi-service restore). */
		if (dev->num_report_maps < (int)nitems(dev->report_map_handles))
			dev->report_map_handles[dev->num_report_maps++] =
			    handle;

		LOG_HOGP(1, "Report Map: %zu bytes", total);
		break;
	}

	/* Admit this instance's reports. */
	for (i = 0; i < ncand; i++) {
		struct hogp_report *rpt = &dev->reports[dev->nreports];

		*rpt = cand[i];
		rpt->instance = (uint8_t)instance;
		dev->nreports++;

		LOG_HOGP(1, "Report handle=%04x id=%d type=%d "
			    "cccd=%04x instance=%d",
			    rpt->value_handle, rpt->report_id,
			    rpt->report_type, rpt->cccd_handle, instance);
	}

	/*
	 * Read HID Information (UUID 0x2A4A).  HOGP §4.6.1.4 makes discovering
	 * it mandatory for a Report Host.
	 * Format: [bcdHID (2 LE), bCountryCode (1), Flags (1)]
	 */
	for (i = 0; i < disc->nchars; i++) {
		uint8_t info[4];

		if (disc->chars[i].uuid16 != UUID_HID_INFORMATION)
			continue;

		ret = att_read(&dev->att, disc->chars[i].value_handle,
		    info, sizeof(info), &len);
		if (ret == 0 && len >= 4) {
			dev->hid_bcdHID = (uint16_t)info[0] |
			    ((uint16_t)info[1] << 8);
			LOG_HOGP(1, "HID Information: bcdHID=%04x "
				    "country=%d flags=%02x",
				    dev->hid_bcdHID, info[2], info[3]);
		}
		break;
	}

	/*
	 * Save HID Control Point handle (UUID 0x2A4C).
	 * Used for Suspend/Exit Suspend per HIDS §2.11: the behaviour is the
	 * same whichever HID Service instance the control point belongs to, so
	 * last-instance-wins is fine.
	 */
	for (i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 == UUID_HID_CONTROL_POINT) {
			dev->hid_ctrl_handle = disc->chars[i].value_handle;
			break;
		}
	}

	return (0);
}

/*
 * Read PnP ID from Device Information Service (0x180A).
 * PnP ID (UUID 0x2A50) is 7 bytes:
 *   vendor_id_source(1) + vendor_id(2 LE) + product_id(2 LE) + product_version(2 LE)
 *
 * Non-fatal: if DIS or PnP ID is absent, idVendor/idProduct stay 0.
 */
static void
hogp_read_dis_pnpid(struct hogp_device *dev, struct gatt_service *dis)
{
	struct gatt_char chars[GATT_MAX_CHARS];
	int nchars, ret;
	size_t len;

	ret = gatt_discover_characteristics(&dev->att,
	    dis->start_handle, dis->end_handle,
	    chars, GATT_MAX_CHARS, &nchars);
	if (ret != 0)
		return;

	for (int i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_PNP_ID)
			continue;

		uint8_t pnp[7];
		ret = att_read(&dev->att, chars[i].value_handle,
		    pnp, sizeof(pnp), &len);
		if (ret != 0 || len < 7)
			break;

		dev->idVendor = (uint16_t)pnp[1] |
		    ((uint16_t)pnp[2] << 8);
		dev->idProduct = (uint16_t)pnp[3] |
		    ((uint16_t)pnp[4] << 8);

		LOG_HOGP(1, "DIS PnP ID: source=%d vendor=%04x "
			    "product=%04x version=%04x",
			    pnp[0], dev->idVendor, dev->idProduct,
			    (uint16_t)pnp[5] | ((uint16_t)pnp[6] << 8));
		break;
	}
}

/*
 * Read Battery Level from Battery Service (0x180F).
 * Battery Level (UUID 0x2A19) is a single byte (0-100 %).
 *
 * Non-fatal: if Battery Service or Battery Level is absent, nothing happens.
 *
 * The located service range and Battery Level value handle are recorded on the
 * device so the bond handle cache can carry them across reconnects; the caller
 * reaches this both from the primary-service list and from HID Service
 * relationship discovery (HOGP §4.5.3).
 */
static void
hogp_read_battery(struct hogp_device *dev, struct gatt_service *bas)
{
	struct gatt_char chars[GATT_MAX_CHARS];
	int nchars, ret;
	size_t len;

	ret = gatt_discover_characteristics(&dev->att,
	    bas->start_handle, bas->end_handle,
	    chars, GATT_MAX_CHARS, &nchars);
	if (ret != 0)
		return;

	for (int i = 0; i < nchars; i++) {
		if (chars[i].uuid16 != UUID_BATTERY_LEVEL)
			continue;

		uint8_t level;

		dev->bat_svc_start = bas->start_handle;
		dev->bat_svc_end = bas->end_handle;
		dev->battery_level_handle = chars[i].value_handle;

		ret = att_read(&dev->att, chars[i].value_handle,
		    &level, sizeof(level), &len);
		if (ret != 0 || len < 1)
			break;

		LOG_HOGP(1, "Battery Level: %u%%", level);
		break;
	}
}

/*
 * Save discovered HOGP handles to a bond's handle cache.
 * Called after successful full GATT discovery to avoid rediscovery
 * on subsequent reconnects when the GATT Database Hash matches.
 */
static void
hogp_cache_save(struct hogp_device *dev, struct smp_bond *bond)
{
	int i, n;

	if (bond == NULL || dev->nreports == 0)
		return;
	/*
	 * Only persist the handle cache when hid_disc was actually populated by
	 * a full discovery (finding 118).  On a cache-hit reconnect hid_disc is
	 * empty (nchars == 0) even though dev->nreports > 0 (restored from the
	 * cache); saving here would zero report_map_handle/hid_info_handle/etc.
	 * and the NEXT reconnect would read a bogus (zero) Report Map handle and
	 * discard the cache with ENOENT.
	 */
	if (dev->hid_disc.nchars == 0) {
		LOG_HOGP(1, "handle cache save skipped: no fresh discovery");
		return;
	}

	bond->hid_svc_start = dev->hid_disc.service.start_handle;
	bond->hid_svc_end = dev->hid_disc.service.end_handle;
	bond->report_map_handle = 0;
	bond->hid_info_handle = 0;
	bond->protocol_mode_handle = 0;
	/* Finding 68: persist the HID Control Point + report-map handles. */
	bond->hid_ctrl_handle = dev->hid_ctrl_handle;
	bond->num_report_maps = 0;
	memset(bond->report_map_handles, 0, sizeof(bond->report_map_handles));

	for (i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 == UUID_REPORT_MAP) {
			bond->report_map_handle =
			    dev->hid_disc.chars[i].value_handle;
		} else if (dev->hid_disc.chars[i].uuid16 == UUID_HID_INFORMATION)
			bond->hid_info_handle =
			    dev->hid_disc.chars[i].value_handle;
		else if (dev->hid_disc.chars[i].uuid16 == UUID_PROTOCOL_MODE)
			bond->protocol_mode_handle =
			    dev->hid_disc.chars[i].value_handle;
	}

	/*
	 * Persist EVERY HID service instance's Report Map handle, in the
	 * service order the discovery loop recorded them (hid_disc above only
	 * covers the primary instance): the full discovery concatenates the
	 * maps across instances, so a cache-hit restore must be able to do
	 * the same or multi-service devices come back with a truncated HID
	 * descriptor.
	 */
	n = dev->num_report_maps;
	if (n > (int)nitems(bond->report_map_handles))
		n = (int)nitems(bond->report_map_handles);
	for (i = 0; i < n; i++)
		bond->report_map_handles[i] = dev->report_map_handles[i];
	bond->num_report_maps = (uint8_t)n;

	n = dev->nreports;
	if (n > HOGP_MAX_REPORTS)
		n = HOGP_MAX_REPORTS;
	for (i = 0; i < n; i++) {
		bond->report_handles[i] = dev->reports[i].value_handle;
		bond->report_cccd_handles[i] = dev->reports[i].cccd_handle;
		bond->report_types[i] = dev->reports[i].report_type;
		bond->report_ids[i] = dev->reports[i].report_id;
	}
	bond->num_reports = n;

	/*
	 * Battery Service handles located by primary and by relationship
	 * discovery (HOGP §4.5.3).  Zero when the peer exposes none.
	 */
	bond->battery_level_handle = dev->battery_level_handle;
	bond->battery_cccd_handle = 0;
	bond->bat_svc_start = dev->bat_svc_start;
	bond->bat_svc_end = dev->bat_svc_end;

	bond->has_handle_cache = true;
	LOG_HOGP(1, "handle cache saved: %d reports, HID svc %04x-%04x",
	    n, bond->hid_svc_start, bond->hid_svc_end);
}

/*
 * Restore HOGP handles from bond cache, skipping full GATT discovery.
 * Must still read Report Map and HID Information from the device since
 * those are value-based (not handles).  Returns 0 on success, nonzero
 * on failure (caller should fall back to full discovery).
 */
static int
hogp_cache_restore(struct hogp_device *dev, struct smp_bond *bond)
{
	int i, ret;
	size_t len;

	if (bond == NULL || !bond->has_handle_cache || bond->num_reports <= 0) {
		LOG_HOGP(1, "handle cache: no valid cache");
		return (-1);
	}

	LOG_HOGP(1, "restoring %d report handles from cache "
	    "(HID svc %04x-%04x)", bond->num_reports,
	    bond->hid_svc_start, bond->hid_svc_end);

	/* Clear state as hogp_discover does */
	free(dev->report_map);
	dev->report_map = NULL;
	dev->report_map_len = 0;
	dev->nreports = 0;
	dev->num_report_maps = 0;
	memset(dev->report_map_handles, 0, sizeof(dev->report_map_handles));
	/*
	 * A cache-hit restore does NOT populate hid_disc (it is a full-discovery
	 * artifact).  Clear it so hogp_cache_save() can tell this path apart and
	 * refuse to overwrite the persisted metadata with zeros (finding 118).
	 */
	memset(&dev->hid_disc, 0, sizeof(dev->hid_disc));
	/*
	 * Finding 68: restore the HID Control Point handle from the bond cache
	 * so a cache-hit reconnect issues the Exit-Suspend write (below) without
	 * rediscovery.  Zero when the cached peer had no control point.
	 */
	dev->hid_ctrl_handle = bond->hid_ctrl_handle;
	dev->hid_bcdHID = 0;
	dev->idVendor = 0;
	dev->idProduct = 0;
	/*
	 * The handle cache does not persist the Service Changed value handle
	 * (that would need a bond-cache field, SMP-side).  It is not needed
	 * here: hogp_enable_change_awareness() locates the characteristic by
	 * Read Using Characteristic UUID on every connection, before this runs,
	 * and enables its indications — so do NOT clear it, or a cache-hit
	 * reconnect would subscribe to Service Changed and then be unable to
	 * recognise the indication when it arrived.
	 */

	/*
	 * Restore report handles from cache.
	 *
	 * The bond record has no per-report HID Service instance field, so
	 * every restored report is tagged instance 0.  That is sound for
	 * routing because the cache can only ever have been written from a
	 * device whose admitted instances were free of (Report Type, Report ID)
	 * collisions -- hogp_process_service() refuses to admit a colliding
	 * instance -- so a restored table is unambiguous by (type, id) alone.
	 * Carrying the real instance index across a bond needs a bond-cache
	 * field (smp.h).
	 */
	for (i = 0; i < bond->num_reports && i < HOGP_MAX_REPORTS; i++) {
		dev->reports[i].value_handle = bond->report_handles[i];
		dev->reports[i].cccd_handle = bond->report_cccd_handles[i];
		dev->reports[i].report_type = bond->report_types[i];
		dev->reports[i].report_id = bond->report_ids[i];
		dev->reports[i].instance = 0;
		dev->nreports++;

		LOG_HOGP(1, "cache: Report handle=%04x id=%d type=%d "
		    "cccd=%04x", bond->report_handles[i],
		    bond->report_ids[i], bond->report_types[i],
		    bond->report_cccd_handles[i]);
	}

	/*
	 * Read the Report Map value from EVERY cached HID service instance,
	 * concatenating in service order exactly as the full discovery does
	 * (multi-service HOGP) -- restoring only the primary instance's map
	 * rebuilt a truncated HID descriptor on multi-instance devices.  The
	 * value is needed for vhid setup even though the handles are cached.
	 * Older caches carry only report_map_handle; treat it as a
	 * one-element list.
	 */
	{
		uint16_t rm_handles[nitems(bond->report_map_handles)];
		int j, nrm = 0;

		if (bond->num_report_maps > 0) {
			int nmaps = bond->num_report_maps;

			if (nmaps > (int)nitems(bond->report_map_handles))
				nmaps = (int)nitems(bond->report_map_handles);
			for (j = 0; j < nmaps; j++)
				if (bond->report_map_handles[j] != 0)
					rm_handles[nrm++] =
					    bond->report_map_handles[j];
		} else if (bond->report_map_handle != 0)
			rm_handles[nrm++] = bond->report_map_handle;

		for (j = 0; j < nrm; j++) {
			uint8_t *rmbuf, *p;
			size_t total = 0;
			size_t rmbuf_sz = 4096;
			uint16_t bearer_mtu;

			rmbuf = malloc(rmbuf_sz);
			if (rmbuf == NULL)
				return (ENOMEM);

			ret = att_read(&dev->att, rm_handles[j],
			    rmbuf, rmbuf_sz, &len);
			if (ret != 0) {
				warnx("cache: failed to read Report Map");
				free(rmbuf);
				return (ret);
			}
			total = len;

			/* Bearer-relative chunk test; see hogp_process_service(). */
			bearer_mtu = att_last_bearer_mtu(&dev->att);
			while (len == (size_t)(bearer_mtu - 1) &&
			    total < rmbuf_sz) {
				ret = att_read_blob(&dev->att,
				    rm_handles[j], total,
				    rmbuf + total, rmbuf_sz - total, &len);
				if (ret != 0)
					break;
				total += len;
				bearer_mtu = att_last_bearer_mtu(&dev->att);
			}
			if (total >= rmbuf_sz &&
			    len == (size_t)(bearer_mtu - 1))
				warnx("cache: Report Map exceeds %zu bytes; "
				    "truncated", rmbuf_sz);

			/* realloc(NULL, n) == malloc(n): appends work for the
			 * first instance too. */
			p = realloc(dev->report_map,
			    dev->report_map_len + total);
			if (p == NULL) {
				free(rmbuf);
				return (ENOMEM);
			}
			memcpy(p + dev->report_map_len, rmbuf, total);
			dev->report_map = p;
			dev->report_map_len += total;
			free(rmbuf);

			LOG_HOGP(1, "cache: Report Map: %zu bytes "
			    "(instance %d)", total, j);
		}
	}

	/*
	 * Read HID Information from cached handle.
	 */
	if (bond->hid_info_handle != 0) {
		uint8_t info[4];

		ret = att_read(&dev->att, bond->hid_info_handle,
		    info, sizeof(info), &len);
		if (ret == 0 && len >= 4) {
			dev->hid_bcdHID = (uint16_t)info[0] |
			    ((uint16_t)info[1] << 8);
			LOG_HOGP(1, "cache: HID Information: bcdHID=%04x",
			    dev->hid_bcdHID);
		}
	}

	/*
	 * No Protocol Mode write on this path either.  HOGP §4.11 line 1189
	 * places no requirement on a Report Host to use the characteristic,
	 * HIDS §2.4.1.1 line 672 already resets the value to its Report
	 * Protocol Mode default at connection establishment, and a Report-mode
	 * write followed by the boot fallback's Boot-mode write would make this
	 * host both roles at once (HOGP §2.3 lines 575/577).  The role is
	 * decided once, in hogp_discover().
	 */

	/*
	 * Read Device Name from GAP Service (0x2A00) via Read By Type.
	 * This doesn't depend on cached handles.
	 */
	{
		uint8_t val[32];
		size_t vlen = 0;

		/*
		 * Skip the 3-byte Read By Type Response header
		 * (attr_data_len(1) + handle(2)) that att_read_by_type()
		 * leaves in front of the value (Vol 3 Part F §3.4.4.1).
		 */
		if (att_read_by_type(&dev->att, 0x0001, 0xFFFF,
		    UUID_DEVICE_NAME, val, sizeof(val), &vlen) == 0 &&
		    vlen > 3) {
			size_t namelen = vlen - 3;
			int nlen = (int)(namelen > 31 ? 31 : namelen);
			memcpy(dev->device_name, val + 3, nlen);
			dev->device_name[nlen] = '\0';
			dev->has_device_name = true;
			LOG_HOGP(1, "cache: device name: %s",
			    dev->device_name);
		}
	}

	/*
	 * Read DIS PnP ID via Read By Type -- handle-independent.
	 *
	 * att_read_by_type() strips only the opcode, so the 7-byte PnP ID
	 * value is preceded by a 3-byte Read By Type Response header:
	 * attr_data_len(1) + handle(2) (Vol 3 Part F §3.4.4.1).  The full
	 * payload is 10 bytes: [len][handle(2)][source(1)][vendor(2)]
	 * [product(2)][version(2)].  A 7-byte buffer truncated the value and
	 * the old pnp[1]/pnp[3] offsets read the handle bytes as the IDs.
	 */
	{
		uint8_t pnp[10];
		size_t plen = 0;

		if (att_read_by_type(&dev->att, 0x0001, 0xFFFF,
		    UUID_PNP_ID, pnp, sizeof(pnp), &plen) == 0 &&
		    plen >= 10) {
			dev->idVendor = (uint16_t)pnp[4] |
			    ((uint16_t)pnp[5] << 8);
			dev->idProduct = (uint16_t)pnp[6] |
			    ((uint16_t)pnp[7] << 8);
			LOG_HOGP(1, "cache: PnP ID: vendor=%04x product=%04x",
			    dev->idVendor, dev->idProduct);
		}
	}

	if (dev->report_map == NULL) {
		warnx("cache: Report Map not available");
		return (ENOENT);
	}

	LOG_HOGP(1, "handle cache restore complete: %d reports, %zu bytes "
	    "report map", dev->nreports, dev->report_map_len);

	return (0);
}

/*
 * Discover with cache support.
 * If the bond has a valid handle cache and the hash matches, restore
 * from cache.  Otherwise do full discovery.
 */
static int
hogp_discover_cached(struct hogp_device *dev, struct smp_bond *bond,
    bool hash_valid)
{
	/*
	 * Attempt cache restore if hash is valid and cache exists.
	 */
	if (bond != NULL && hash_valid && bond->has_handle_cache) {
		int ret = hogp_cache_restore(dev, bond);
		if (ret == 0) {
			LOG_HOGP(1, "GATT discovery skipped (cached handles)");
			return (0);
		}
		LOG_HOGP(1, "cache restore failed (%d), falling back to "
		    "full discovery", ret);
		bond->has_handle_cache = false;
	}

	return (hogp_discover(dev));
}

/*
 * Report IDs stamped on the two halves of a combo boot device.  Boot Protocol
 * reports carry no Report ID on the wire; these number the concatenated
 * descriptor so one virtual HID device can carry both, and are prepended on
 * delivery and stripped on send by the same code that handles a Report Host's
 * numbered reports (HOGP §4.8.1).
 */
#define HOGP_BOOT_KB_REPORT_ID		1
#define HOGP_BOOT_MOUSE_REPORT_ID	2

/*
 * Append one boot report descriptor to dst at off, optionally numbering it.
 *
 * Both boot descriptors open with the same six-octet Usage Page / Usage /
 * Collection(Application) preamble; a Report ID is a global item and is
 * placed immediately after it so it applies to every main item of that
 * collection (USB HID 1.11 §6.2.2.7).  Returns the new offset, or 0 if the
 * result would not fit.
 */
static size_t
hogp_boot_map_append(uint8_t *dst, size_t dstlen, size_t off,
    const uint8_t *map, size_t maplen, uint8_t report_id)
{
	const size_t pre = 6;

	if (maplen < pre)
		return (0);
	if (off + maplen + (report_id != 0 ? 2 : 0) > dstlen)
		return (0);
	memcpy(dst + off, map, pre);
	off += pre;
	if (report_id != 0) {
		dst[off++] = 0x85;	/* Report ID (global) */
		dst[off++] = report_id;
	}
	memcpy(dst + off, map + pre, maplen - pre);
	return (off + maplen - pre);
}

/*
 * The Client Characteristic Configuration descriptor of the characteristic
 * whose value attribute is value_handle: the first CCCD after it that is not
 * separated from it by a later Characteristic declaration.  0 if there is
 * none.
 */
static uint16_t
hogp_boot_find_cccd(const struct gatt_discovery *disc, uint16_t value_handle)
{
	int j, k;

	for (j = 0; j < disc->ndescs; j++) {
		uint16_t dh = disc->descs[j].handle;
		bool belongs = true;

		if (dh <= value_handle ||
		    disc->descs[j].uuid16 != GATT_UUID_CCCD)
			continue;
		for (k = 0; k < disc->nchars; k++) {
			if (disc->chars[k].decl_handle > value_handle &&
			    disc->chars[k].decl_handle <= dh) {
				belongs = false;
				break;
			}
		}
		if (belongs)
			return (dh);
	}
	return (0);
}

/*
 * Append one boot-mode report to the device's report table, if there is
 * room for it.
 */
static void
hogp_boot_add_report(struct hogp_device *dev, uint16_t value_handle,
    uint16_t cccd_handle, uint8_t report_id, uint8_t report_type,
    uint8_t properties)
{
	struct hogp_report *rpt;

	if (dev->nreports >= HOGP_MAX_REPORTS) {
		warnx("report table full (%d); boot report at handle %04x "
		    "dropped", HOGP_MAX_REPORTS, value_handle);
		return;
	}
	rpt = &dev->reports[dev->nreports++];
	memset(rpt, 0, sizeof(*rpt));
	rpt->value_handle = value_handle;
	rpt->cccd_handle = cccd_handle;
	rpt->report_id = report_id;
	rpt->report_type = report_type;
	rpt->instance = 0;
	rpt->properties = properties;
	LOG_HOGP(1, "boot report type=%u id=%u handle=%04x cccd=%04x",
	    report_type, report_id, value_handle, cccd_handle);
}

/*
 * Boot Protocol fallback: construct a minimal HID Report Map for devices
 * that expose Boot Keyboard (0x2A22) or Boot Mouse (0x2A33) characteristics
 * but lack a Report Map characteristic.
 *
 * This is where the host's HOGP role is decided, once per device.  HOGP §2.1
 * line 493 defines three roles — HID Device, Boot Host, Report Host — and §2.3
 * lines 575/577 make the two host roles mutually exclusive in both directions.
 * A device with a Report Map is handled as a Report Host, which writes no
 * Protocol Mode at all (§4.11 line 1189); only when there is no Report Map
 * does this function take the Boot Host role and write Boot Protocol Mode to
 * every HID Service instance (§4.11 line 1187), which is what `pm_handles'
 * carries.
 *
 * Returns 0 on success (report_map set, boot report added),
 *         ENOENT if no boot characteristics found.
 */
static int
hogp_setup_boot_protocol(struct hogp_device *dev, const uint16_t *pm_handles,
    int npm_handles)
{
	/* Standard Boot Keyboard HID Report Descriptor */
	static const uint8_t boot_kb_report_map[] = {
	    0x05, 0x01,        /* Usage Page (Generic Desktop) */
	    0x09, 0x06,        /* Usage (Keyboard) */
	    0xA1, 0x01,        /* Collection (Application) */
	    0x05, 0x07,        /*   Usage Page (Key Codes) */
	    0x19, 0xE0,        /*   Usage Min (224) */
	    0x29, 0xE7,        /*   Usage Max (231) */
	    0x15, 0x00,        /*   Logical Min (0) */
	    0x25, 0x01,        /*   Logical Max (1) */
	    0x75, 0x01,        /*   Report Size (1) */
	    0x95, 0x08,        /*   Report Count (8) */
	    0x81, 0x02,        /*   Input (Data, Variable, Absolute) */
	    0x95, 0x01,        /*   Report Count (1) */
	    0x75, 0x08,        /*   Report Size (8) */
	    0x81, 0x01,        /*   Input (Constant) */
	    0x95, 0x05,        /*   Report Count (5) */
	    0x75, 0x01,        /*   Report Size (1) */
	    0x05, 0x08,        /*   Usage Page (LEDs) */
	    0x19, 0x01,        /*   Usage Min (1) */
	    0x29, 0x05,        /*   Usage Max (5) */
	    0x91, 0x02,        /*   Output (Data, Variable, Absolute) */
	    0x95, 0x01,        /*   Report Count (1) */
	    0x75, 0x03,        /*   Report Size (3) */
	    0x91, 0x01,        /*   Output (Constant) */
	    0x95, 0x06,        /*   Report Count (6) */
	    0x75, 0x08,        /*   Report Size (8) */
	    0x15, 0x00,        /*   Logical Min (0) */
	    0x25, 0x65,        /*   Logical Max (101) */
	    0x05, 0x07,        /*   Usage Page (Key Codes) */
	    0x19, 0x00,        /*   Usage Min (0) */
	    0x29, 0x65,        /*   Usage Max (101) */
	    0x81, 0x00,        /*   Input (Data, Array) */
	    0xC0               /* End Collection */
	};

	/* Standard Boot Mouse HID Report Descriptor */
	static const uint8_t boot_mouse_report_map[] = {
	    0x05, 0x01,        /* Usage Page (Generic Desktop) */
	    0x09, 0x02,        /* Usage (Mouse) */
	    0xA1, 0x01,        /* Collection (Application) */
	    0x09, 0x01,        /*   Usage (Pointer) */
	    0xA1, 0x00,        /*   Collection (Physical) */
	    0x05, 0x09,        /*     Usage Page (Buttons) */
	    0x19, 0x01,        /*     Usage Min (1) */
	    0x29, 0x03,        /*     Usage Max (3) */
	    0x15, 0x00,        /*     Logical Min (0) */
	    0x25, 0x01,        /*     Logical Max (1) */
	    0x95, 0x03,        /*     Report Count (3) */
	    0x75, 0x01,        /*     Report Size (1) */
	    0x81, 0x02,        /*     Input (Data, Variable, Absolute) */
	    0x95, 0x01,        /*     Report Count (1) */
	    0x75, 0x05,        /*     Report Size (5) */
	    0x81, 0x01,        /*     Input (Constant) */
	    0x05, 0x01,        /*     Usage Page (Generic Desktop) */
	    0x09, 0x30,        /*     Usage (X) */
	    0x09, 0x31,        /*     Usage (Y) */
	    0x15, 0x81,        /*     Logical Min (-127) */
	    0x25, 0x7F,        /*     Logical Max (127) */
	    0x75, 0x08,        /*     Report Size (8) */
	    0x95, 0x02,        /*     Report Count (2) */
	    0x81, 0x06,        /*     Input (Data, Variable, Relative) */
	    0xC0,              /*   End Collection */
	    0xC0               /* End Collection */
	};

	uint8_t mapbuf[sizeof(boot_kb_report_map) +
	    sizeof(boot_mouse_report_map) + 4];
	uint16_t kb_in = 0, kb_out = 0, ms_in = 0;
	uint8_t kb_in_props = 0, kb_out_props = 0, ms_in_props = 0;
	size_t map_len = 0;
	bool combo;
	int i, ret;

	/*
	 * Scan discovered characteristics for Boot Protocol UUIDs.
	 *
	 * All three are collected, not the first one found.  HOGP §4.4.1.2 to
	 * §4.4.1.4 let a Boot Host discover each of them "for each HID Service
	 * on the GATT Server", and the Boot Host column of the profile's
	 * feature table marks Boot Keyboard Input Report and Boot Keyboard
	 * Output Report C.2/C.3, where C.3 reads "If one of these features is
	 * supported, both features shall be supported" -- so a host that takes
	 * the keyboard's input must also take its Output Report, which §4.13
	 * defines as "the status of LED's visible to the user".  Taking only
	 * the first match left a combo device's mouse dead (finding H13) and
	 * the keyboard's LEDs unreachable (finding H12).
	 */
	for (i = 0; i < dev->hid_disc.nchars; i++) {
		const struct gatt_char *ch = &dev->hid_disc.chars[i];

		switch (ch->uuid16) {
		case UUID_BOOT_KB_INPUT_REPORT:
			if (kb_in == 0) {
				kb_in = ch->value_handle;
				kb_in_props = ch->properties;
			}
			break;
		case UUID_BOOT_KB_OUTPUT_REPORT:
			if (kb_out == 0) {
				kb_out = ch->value_handle;
				kb_out_props = ch->properties;
			}
			break;
		case UUID_BOOT_MOUSE_INPUT_REPORT:
			if (ms_in == 0) {
				ms_in = ch->value_handle;
				ms_in_props = ch->properties;
			}
			break;
		default:
			break;
		}
	}

	if (kb_in == 0 && ms_in == 0)
		return (ENOENT);

	/*
	 * One virtual HID device carries both halves of a combo boot device,
	 * so the two descriptors are concatenated and each is given a Report
	 * ID.  A single-function device keeps an unnumbered descriptor, which
	 * is what a boot keyboard or boot mouse reports on the wire.
	 */
	combo = (kb_in != 0 && ms_in != 0);
	if (kb_in != 0) {
		map_len = hogp_boot_map_append(mapbuf, sizeof(mapbuf), map_len,
		    boot_kb_report_map, sizeof(boot_kb_report_map),
		    combo ? HOGP_BOOT_KB_REPORT_ID : 0);
		if (map_len == 0)
			return (ENOMEM);
	}
	if (ms_in != 0) {
		map_len = hogp_boot_map_append(mapbuf, sizeof(mapbuf), map_len,
		    boot_mouse_report_map, sizeof(boot_mouse_report_map),
		    combo ? HOGP_BOOT_MOUSE_REPORT_ID : 0);
		if (map_len == 0)
			return (ENOMEM);
	}

	/* Allocate and copy the report map descriptor */
	dev->report_map = malloc(map_len);
	if (dev->report_map == NULL)
		return (ENOMEM);
	memcpy(dev->report_map, mapbuf, map_len);
	dev->report_map_len = map_len;

	if (kb_in != 0)
		hogp_boot_add_report(dev, kb_in,
		    hogp_boot_find_cccd(&dev->hid_disc, kb_in),
		    combo ? HOGP_BOOT_KB_REPORT_ID : 0,
		    HID_REPORT_TYPE_INPUT, kb_in_props);
	/*
	 * The Boot Keyboard Output Report has no Client Characteristic
	 * Configuration descriptor (HIDS §2.5.1: none shall exist for Output
	 * Report data), so it is registered with cccd_handle 0 and is never
	 * subscribed -- only written.
	 */
	if (kb_in != 0 && kb_out != 0)
		hogp_boot_add_report(dev, kb_out, 0,
		    combo ? HOGP_BOOT_KB_REPORT_ID : 0,
		    HID_REPORT_TYPE_OUTPUT, kb_out_props);
	if (ms_in != 0)
		hogp_boot_add_report(dev, ms_in,
		    hogp_boot_find_cccd(&dev->hid_disc, ms_in),
		    combo ? HOGP_BOOT_MOUSE_REPORT_ID : 0,
		    HID_REPORT_TYPE_INPUT, ms_in_props);

	/*
	 * A boot-only device notifies its Boot Input Report only while in Boot
	 * Protocol Mode; HIDS Table 2.2 line 662: "A HID Service shall only
	 * enter Boot Protocol Mode after this value has been written."  The
	 * write goes to EVERY HID Service instance's Protocol Mode
	 * characteristic (HOGP §4.11 line 1187, "for each HID Service on the
	 * GATT Server"), which is why the handles are accumulated across the
	 * discovery loop rather than taken from dev->hid_disc — that is the
	 * primary instance only, and a second HID Service would stay in Report
	 * mode with its boot characteristics dead.
	 */
	ret = hogp_enter_boot_protocol_handles(&dev->att, pm_handles,
	    npm_handles);
	if (ret != 0)
		return (ret);
	LOG_HOGP(1, "set Boot Protocol mode on %d HID Service instance(s)",
	    npm_handles);

	dev->boot_protocol = true;
	return (0);
}

/*
 * Discover HID Service (0x1812), read Report Map, classify reports.
 * Handles multiple HID Service instances (e.g., combo keyboard+mouse).
 */
static int
hogp_discover(struct hogp_device *dev)
{
	struct gatt_service svcs[GATT_MAX_SERVICES];
	/*
	 * Protocol Mode value handles accumulated across EVERY HID Service
	 * instance.  The Boot Host write of HOGP §4.11 line 1187 is "for each
	 * HID Service on the GATT Server", and dev->hid_disc holds the primary
	 * instance only, so the boot fallback is handed this list instead.
	 */
	uint16_t pm_handles[HOGP_MAX_PROTOCOL_MODE_HANDLES];
	int npm_handles = 0;
	int nsvcs, ret, nsvc_found = 0;

	free(dev->report_map);
	dev->report_map = NULL;
	dev->report_map_len = 0;
	dev->nreports = 0;
	dev->num_report_maps = 0;
	memset(dev->report_map_handles, 0, sizeof(dev->report_map_handles));
	dev->hid_ctrl_handle = 0;
	dev->hid_bcdHID = 0;
	dev->idVendor = 0;
	dev->idProduct = 0;
	dev->svc_changed_handle = 0;
	/*
	 * Reset the primary HID-service discovery on every (re)discovery
	 * (finding 61).  dev survives reconnects, so a stale hid_disc with a
	 * non-zero service.start_handle would keep the OLD characteristic
	 * layout: the primary-instance assignment below only fires when HID is
	 * the first service or hid_disc.service.start_handle is still zero, and
	 * hogp_cache_save() would then persist stale Report Map / HID
	 * Information / Protocol Mode handles alongside a fresh DB hash.
	 */
	memset(&dev->hid_disc, 0, sizeof(dev->hid_disc));

	/* Discover all primary services */
	ret = gatt_discover_primary_services(&dev->att, svcs,
	    GATT_MAX_SERVICES, &nsvcs);
	if (ret != 0)
		return (ret);

	/*
	 * Record the Service Changed characteristic's value handle from the
	 * GATT Service (0x1801) so a later Service Changed indication can be
	 * matched by handle rather than by length alone (Core Spec Vol 3
	 * Part G §2.5.2 / §7.1).  Absent characteristic leaves the handle
	 * zero, which never matches.
	 */
	for (int s = 0; s < nsvcs; s++) {
		struct gatt_char gchars[GATT_MAX_CHARS];
		int ngc = 0;

		if (svcs[s].uuid16 != UUID_GATT_SERVICE)
			continue;
		if (gatt_discover_characteristics(&dev->att,
		    svcs[s].start_handle, svcs[s].end_handle,
		    gchars, GATT_MAX_CHARS, &ngc) == 0) {
			for (int c = 0; c < ngc; c++) {
				if (gchars[c].uuid16 ==
				    GATT_UUID_SERVICE_CHANGED) {
					dev->svc_changed_handle =
					    gchars[c].value_handle;
					LOG_HOGP(1, "Service Changed value "
					    "handle %04x",
					    dev->svc_changed_handle);
					break;
				}
			}
		}
		break;
	}

	/* Read Device Name from GAP Service (UUID 0x2A00) if present */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_GAP_SERVICE) {
			uint8_t val[32];
			size_t vlen = 0;

			/*
			 * att_read_by_type() strips only the opcode, so the
			 * value is preceded by a 3-byte Read By Type Response
			 * header: attr_data_len(1) + handle(2) (Core Spec Vol 3
			 * Part F §3.4.4.1).  Skip it before copying the name.
			 */
			if (att_read_by_type(&dev->att, svcs[s].start_handle,
			    svcs[s].end_handle, UUID_DEVICE_NAME, val,
			    sizeof(val),
			    &vlen) == 0 && vlen > 3) {
				size_t namelen = vlen - 3;
				int nlen = (int)(namelen > 31 ? 31 : namelen);
				memcpy(dev->device_name, val + 3, nlen);
				dev->device_name[nlen] = '\0';
				dev->has_device_name = true;
				LOG_HOGP(1, "device name: %s",
				    dev->device_name);
			}
			break;
		}
	}

	/* Read PnP ID from Device Information Service if present */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_DEVICE_INFO_SERVICE) {
			hogp_read_dis_pnpid(dev, &svcs[s]);
			break;
		}
	}

	/* Read Battery Level from Battery Service if present (HOGP §4.15). */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 == UUID_BATTERY_SERVICE) {
			hogp_read_battery(dev, &svcs[s]);
			break;
		}
	}

	/* Iterate all HID Service instances */
	for (int s = 0; s < nsvcs; s++) {
		if (svcs[s].uuid16 != UUID_HID_SERVICE)
			continue;

		nsvc_found++;

		LOG_HOGP(1, "HID Service found, handles %04x-%04x",
			    svcs[s].start_handle, svcs[s].end_handle);

		/*
		 * HOGP §4.5.3: relationship discovery over this HID Service.
		 * This is the only way to reach a Battery Service the HID
		 * Service INCLUDES rather than one published as primary, and
		 * it is a "shall" on a Report Host.  Non-fatal: a peer that
		 * rejects Read By Type on «Include» keeps whatever the
		 * primary-service scan above found.
		 */
		{
			struct gatt_service inc_bas;

			if (hogp_find_included_battery(&dev->att, &svcs[s],
			    &inc_bas) == 1 &&
			    inc_bas.start_handle != dev->bat_svc_start) {
				LOG_HOGP(1, "HID Service %04x-%04x includes "
				    "Battery Service %04x-%04x",
				    svcs[s].start_handle, svcs[s].end_handle,
				    inc_bas.start_handle, inc_bas.end_handle);
				hogp_read_battery(dev, &inc_bas);
			}
		}

		/* Discover characteristics and descriptors for this instance */
		struct gatt_discovery disc;
		memset(&disc, 0, sizeof(disc));
		disc.service = svcs[s];

		ret = gatt_discover_characteristics(&dev->att,
		    disc.service.start_handle, disc.service.end_handle,
		    disc.chars, GATT_MAX_CHARS, &disc.nchars);
		if (ret != 0)
			return (ret);

		disc.ndescs = 0;
		for (int i = 0; i < disc.nchars; i++) {
			uint16_t desc_start = disc.chars[i].value_handle + 1;
			uint16_t desc_end;
			if (i + 1 < disc.nchars)
				desc_end = disc.chars[i + 1].decl_handle - 1;
			else
				desc_end = disc.service.end_handle;
			if (desc_start > desc_end)
				continue;

			int ndesc;
			ret = gatt_discover_descriptors(&dev->att,
			    desc_start, desc_end,
			    disc.descs + disc.ndescs,
			    GATT_MAX_DESCS - disc.ndescs, &ndesc);
			if (ret != 0)
				return (ret);
			disc.ndescs += ndesc;
		}

		/* Use the first HID service as the primary instance. */
		if (svcs[s].start_handle == svcs[0].start_handle ||
		    dev->hid_disc.service.start_handle == 0)
			dev->hid_disc = disc;

		if (hogp_collect_protocol_mode_handles(disc.chars, disc.nchars,
		    pm_handles, (int)nitems(pm_handles), &npm_handles) ==
		    ENOSPC)
			warnx("more than %zu HID Service instances expose a "
			    "Protocol Mode characteristic; the rest cannot be "
			    "switched to Boot Protocol Mode",
			    nitems(pm_handles));

		ret = hogp_process_service(dev, &disc, nsvc_found - 1);
		if (ret != 0)
			return (ret);
	}

	if (nsvc_found == 0) {
		warnx("HID Service (0x1812) not found");
		return (ENOENT);
	}

	if (dev->report_map == NULL) {
		/*
		 * No Report Map characteristic: this device can only be driven
		 * as a Boot Host (HOGP §2.3 makes that role exclusive of the
		 * Report Host role, so the switch happens here and only here).
		 */
		if (hogp_setup_boot_protocol(dev, pm_handles,
		    npm_handles) != 0) {
			warnx("Report Map not found and no Boot Protocol support");
			return (ENOENT);
		}
		LOG_HOGP(1, "using Boot Protocol fallback");
	}

	LOG_HOGP(1, "total: %d reports, %zu bytes report map"
		    " from %d service(s)",
		    dev->nreports, dev->report_map_len, nsvc_found);

	return (0);
}

/*
 * Unwind a partially set-up vhid unit: close the device fd (so a reconnect
 * retry starts from scratch instead of skipping setup on a half-configured
 * fd) and VHID_DESTROY the created unit on the control node so failed
 * attempts do not each leak one of the VHID_MAX_DEVICES units.
 */
static void
hogp_vhid_create_undo(struct hogp_device *dev)
{

	if (dev->vhid_fd >= 0) {
		close(dev->vhid_fd);
		dev->vhid_fd = -1;
	}
	if (dev->vhid_ctl_fd >= 0 &&
	    ioctl(dev->vhid_ctl_fd, VHID_DESTROY, &dev->vhid_unit) < 0)
		warn("VHID_DESTROY vhid%d", dev->vhid_unit);
}

/*
 * Create a /dev/vhidN device and configure it with the Report Map.
 */
static int
hogp_setup_vhid(struct hogp_device *dev)
{
	struct vhid_attach_arg arg;
	char path[32];
	ssize_t n;

	/*
	 * Lazily acquire the vhid control node if it was not available at startup
	 * (the filesystem daemon may have come up since).  This keeps tzfsd from
	 * being a hard startup dependency: no device could be set up without it
	 * anyway, so failing here just fails this one device, softly.
	 */
	if (dev->vhid_ctl_fd < 0 && blued_g.svc_ctx != NULL) {
		/* Ensure the vhid module is loaded (best-effort), then open. */
		(void)service_ensure_extension(blued_g.svc_ctx, "vhid");
		if (service_open_isolated(blued_g.svc_ctx, "/dev/vhid",
		    SERVICE_OPEN_READ | SERVICE_OPEN_WRITE | SERVICE_OPEN_IOCTL,
		    0, &blued_g.vhid_ctl_fd) == -1)
			return (-1);
		{
			cap_rights_t rights;
			unsigned long vhid_ioctls[] = { VHID_CREATE,
			    VHID_DESTROY };

			cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
			(void)cap_rights_limit(blued_g.vhid_ctl_fd, &rights);
			(void)cap_ioctls_limit(blued_g.vhid_ctl_fd, vhid_ioctls,
			    nitems(vhid_ioctls));
		}
		dev->vhid_ctl_fd = blued_g.vhid_ctl_fd;
	}
	if (dev->vhid_ctl_fd < 0)
		return (-1);

	/* Create a new vhid instance */
	if (ioctl(dev->vhid_ctl_fd, VHID_CREATE, &dev->vhid_unit) < 0)
		return (-1);

	snprintf(path, sizeof(path), "/dev/vhid%d", dev->vhid_unit);
	/*
	 * Under switchboard, get the per-device node from the filesystem daemon
	 * (its policy grants blued the /dev/vhid* prefix with read/write/ioctl);
	 * a sandboxed blued cannot open it by path after cap_enter().  Standalone,
	 * open it directly.  Either way the rights are narrowed further below.
	 */
	if (blued_g.svc_ctx != NULL) {
		if (service_open_isolated(blued_g.svc_ctx, path,
		    SERVICE_OPEN_READ | SERVICE_OPEN_WRITE | SERVICE_OPEN_IOCTL,
		    0, &dev->vhid_fd) == -1) {
			hogp_vhid_create_undo(dev);
			return (-1);
		}
	} else {
		dev->vhid_fd = open(path, O_RDWR | O_CLOEXEC | O_CLOFORK);
		if (dev->vhid_fd < 0) {
			hogp_vhid_create_undo(dev);
			return (-1);
		}
	}

	/* Limit Capsicum rights on the vhid device fd */
	{
		cap_rights_t rights;
		unsigned long vhid_dev_ioctls[] = { VHID_ATTACH };

		cap_rights_init(&rights, CAP_READ, CAP_WRITE, CAP_EVENT,
		    CAP_IOCTL);
		if (cap_rights_limit(dev->vhid_fd, &rights) < 0 &&
		    errno != ENOSYS)
			warn("cap_rights_limit(vhid%d)", dev->vhid_unit);
		if (cap_ioctls_limit(dev->vhid_fd, vhid_dev_ioctls,
		    nitems(vhid_dev_ioctls)) < 0 && errno != ENOSYS)
			warn("cap_ioctls_limit(vhid%d)", dev->vhid_unit);
	}

	/* Write report descriptor, then attach */
	n = write(dev->vhid_fd, dev->report_map, dev->report_map_len);
	if (n < 0 || (size_t)n != dev->report_map_len) {
		hogp_vhid_create_undo(dev);
		return (-1);
	}

	memset(&arg, 0, sizeof(arg));
	arg.idVendor = dev->idVendor;
	arg.idProduct = dev->idProduct;
	arg.idVersion = dev->hid_bcdHID;	/* from HID Information */
	strlcpy(arg.name, "BLE HID Device", sizeof(arg.name));

	if (ioctl(dev->vhid_fd, VHID_ATTACH, &arg) < 0) {
		hogp_vhid_create_undo(dev);
		return (-1);
	}

	LOG_HOGP(1, "vhid%d configured", dev->vhid_unit);

	return (0);
}

/*
 * Subscribe to notifications on all Input Report characteristics.
 *
 * Returns 0 on success, a positive ATT error code the caller can act on
 * (pair, or invalidate the cache and rediscover), or -1.
 *
 * A device with no usable Input Report is a failure, not a success.  HOGP
 * §4.8 has the Report Host enable notifications on the Report characteristics
 * containing Input Reports, and HIDS Table 2.4 makes Notify mandatory for
 * one, so a HID device that offers none — because every Report Reference read
 * failed, or every Input Report lacks a CCCD — can never deliver a keystroke.
 * Returning success there attached a vhid keyboard that was silently mute.
 */
int
hogp_subscribe(struct hogp_device *dev)
{
	int ret, any_success = 0, usable, first_error = 0;

	usable = hogp_count_usable_input_reports(dev->reports, dev->nreports);
	if (usable == 0) {
		warnx("no usable Input Report (with a CCCD) was discovered; "
		    "the device cannot deliver reports");
		return (-1);
	}

	for (int i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_INPUT)
			continue;
		if (rpt->cccd_handle == 0)
			continue;

		/* Write 0x0001 to CCCD to enable notifications */
		uint8_t val[2] = { 0x01, 0x00 };
		ret = att_write_req(&dev->att, rpt->cccd_handle,
		    val, sizeof(val));
		if (ret != 0) {
			warnx("failed to enable notifications for "
			    "handle %04x", rpt->value_handle);
			if (first_error == 0 &&
			    hogp_att_error_is_actionable(ret))
				first_error = ret;
		} else {
			any_success = 1;
			LOG_HOGP(1, "notifications enabled "
				    "for report id=%d handle=%04x",
				    rpt->report_id, rpt->value_handle);
		}
	}

	if (!any_success) {
		warnx("all CCCD writes failed, no notifications will arrive");
		return (first_error != 0 ? first_error : -1);
	}
	return (0);
}

/*
 * Handle an Output report from the kernel vhid driver.
 *
 * When an application sets LED state (e.g., Caps Lock, Num Lock),
 * the kernel writes the Output report to the vhid device fd.
 * We read it here and forward it to the BLE device via ATT Write
 * Without Response (Write Command).  HIDS §2.5.1 lines 781-784 gives two
 * procedures for an Output Report — GATT Write Characteristic Value (a
 * Set_Report (Output) in USB HID terms) and GATT Write Without Response (Data
 * Output) — and Table 2.4 line 711 makes both properties mandatory on an
 * Output Report, so an unconditional Write Command reaches a conformant
 * device.  Choosing by the discovered properties is finding H17.
 *
 * The report from the kernel is in standard HID format:
 *   - If report IDs are in use: [report_id, data...]
 *   - If no report IDs: [data...]
 *
 * We match the report ID to find the correct Output Report
 * characteristic handle and strip the report ID byte before
 * sending over BLE (HOGP sends report data without the ID byte;
 * the ID is implicit in the characteristic handle).
 */
void
hogp_handle_vhid_output(struct hogp_device *dev)
{
	uint8_t buf[VHID_MAX_REPORT];
	ssize_t n;
	uint8_t report_id;
	uint8_t *report_data;
	size_t report_len;
	int i, ret;

	do {
		n = read(dev->vhid_fd, buf, sizeof(buf));
	} while (n < 0 && errno == EINTR);

	if (n <= 0) {
		if (n < 0 && errno != EAGAIN)
			warn("vhid read");
		return;
	}

	/*
	 * Determine report ID.  If any report in the device has a
	 * non-zero report ID, then the first byte is the report ID.
	 * Otherwise, there is no report ID byte (HOGP §4.8.1 lines 1147-1153:
	 * prepend on receive, strip on send).
	 *
	 * This is a whole-vhid-device property, which is why
	 * hogp_instance_conflicts() refuses to admit a HID Service instance
	 * that disagrees with the already-admitted ones about whether Report
	 * IDs are in use: mixing them would mis-frame one instance's reports.
	 */
	{
		bool has_report_ids = false;

		for (i = 0; i < dev->nreports; i++) {
			if (dev->reports[i].report_id != 0) {
				has_report_ids = true;
				break;
			}
		}

		if (has_report_ids && n >= 1) {
			report_id = buf[0];
			report_data = buf + 1;
			report_len = (size_t)(n - 1);
		} else {
			report_id = 0;
			report_data = buf;
			report_len = (size_t)n;
		}
	}

	/*
	 * Find the Output Report characteristic for this report ID.
	 *
	 * Resolving by (Report Type, Report ID) alone is only unambiguous
	 * because no two admitted HID Service instances share a pair; without
	 * that invariant the keyboard's LED write could be delivered to the
	 * mouse instance's Output Report characteristic (finding H1).
	 */
	for (i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_OUTPUT)
			continue;
		if (rpt->report_id != report_id)
			continue;

		/*
		 * HIDS §2.5.1 lines 783-784 map a Data Output to the GATT
		 * Write Without Response sub-procedure (ATT Write Command,
		 * opcode 0x52), and Table 2.4 line 711 makes that property
		 * mandatory on an Output Report -- but only on a conformant
		 * device.  Follow the discovered properties (finding H17): a
		 * device that offers Write and not Write Without Response
		 * still gets its LEDs, via the Write Characteristic Value
		 * sub-procedure that §2.5.1 line 781 maps to a Set_Report
		 * (Output).  BlueZ profiles/input/hog-lib.c forward_report()
		 * makes the same choice from properties, in the opposite
		 * preference order (Write first); the spec's Data Output
		 * mapping is followed here, so Write Without Response wins
		 * when the device offers both.
		 */
		if (rpt->properties != 0 &&
		    (rpt->properties & GATT_PROP_WRITE_NO_RSP) == 0 &&
		    (rpt->properties & GATT_PROP_WRITE) != 0)
			ret = att_write_req(&dev->att, rpt->value_handle,
			    report_data, report_len);
		else
			ret = att_write_cmd(&dev->att, rpt->value_handle,
			    report_data, report_len);
		if (ret < 0)
			warn("output report write failed "
			    "(handle=%04x id=%d)",
			    rpt->value_handle, report_id);
		else
			LOG_HOGP(2, "output report sent: id=%d handle=%04x "
			    "len=%zu", report_id, rpt->value_handle,
			    report_len);
		return;
	}

	LOG_HOGP(2, "no output report handle for id=%d, dropped", report_id);
}

/*
 * Find the ATT value handle for a Feature report with the given report ID.
 * Returns 0 if not found.
 *
 * Called from ctl.c for IPC_GATT_HID_FEATURE_HANDLE (finding H10): Feature
 * Reports were discovered, classified and stored, and the handle never left
 * the daemon, so they could neither be read nor written.  A client resolves
 * the handle here and then issues a Get_Report (Feature) as an
 * IPC_GATT_READ and a Set_Report (Feature) as an IPC_GATT_WRITE, which is the
 * mapping of HIDS v1.1 section 2.5.1.  IPC_GATT_WRITE_CMD must not be used:
 * HIDS Table 2.4 line 713 marks Write Without Response EXCLUDED for a Feature
 * Report.
 */
/*
 * Allocate and initialize a hogp_device for a new central connection.
 * Called from ctl.c CONNECT command.
 */
struct hogp_device *
blued_hogp_alloc(struct blued_adapter *adp, const uint8_t *addr,
    uint8_t addr_type, bool reconnect)
{
	struct hogp_device *hdev;

	hdev = calloc(1, sizeof(*hdev));
	if (hdev == NULL)
		return (NULL);

	hdev->att.fd = -1;
	hdev->att.bearer_fd = -1;
	hdev->smp.fd = -1;
	hdev->bond_fd = blued_g.bond_fd;
	hdev->bond_db = blued_g.bond_db;
	hdev->vhid_ctl_fd = blued_g.vhid_ctl_fd;
	hdev->vhid_fd = -1;
	hdev->hci_fd = adp->hci_fd;
	hdev->adapter = adp->name;
	hdev->le_features = adp->le_features;
	memcpy(hdev->local_addr, &adp->addr, 6);
	hdev->debug = (blued_verbose >= 1);
	memcpy(hdev->addr, addr, 6);
	hdev->addr_type = addr_type;
	hdev->reconnect = reconnect;
	return (hdev);
}

uint16_t
hogp_find_feature_handle(struct blued_conn *conn, uint8_t report_id)
{
	struct hogp_device *dev;

	if (conn == NULL || conn->hogp == NULL)
		return (0);
	dev = conn->hogp;
	return (hogp_find_report_handle(dev->reports, dev->nreports, report_id,
	    HID_REPORT_TYPE_FEATURE));
}

/*
 * Process a single ATT notification/indication from a kqueue-managed
 * connection.  Called when EVFILT_READ fires on the ATT fd.
 */
static void
hogp_deliver_notification(struct blued_conn *conn, uint16_t handle,
    const uint8_t *report_data, size_t report_len, uint16_t bearer_mtu)
{
	struct hogp_device *dev;
	int i;

	dev = conn->hogp;
	blued_ctl_notify_value(conn, handle, report_data, (uint16_t)report_len,
	    bearer_mtu);
	/*
	 * Inbound routing is by ATT value handle, which is unique across HID
	 * Service instances by construction, so a notification is always
	 * attributed to the instance that sent it.
	 */
	for (i = 0; i < dev->nreports; i++) {
		if (dev->reports[i].value_handle != handle)
			continue;
		BLUED_PROBE_HID_REPORT(dev->reports[i].report_id,
		    (int)report_len);
		if (dev->reports[i].report_id != 0) {
			uint8_t full[VHID_MAX_REPORT];

			full[0] = dev->reports[i].report_id;
			if (report_len + 1 > sizeof(full))
				break;
			memcpy(full + 1, report_data, report_len);
			if (write(dev->vhid_fd, full, report_len + 1) < 0 &&
			    errno != EAGAIN)
				warn("vhid write");
		} else if (write(dev->vhid_fd, report_data, report_len) < 0 &&
		    errno != EAGAIN)
			warn("vhid write");
		break;
	}
}

static int
hogp_process_pdu(struct blued_conn *conn, int fd, const uint8_t *buf,
    size_t len, uint16_t bearer_mtu)
{
	struct hogp_device *dev;

	dev = conn->hogp;
	if (dev == NULL)
		return (-1);

	if (len < 3)
		return (0);

	{
		uint8_t opcode = buf[0];

		if (opcode == ATT_OP_HANDLE_NOTIFY) {
			uint16_t handle = (uint16_t)buf[1] |
			    ((uint16_t)buf[2] << 8);

			hogp_deliver_notification(conn, handle, buf + 3, len - 3,
			    bearer_mtu);
		} else if (opcode == ATT_OP_MULTIPLE_HANDLE_VALUE_NTF) {
			size_t off = 1;

			/*
			 * C2-MHVN1: a malformed tuple ends the parse; it does
			 * not fail the bearer.
			 *
			 * Core Vol 3 Part F §3.4.7.4 (Table 3.41): "If an
			 * attribute handle or an attribute value is invalid,
			 * then the client shall ignore that attribute when
			 * receiving this notification."  Ignoring the
			 * attribute is the whole remedy -- there is no
			 * error response to a notification (§3.3.1) and
			 * nothing here entitles a client to drop the bearer.
			 * Returning -1 did drop it: the EATT read path in
			 * blued_event.c removes a bearer whose handler
			 * failed, so one truncated tuple from a peer took out
			 * an entire ATT bearer and every notification
			 * subscription riding on it.  Tuples parsed before
			 * the bad one have already been delivered, which is
			 * exactly "ignore that attribute".
			 */
			while (off < len) {
				uint16_t handle, vlen;

				if (len - off < 4) {
					LOG_HOGP(1, "multiple handle value "
					    "notification: truncated tuple "
					    "header at offset %zu, remainder "
					    "ignored", off);
					break;
				}
				handle = (uint16_t)buf[off] |
				    ((uint16_t)buf[off + 1] << 8);
				vlen = (uint16_t)buf[off + 2] |
				    ((uint16_t)buf[off + 3] << 8);
				off += 4;
				if (vlen > len - off) {
					LOG_HOGP(1, "multiple handle value "
					    "notification: tuple for handle "
					    "%04x claims %u octets but only "
					    "%zu remain, ignored", handle,
					    vlen, len - off);
					break;
				}
				/*
				 * §3.4.7.4: the Attribute Handle field is the
				 * handle of the attribute being notified, and
				 * 0x0000 is not a valid attribute handle
				 * (§3.2.2), so such a tuple is ignored too.
				 */
				if (handle != 0)
					hogp_deliver_notification(conn, handle,
					    buf + off, vlen, bearer_mtu);
				off += vlen;
			}
		} else if (opcode == ATT_OP_HANDLE_IND) {
			uint16_t handle = (uint16_t)buf[1] |
			    ((uint16_t)buf[2] << 8);
			const uint8_t *ind_data = buf + 3;
			size_t ind_len = len - 3;

			/* Notify subscribed ctl clients */
			blued_ctl_notify_value(conn, handle,
			    ind_data, (uint16_t)ind_len, bearer_mtu);
			att_confirm_bearer(&dev->att, fd);

			/*
			 * Check for Service Changed indication (UUID 0x2A05).
			 * Core Spec Vol 3 Part G Section 2.5.2: when a server
			 * indicates Service Changed, the client must invalidate
			 * any cached GATT handles for the affected range.
			 *
			 * Identify it by the characteristic's value handle
			 * (recorded at discovery), not by length alone —
			 * §2.5.2 identifies Service Changed by the
			 * characteristic, so a 4-byte indication on any other
			 * handle must NOT thrash the handle cache.
			 */
			if (gatt_indication_is_service_changed(
			    dev->svc_changed_handle, handle, ind_len)) {
				uint16_t sc_start = (uint16_t)ind_data[0] |
				    ((uint16_t)ind_data[1] << 8);
				uint16_t sc_end = (uint16_t)ind_data[2] |
				    ((uint16_t)ind_data[3] << 8);
				struct smp_bond *bond;
				char astr[18];

				bt_ntoa(&conn->dst, astr);
				/*
				 * C-SC1: the cross-connection cache belongs to
				 * the BOND, so only the bonded peer may discard
				 * it.
				 *
				 * §2.5.2 grants a cache that survives
				 * disconnection solely to "clients that have a
				 * trusted relationship (i.e. bond) with the
				 * server", and gives a client without one a
				 * cache "valid only during the connection".
				 * The trusted relationship is proven on the
				 * air by encrypting the link with the bond's
				 * LTK (Vol 3 Part H §2.4.4, Vol 3 Part C
				 * §10.2.4) -- a peer address alone is not
				 * proof, LE addresses being trivially
				 * spoofable and this link not yet resolved
				 * against the bond's IRK.
				 *
				 * On a plaintext link the sender is therefore
				 * an untrusted client, and an untrusted
				 * client's Service Changed reaches only the
				 * current connection: the indication is still
				 * confirmed above and still surfaced to ctl
				 * subscribers, but the bond's persisted handle
				 * cache and Database Hash stay put.  Without
				 * this an unencrypted spoofed four-octet
				 * indication forces a bonded HID device
				 * through full rediscovery on every reconnect.
				 */
				pthread_mutex_lock(&blued_g.bond_db_lock);
				bond = smp_find_bond(blued_g.bond_db,
				    (const uint8_t *)&conn->dst,
				    conn->addr_type);
				if (bond != NULL && !dev->att.encrypted) {
					LOG_HOGP(1, "Service Changed from %s: "
					    "range %04x-%04x on an unencrypted "
					    "link, bonded cache retained",
					    astr, sc_start, sc_end);
				} else if (bond != NULL) {
					bond->has_handle_cache = false;
					bond->has_db_hash = false;
					LOG_HOGP(1, "Service Changed from %s: "
					    "range %04x-%04x, cache invalidated",
					    astr, sc_start, sc_end);
				} else {
					LOG_HOGP(1, "Service Changed from %s: "
					    "range %04x-%04x (no bond)",
					    astr, sc_start, sc_end);
				}
				pthread_mutex_unlock(&blued_g.bond_db_lock);
			}
		}
	}
	return (0);
}

static void
hogp_unsolicited(struct att_conn *ac, int fd, const uint8_t *pdu,
    size_t len, void *arg)
{
	struct blued_conn *conn = arg;
	uint16_t mtu;
	int i;

	mtu = ac->mtu;
	for (i = 0; i < ac->eatt_count; i++)
		if (ac->eatt[i].fd == fd) {
			mtu = ac->eatt[i].mtu;
			break;
		}
	(void)hogp_process_pdu(conn, fd, pdu, len, mtu);
}

int
hogp_event_loop_bearer(struct blued_conn *conn, int fd, uint16_t mtu)
{
	uint8_t fixed[ATT_PDU_BUF_SIZE], *buf;
	size_t len;
	int rc;

	if (mtu < ATT_DEFAULT_MTU)
		return (-1);
	buf = mtu <= sizeof(fixed) ? fixed : malloc(mtu);
	if (buf == NULL)
		return (-1);
	/*
	 * This runs on the daemon's single kqueue thread, so the receive must
	 * not block: an ATT socket carries whatever SO_RCVTIMEO the last
	 * transaction left on it (up to 30 s on an EATT bearer, unbounded
	 * after a deadline-less request), and a readable event that turns out
	 * to carry no record -- a stale kevent for a closed and reused bearer
	 * fd -- would stall every other connection behind it.
	 */
	if (att_recv_bearer(conn->att, fd, buf, mtu, &len,
	    MSG_DONTWAIT) < 0) {
		int saved = errno;

		if (buf != fixed)
			free(buf);
		/* No record ready is not a bearer failure. */
		if (saved == EAGAIN || saved == EWOULDBLOCK)
			return (0);
		errno = saved;
		return (-1);
	}
	rc = hogp_process_pdu(conn, fd, buf, len, mtu);
	if (buf != fixed)
		free(buf);
	return (rc);
}

void
hogp_event_loop_once(struct blued_conn *conn)
{
	struct hogp_device *dev;

	dev = conn->hogp;
	if (dev != NULL)
		hogp_event_loop_bearer(conn, dev->att.fd, dev->att.mtu);
}
