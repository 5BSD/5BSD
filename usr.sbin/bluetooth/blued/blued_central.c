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
 * schedules an EVFILT_TIMER to retry.  Otherwise flags the conn
 * for cleanup by the main thread (via the self-pipe handler) to
 * avoid a data race on blued_g.conns.
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
		struct kevent kev;

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
		if (conn->reconnect_delay == 0)
			conn->reconnect_delay = 3;
		LOG_HOGP(1, "setup failed, reconnecting in %d seconds...",
		    conn->reconnect_delay);

		conn->reconnect_timer = blued_next_timer_id++;
		EV_SET(&kev, conn->reconnect_timer,
		    EVFILT_TIMER,
		    EV_ADD | EV_ONESHOT, NOTE_SECONDS,
		    conn->reconnect_delay, conn);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

		conn->reconnect_delay *= 2;
		if (conn->reconnect_delay > blued_reconnect_max_delay)
			conn->reconnect_delay = blued_reconnect_max_delay;
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
static int	hogp_subscribe(struct hogp_device *dev);
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
	 * Initial connection parameters: use the operator-requested values from
	 * CONNECT when present, else the daemon defaults (Core Spec Vol 4
	 * Part E §7.8.18).
	 */
	if (conn->has_req_conn_params)
		hci_le_connection_update(dev->hci_fd, dev->con_handle,
		    conn->req_itvl_min, conn->req_itvl_max,
		    conn->req_latency, conn->req_timeout);
	else
		hci_le_connection_update(dev->hci_fd, dev->con_handle,
		    6, 12, 4, 500);

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

		if (hogp_bond_snapshot(dev, &bond)) {
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
		}
	}

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

	/* Handle Database Out Of Sync -- full rediscovery */
	if (ret == ATT_ERR_DATABASE_OUT_OF_SYNC) {
		struct smp_bond bond;

		LOG_HOGP(1, "ATT Database Out Of Sync, full rediscovery");
		if (hogp_bond_snapshot(dev, &bond)) {
			bond.has_handle_cache = false;
			bond.has_db_hash = false;
			(void)hogp_bond_commit_metadata(dev, &bond);
		}
		ret = hogp_discover(dev);
	}

	/* Handle auth errors -- pair and retry */
	{
		if (ret == ATT_ERR_INSUFF_AUTHEN ||
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
	if (hogp_subscribe(dev) != 0) {
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
		    dev->addr, dev->addr_type, 2);
		pthread_mutex_unlock(&blued_g.att_sec_lock);
		if (eatt_opened > 0)
			LOG_ATT(1, "opened %d EATT bearer(s)", eatt_opened);
	}

	/*
	 * Connection Subrating (BT 5.3) is not used — this stack
	 * targets BT 5.2 max.  The HCI wrappers exist as API stubs
	 * but are intentionally not called.
	 */

	/*
	 * Expose the connection to the event loop.  Past this point conn
	 * (and dev) may be freed at any moment by the main thread, so we
	 * do nothing but signal success on the (global) setup pipe and
	 * return -- no further conn/dev access.
	 */
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	if (blued_conn_register(conn) < 0) {
		warnx("blued_conn_register failed");
		blued_central_setup_fail(conn);
		return (NULL);
	}

	/*
	 * Register the vhid Output-report fd (LED state etc.) only now, as the
	 * final handoff step (finding 89).  Registering it earlier exposed
	 * conn to the main loop's vhid handler (hogp_handle_vhid_output ->
	 * att_write_cmd) while this setup thread was still operating on the
	 * same att_conn (att_open_eatt above), racing two writers on one ATT
	 * bearer.  By this point the setup thread performs no further dev/att
	 * access, so there is no concurrent user of conn->hogp->att.  On the
	 * failure paths the fd is deregistered/closed by blued_conn_central_
	 * teardown, so it can never be leaked while registered.
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
 * Process a single HID Service instance: read its Report Map,
 * classify Report characteristics, read HID Information,
 * save HID Control Point handle, set Protocol Mode.
 */
static int
hogp_process_service(struct hogp_device *dev, struct gatt_discovery *disc)
{
	int ret;
	size_t len;

	/*
	 * Read Report Map characteristic (UUID 0x2A4B).
	 * This contains the HID Report Descriptor.
	 * Report Map can be longer than MTU-1, use read blob.
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_REPORT_MAP)
			continue;

		/* Heap-allocate read buffer: Report Maps can be up to
		 * 4KB; too large for the stack in a setup thread. */
		uint8_t *rmbuf;
		size_t total = 0;
		size_t rmbuf_sz = 4096;
		uint16_t handle = disc->chars[i].value_handle;

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

		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < rmbuf_sz) {
			ret = att_read_blob(&dev->att, handle, total,
			    rmbuf + total, rmbuf_sz - total, &len);
			if (ret != 0)
				break;
			total += len;
		}
		/*
		 * The buffer filled while a full MTU-sized blob was still coming:
		 * the Report Map is longer than rmbuf_sz and has been truncated.
		 * A truncated HID descriptor yields a malformed vhid, so surface
		 * it rather than attaching it silently (finding 68).
		 */
		if (total >= rmbuf_sz && len == (size_t)(dev->att.mtu - 1))
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

		LOG_HOGP(1, "Report Map: %zu bytes", total);
		break;
	}

	/*
	 * Classify Report characteristics (UUID 0x2A4D).
	 * Each Report has a Report Reference descriptor (UUID 0x2908)
	 * that tells us the report ID and type (input/output/feature).
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_REPORT)
			continue;
		if (dev->nreports >= HOGP_MAX_REPORTS)
			break;

		struct hogp_report *rpt = &dev->reports[dev->nreports];
		rpt->value_handle = disc->chars[i].value_handle;
		rpt->cccd_handle = 0;
		rpt->report_id = 0;
		rpt->report_type = 0;

		uint16_t desc_start = rpt->value_handle + 1;
		uint16_t desc_end;
		if (i + 1 < disc->nchars)
			desc_end = disc->chars[i + 1].decl_handle - 1;
		else
			desc_end = disc->service.end_handle;

		for (int j = 0; j < disc->ndescs; j++) {
			uint16_t dh = disc->descs[j].handle;
			if (dh < desc_start || dh > desc_end)
				continue;

			if (disc->descs[j].uuid16 ==
			    GATT_UUID_REPORT_REFERENCE) {
				uint8_t ref[2];
				ret = att_read(&dev->att, dh, ref,
				    sizeof(ref), &len);
				if (ret == 0 && len >= 2) {
					rpt->report_id = ref[0];
					rpt->report_type = ref[1];
				}
			} else if (disc->descs[j].uuid16 ==
			    GATT_UUID_CCCD) {
				rpt->cccd_handle = dh;
			}
		}

		dev->nreports++;

		LOG_HOGP(1, "Report handle=%04x id=%d type=%d "
			    "cccd=%04x",
			    rpt->value_handle, rpt->report_id,
			    rpt->report_type, rpt->cccd_handle);
	}

	/*
	 * Read HID Information (UUID 0x2A4A) -- mandatory per HOGP 3.2.
	 * Format: [bcdHID (2 LE), bCountryCode (1), Flags (1)]
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 != UUID_HID_INFORMATION)
			continue;

		uint8_t info[4];
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
	 * Used for Suspend/Exit Suspend per HOGP.
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 == UUID_HID_CONTROL_POINT) {
			dev->hid_ctrl_handle = disc->chars[i].value_handle;
			break;
		}
	}

	/*
	 * Set Protocol Mode to Report Protocol (0x01) on EVERY Protocol Mode
	 * instance in this HID service (HOGP v1.1 §4.11).  C2-M10: the old
	 * `break` after the first instance left a composite/dual-HID service
	 * with additional Protocol Mode characteristics in an undefined mode.
	 * The bond cache still records only a single protocol_mode_handle (last
	 * wins) — that persistence limitation is unchanged — but at connect time
	 * every discovered instance is now switched to Report mode.
	 */
	for (int i = 0; i < disc->nchars; i++) {
		if (disc->chars[i].uuid16 == UUID_PROTOCOL_MODE) {
			uint8_t mode = HID_PROTOCOL_REPORT;
			att_write_cmd(&dev->att,
			    disc->chars[i].value_handle,
			    &mode, 1);
			LOG_HOGP(1, "set Report Protocol mode (handle=%04x)",
			    disc->chars[i].value_handle);
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
 * Per HOGP v1.0 Section 2: the HID Host shall discover the Battery Service.
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
			if (bond->num_report_maps <
			    (int)nitems(bond->report_map_handles))
				bond->report_map_handles[
				    bond->num_report_maps++] =
				    dev->hid_disc.chars[i].value_handle;
		} else if (dev->hid_disc.chars[i].uuid16 == UUID_HID_INFORMATION)
			bond->hid_info_handle =
			    dev->hid_disc.chars[i].value_handle;
		else if (dev->hid_disc.chars[i].uuid16 == UUID_PROTOCOL_MODE)
			bond->protocol_mode_handle =
			    dev->hid_disc.chars[i].value_handle;
	}

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

	/* Battery handles default to 0 (not cached individually) */
	bond->battery_level_handle = 0;
	bond->battery_cccd_handle = 0;
	bond->bat_svc_start = 0;
	bond->bat_svc_end = 0;

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
	 * (that would need a bond-cache field, SMP-side), so a cache-hit
	 * reconnect leaves it zero and Service Changed indications simply do
	 * not invalidate — safe (never over-invalidates), just not optimal.
	 */
	dev->svc_changed_handle = 0;

	/* Restore report handles from cache */
	for (i = 0; i < bond->num_reports && i < HOGP_MAX_REPORTS; i++) {
		dev->reports[i].value_handle = bond->report_handles[i];
		dev->reports[i].cccd_handle = bond->report_cccd_handles[i];
		dev->reports[i].report_type = bond->report_types[i];
		dev->reports[i].report_id = bond->report_ids[i];
		dev->nreports++;

		LOG_HOGP(1, "cache: Report handle=%04x id=%d type=%d "
		    "cccd=%04x", bond->report_handles[i],
		    bond->report_ids[i], bond->report_types[i],
		    bond->report_cccd_handles[i]);
	}

	/*
	 * Read Report Map from cached handle -- the value is needed
	 * for vhid setup even though the handle is cached.
	 */
	if (bond->report_map_handle != 0) {
		uint8_t *rmbuf;
		size_t total = 0;
		size_t rmbuf_sz = 4096;

		rmbuf = malloc(rmbuf_sz);
		if (rmbuf == NULL)
			return (ENOMEM);

		ret = att_read(&dev->att, bond->report_map_handle,
		    rmbuf, rmbuf_sz, &len);
		if (ret != 0) {
			warnx("cache: failed to read Report Map");
			free(rmbuf);
			return (ret);
		}
		total = len;

		while (len == (size_t)(dev->att.mtu - 1) &&
		    total < rmbuf_sz) {
			ret = att_read_blob(&dev->att,
			    bond->report_map_handle, total,
			    rmbuf + total, rmbuf_sz - total, &len);
			if (ret != 0)
				break;
			total += len;
		}
		if (total >= rmbuf_sz && len == (size_t)(dev->att.mtu - 1))
			warnx("cache: Report Map exceeds %zu bytes; truncated",
			    rmbuf_sz);

		dev->report_map = malloc(total);
		if (dev->report_map == NULL) {
			free(rmbuf);
			return (ENOMEM);
		}
		memcpy(dev->report_map, rmbuf, total);
		dev->report_map_len = total;
		free(rmbuf);

		LOG_HOGP(1, "cache: Report Map: %zu bytes", total);
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
	 * Set Protocol Mode to Report Protocol from cached handle.
	 */
	if (bond->protocol_mode_handle != 0) {
		uint8_t mode = HID_PROTOCOL_REPORT;
		att_write_cmd(&dev->att, bond->protocol_mode_handle,
		    &mode, 1);
		LOG_HOGP(1, "cache: set Report Protocol mode");
	}

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
 * Boot Protocol fallback: construct a minimal HID Report Map for devices
 * that expose Boot Keyboard (0x2A22) or Boot Mouse (0x2A33) characteristics
 * but lack a Report Map characteristic.
 *
 * HOGP v1.0 Section 3.1 requires the HID Host to support Boot Protocol
 * for keyboard and mouse devices.
 *
 * Returns 0 on success (report_map set, boot report added),
 *         ENOENT if no boot characteristics found.
 */
static int
hogp_setup_boot_protocol(struct hogp_device *dev)
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

	const uint8_t *map = NULL;
	size_t map_len = 0;
	uint16_t boot_value_handle = 0;
	uint16_t boot_cccd_handle = 0;
	int i, j, ret;

	/*
	 * Scan discovered characteristics for Boot Protocol UUIDs.
	 * Prefer keyboard over mouse if both are present.
	 */
	for (i = 0; i < dev->hid_disc.nchars; i++) {
		if (dev->hid_disc.chars[i].uuid16 == UUID_BOOT_KB_INPUT_REPORT) {
			map = boot_kb_report_map;
			map_len = sizeof(boot_kb_report_map);
			boot_value_handle = dev->hid_disc.chars[i].value_handle;
			break;
		}
		if (dev->hid_disc.chars[i].uuid16 == UUID_BOOT_MOUSE_INPUT_REPORT &&
		    map == NULL) {
			map = boot_mouse_report_map;
			map_len = sizeof(boot_mouse_report_map);
			boot_value_handle = dev->hid_disc.chars[i].value_handle;
			/* Keep scanning in case a keyboard is also present */
		}
	}

	if (map == NULL)
		return (ENOENT);

	/* Look up the CCCD handle for the boot characteristic */
	for (j = 0; j < dev->hid_disc.ndescs; j++) {
		uint16_t dh = dev->hid_disc.descs[j].handle;

		if (dh > boot_value_handle &&
		    dev->hid_disc.descs[j].uuid16 == GATT_UUID_CCCD) {
			/*
			 * Verify this CCCD belongs to the boot characteristic
			 * and not a subsequent one, by checking it falls before
			 * the next characteristic declaration.
			 */
			bool belongs = true;
			for (int k = 0; k < dev->hid_disc.nchars; k++) {
				if (dev->hid_disc.chars[k].decl_handle > boot_value_handle &&
				    dev->hid_disc.chars[k].decl_handle <= dh) {
					belongs = false;
					break;
				}
			}
			if (belongs) {
				boot_cccd_handle = dh;
				break;
			}
		}
	}

	/* Allocate and copy the report map descriptor */
	dev->report_map = malloc(map_len);
	if (dev->report_map == NULL)
		return (ENOMEM);
	memcpy(dev->report_map, map, map_len);
	dev->report_map_len = map_len;

	/* Add boot report: report_id=0, type=Input */
	if (dev->nreports < HOGP_MAX_REPORTS) {
		struct hogp_report *rpt = &dev->reports[dev->nreports];
		rpt->value_handle = boot_value_handle;
		rpt->cccd_handle = boot_cccd_handle;
		rpt->report_id = 0;
		rpt->report_type = HID_REPORT_TYPE_INPUT;
		dev->nreports++;

		LOG_HOGP(1, "boot report handle=%04x cccd=%04x",
		    boot_value_handle, boot_cccd_handle);
	}

	/*
	 * A boot-only device notifies its Boot Input Report only while in
	 * Boot Protocol Mode.  The Protocol Mode characteristic defaults to
	 * Report Protocol (0x01) at connection, so write Boot Protocol
	 * (0x00) to its value handle before subscribing — otherwise the
	 * device stays in Report mode and delivers no input (HOGP spec,
	 * Protocol Mode / Boot Host requirements).
	 */
	ret = hogp_enter_boot_protocol(&dev->att, dev->hid_disc.chars,
	    dev->hid_disc.nchars);
	if (ret != 0)
		return (ret);
	LOG_HOGP(1, "set Boot Protocol mode");

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
	int nsvcs, ret, nsvc_found = 0;

	free(dev->report_map);
	dev->report_map = NULL;
	dev->report_map_len = 0;
	dev->nreports = 0;
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

	/* Read Battery Level from Battery Service if present
	 * (mandatory per HOGP v1.0 Section 2) */
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

		ret = hogp_process_service(dev, &disc);
		if (ret != 0)
			return (ret);
	}

	if (nsvc_found == 0) {
		warnx("HID Service (0x1812) not found");
		return (ENOENT);
	}

	if (dev->report_map == NULL) {
		/*
		 * No Report Map characteristic — try Boot Protocol fallback.
		 * HOGP v1.0 Section 3.1 requires the HID Host to support
		 * Boot Protocol for keyboard and mouse devices.
		 */
		if (hogp_setup_boot_protocol(dev) != 0) {
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
 * Create a /dev/vhidN device and configure it with the Report Map.
 */
static int
hogp_setup_vhid(struct hogp_device *dev)
{
	struct vhid_attach_arg arg;
	char path[32];
	ssize_t n;

	/* Create a new vhid instance */
	if (ioctl(dev->vhid_ctl_fd, VHID_CREATE, &dev->vhid_unit) < 0)
		return (-1);

	snprintf(path, sizeof(path), "/dev/vhid%d", dev->vhid_unit);
	/*
	 * Under serviced, get the per-device node from the filesystem daemon
	 * (its policy grants blued the /dev/vhid* prefix with read/write/ioctl);
	 * a sandboxed blued cannot open it by path after cap_enter().  Standalone,
	 * open it directly.  Either way the rights are narrowed further below.
	 */
	if (blued_g.svc_ctx != NULL) {
		if (service_open_isolated(blued_g.svc_ctx, path,
		    SERVICE_OPEN_READ | SERVICE_OPEN_WRITE | SERVICE_OPEN_IOCTL,
		    0, &dev->vhid_fd) == -1)
			return (-1);
	} else {
		dev->vhid_fd = open(path, O_RDWR | O_CLOEXEC | O_CLOFORK);
		if (dev->vhid_fd < 0)
			return (-1);
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
	if (n < 0 || (size_t)n != dev->report_map_len)
		return (-1);

	memset(&arg, 0, sizeof(arg));
	arg.idVendor = dev->idVendor;
	arg.idProduct = dev->idProduct;
	arg.idVersion = dev->hid_bcdHID;	/* from HID Information */
	strlcpy(arg.name, "BLE HID Device", sizeof(arg.name));

	if (ioctl(dev->vhid_fd, VHID_ATTACH, &arg) < 0)
		return (-1);

	LOG_HOGP(1, "vhid%d configured", dev->vhid_unit);

	return (0);
}

/*
 * Subscribe to notifications on all Input Report characteristics.
 */
static int
hogp_subscribe(struct hogp_device *dev)
{
	int ret, any_success = 0, any_input = 0;

	for (int i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_INPUT)
			continue;
		if (rpt->cccd_handle == 0)
			continue;

		any_input = 1;

		/* Write 0x0001 to CCCD to enable notifications */
		uint8_t val[2] = { 0x01, 0x00 };
		ret = att_write_req(&dev->att, rpt->cccd_handle,
		    val, sizeof(val));
		if (ret != 0)
			warnx("failed to enable notifications for "
			    "handle %04x", rpt->value_handle);
		else {
			any_success = 1;
			LOG_HOGP(1, "notifications enabled "
				    "for report id=%d handle=%04x",
				    rpt->report_id, rpt->value_handle);
		}
	}

	if (any_input && !any_success) {
		warnx("all CCCD writes failed, no notifications will arrive");
		return (-1);
	}
	return (0);
}

/*
 * Handle an Output report from the kernel vhid driver.
 *
 * When an application sets LED state (e.g., Caps Lock, Num Lock),
 * the kernel writes the Output report to the vhid device fd.
 * We read it here and forward it to the BLE device via ATT Write
 * Without Response (Write Command), as required by HOGP v1.0
 * Section 3.3.3.
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
	int i;

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
	 * Otherwise, there is no report ID byte.
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

	/* Find the Output Report characteristic for this report ID */
	for (i = 0; i < dev->nreports; i++) {
		struct hogp_report *rpt = &dev->reports[i];

		if (rpt->report_type != HID_REPORT_TYPE_OUTPUT)
			continue;
		if (rpt->report_id != report_id)
			continue;

		/*
		 * HOGP v1.0 Section 3.3.3: Output Reports use Write
		 * Without Response (ATT Write Command, opcode 0x52).
		 */
		if (att_write_cmd(&dev->att, rpt->value_handle,
		    report_data, report_len) < 0)
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
 * Returns 0 if not found.  Used by ctl.c for HOGP_READ/HOGP_WRITE commands.
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

			while (off < len) {
				uint16_t handle, vlen;

				if (len - off < 4)
					return (-1);
				handle = (uint16_t)buf[off] |
				    ((uint16_t)buf[off + 1] << 8);
				vlen = (uint16_t)buf[off + 2] |
				    ((uint16_t)buf[off + 3] << 8);
				off += 4;
				if (vlen > len - off)
					return (-1);
				hogp_deliver_notification(conn, handle, buf + off,
				    vlen, bearer_mtu);
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
				pthread_mutex_lock(&blued_g.bond_db_lock);
				bond = smp_find_bond(blued_g.bond_db,
				    (const uint8_t *)&conn->dst,
				    conn->addr_type);
				if (bond != NULL) {
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
	if (att_recv_bearer(conn->att, fd, buf, mtu, &len) < 0) {
		if (buf != fixed)
			free(buf);
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
