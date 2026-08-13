/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

/*
 * blued peripheral (server) role: advertising setup, accept loop,
 * serving ATT requests, re-enabling advertising on disconnect,
 * GATT database construction.
 */

#include "blued_internal.h"

/*
 * Re-enable advertising after a peripheral connection ends or
 * fails setup.
 *
 * IMPORTANT: this function must only be called from the main event
 * loop thread.  Setup threads that need re-advertising set
 * conn->needs_readvertise and signal via the self-pipe; the main
 * thread's pipe handler calls this function.  Retry state and timer ownership
 * are adapter-local: one failing controller must not consume or reset another
 * controller's retry budget.
 */
static void
blued_periph_readvertise_one(struct blued_adapter *adp)
{
	struct kevent kev;
	uintptr_t timer_id;
	int adv_err;

	if (!blued_g.periph_active || adp->periph_listen_fd < 0 ||
	    !adp->active || !adp->powered || !adp->adv_configured)
		return;
	if (adp->power_quiescing)
		return;

	if (adp->adv_use_extended)
		adv_err = hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0x00);
	else
		adv_err = hci_le_set_advertise_enable(adp->hci_fd, true);
	if (adv_err >= 0) {
		adp->adv_enabled = true;
		blued_periph_readvertise_cancel(adp);
		LOG_HOGP(1, "%s: re-advertising", adp->name);
		return;
	}

	warn("%s: re-advertise failed", adp->name);
	if (adp->readvertise_timer != 0)
		return;
	if (adp->readvertise_retries >= BLUED_READVERTISE_MAX_RETRIES) {
		LOG_HOGP(0, "%s: re-advertise failed after %d retries, "
		    "peripheral not discoverable", adp->name,
		    BLUED_READVERTISE_MAX_RETRIES);
		return;
	}

	timer_id = blued_next_timer_id++;
	if (timer_id == 0)
		timer_id = blued_next_timer_id++;
	EV_SET(&kev, timer_id, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
	    NOTE_SECONDS, 1, BLUED_KQ_READVERTISE);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		warn("%s: cannot arm re-advertise retry", adp->name);
		return;
	}
	adp->readvertise_timer = timer_id;
	adp->readvertise_retries++;
	LOG_HOGP(1, "%s: re-advertise retry %u/%d in 1 second",
	    adp->name, adp->readvertise_retries,
	    BLUED_READVERTISE_MAX_RETRIES);
}

void
blued_periph_readvertise_cancel(struct blued_adapter *adp)
{
	struct kevent kev;

	if (adp == NULL)
		return;
	if (adp->readvertise_timer != 0 && blued_g.kq >= 0) {
		EV_SET(&kev, adp->readvertise_timer, EVFILT_TIMER, EV_DELETE,
		    0, 0, BLUED_KQ_READVERTISE);
		(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);
	}
	adp->readvertise_timer = 0;
	adp->readvertise_retries = 0;
}

bool
blued_periph_readvertise_timer_fired(uintptr_t timer_id)
{
	struct blued_adapter *adp;

	LIST_FOREACH(adp, &blued_g.adapters, entries) {
		if (adp->readvertise_timer != timer_id)
			continue;
		/* The one-shot has fired; a failed attempt may arm its successor. */
		adp->readvertise_timer = 0;
		blued_periph_readvertise_one(adp);
		return (true);
	}
	return (false);
}

void
blued_periph_readvertise(void)
{
	struct blued_adapter *adp;

	LIST_FOREACH(adp, &blued_g.adapters, entries)
		blued_periph_readvertise_one(adp);
}

/*
 * Accept an incoming peripheral ATT connection from the listen socket.
 * Called when EVFILT_READ fires on an adapter's ATT listener.
 *
 * Allocates the connection and att_conn, disables advertising, then
 * spawns blued_conn_setup_peripheral() to handle SMP and kqueue
 * registration.
 */
void
blued_periph_accept(struct blued_adapter *adp)
{
	struct sockaddr_l2cap peer_sa;
	socklen_t peer_len;
	struct blued_conn *conn;
	struct att_conn *ac;
	int client_fd;
	pthread_t tid;
	pthread_attr_t attr;

	LOG_HOGP(2, "peripheral listen socket readable, accepting");

	/*
	 * Rate-limit accept() to mitigate rapid connect/disconnect DoS.
	 * Token bucket: 2 tokens/sec, max burst of 4.
	 */
	{
		static time_t last_accept;
		static int tokens;
		struct timespec mono_now;
		time_t now;

		clock_gettime(CLOCK_MONOTONIC, &mono_now);
		now = mono_now.tv_sec;

		if (now != last_accept) {
			/* Refill: 2 tokens per second, max 4 */
			int elapsed = (int)(now - last_accept);
			if (elapsed > 4)
				elapsed = 4;
			tokens += elapsed * 2;
			if (tokens > 4)
				tokens = 4;
			last_accept = now;
		}
		if (tokens <= 0) {
			LOG_HOGP(1, "accept rate limit, rejecting");
			client_fd = accept4(adp->periph_listen_fd, NULL,
			    NULL, SOCK_CLOEXEC | SOCK_CLOFORK);
			if (client_fd >= 0)
				close(client_fd);
			return;
		}
		tokens--;
	}

	/* Enforce maximum simultaneous connections */
	{
		struct blued_conn *cc;
		int nactive = 0;

		pthread_rwlock_rdlock(&blued_g.conns_lock);
		LIST_FOREACH(cc, &blued_g.conns, entries)
			nactive++;
		pthread_rwlock_unlock(&blued_g.conns_lock);
		if (nactive >= BLUED_MAX_CONNS) {
			LOG_HOGP(1, "max connections (%d) reached, rejecting",
			    BLUED_MAX_CONNS);
			/* Drain the pending accept to avoid busy-loop */
			client_fd = accept4(adp->periph_listen_fd, NULL,
			    NULL, SOCK_CLOEXEC | SOCK_CLOFORK);
			if (client_fd >= 0)
				close(client_fd);
			return;
		}
	}

	peer_len = sizeof(peer_sa);
	client_fd = accept4(adp->periph_listen_fd,
	    (struct sockaddr *)&peer_sa, &peer_len,
	    SOCK_CLOEXEC | SOCK_CLOFORK);
	if (client_fd < 0) {
		if (errno != EINTR)
			warn("peripheral accept");
		return;
	}

	/* Guard against duplicate connections from the same device */
	{
		struct blued_conn *existing;

		existing = blued_conn_by_peer(adp,
		    (const bdaddr_t *)peer_sa.l2cap_bdaddr.b,
		    peer_sa.l2cap_bdaddr_type);
		if (existing != NULL) {
			char addr_str[18];
			bt_ntoa((bdaddr_t *)peer_sa.l2cap_bdaddr.b, addr_str);
			LOG_HOGP(1, "duplicate connection from %s, "
			    "closing stale", addr_str);
			blued_conn_disconnect(existing);
		}
	}

	conn = blued_conn_alloc();
	if (conn == NULL) {
		close(client_fd);
		return;
	}
	conn->role = BLUED_ROLE_PERIPHERAL;
	memcpy(&conn->dst, peer_sa.l2cap_bdaddr.b, sizeof(conn->dst));
	conn->addr_type = peer_sa.l2cap_bdaddr_type;
	conn->adapter = adp;
	blued_conn_apply_cached_local(conn);
	blued_conn_local_from_socket(conn, client_fd);

	/* Heap-allocate att_conn for peripheral */
	ac = calloc(1, sizeof(struct att_conn));
	if (ac == NULL) {
		close(client_fd);
		blued_conn_free(conn);
		return;
	}
	ac->fd = client_fd;
	ac->mtu = ATT_DEFAULT_MTU;
	ac->min_key_size = blued_cfg.min_key_size;
	ac->ind_timer = 0;
	ac->buf = malloc(ATT_MAX_MTU);
	if (ac->buf == NULL) {
		close(client_fd);
		free(ac);
		blued_conn_free(conn);
		return;
	}

	conn->att_owned = ac;
	conn->att = ac;
	conn->att_fd = client_fd;
	conn->gatt_db = &periph_gatt_db;
	blued_conn_set_state(conn, BLUED_CONN_CONNECTING);

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_HOGP(1, "peripheral client accepted: %s", addr_str);
	}

	/* Spawn setup thread for SMP + kqueue registration */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	blued_conn_ref(conn);
	blued_setup_worker_start(conn);
	if (pthread_create(&tid, &attr, blued_conn_setup_peripheral,
	    conn) != 0) {
		blued_setup_worker_finish(conn);
		blued_conn_unref(conn);
		warn("peripheral setup thread");
		blued_conn_free(conn);
		blued_periph_readvertise(); /* main thread context, safe */
		pthread_attr_destroy(&attr);
		return;
	}
	pthread_attr_destroy(&attr);

	/* A connectable advertising set is disabled when it creates a link. */
	blued_periph_readvertise();
}

/*
 * Peripheral setup thread failure cleanup.
 *
 * Flags the conn for cleanup and re-advertising, both deferred to
 * the main thread's self-pipe handler to avoid data races on
 * blued_g.conns and HCI advertising commands.
 */
void
blued_periph_setup_fail(struct blued_conn *conn)
{

	blued_conn_set_state(conn, BLUED_CONN_IDLE);
	atomic_store_explicit(&conn->needs_readvertise, true,
	    memory_order_release);
	atomic_store_explicit(&conn->needs_cleanup, true,
	    memory_order_release);
	(void)write(blued_g.setup_pipe[1], "x", 1);
}

/*
 * Send a Service Changed indication to a connected client.
 * Core Spec Vol 3 Part G 2.5.2, 7.1: when the GATT database changes,
 * the server shall indicate the Service Changed characteristic to all
 * bonded clients that have enabled indications via the CCCD.
 *
 * The indication carries the affected handle range [start, end].
 *
 * Returns 0 when the client has been (or need not be) notified — the
 * indication was sent, or there is no Service Changed characteristic, or the
 * client has not subscribed (robust caching / change_aware covers those).
 * Returns -1 only when the indication was due but att_send_indication() failed,
 * so the caller must NOT advance the stored db_hash (finding 120).
 */
static int
gatt_send_service_changed(struct blued_conn *pconn, struct att_conn *ac,
    struct att_db *db, uint16_t start, uint16_t end)
{
	int i;
	uint16_t sc_handle = 0;
	uint16_t cccd_handle = 0;

	/* Find the Service Changed characteristic value handle */
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == 0x2A05 &&
		    db->attrs[i].is_char_value) {
			sc_handle = db->attrs[i].handle;
			/* The CCCD immediately follows the char value */
			if (i + 1 < db->count &&
			    db->attrs[i + 1].uuid16 == GATT_UUID_CCCD)
				cccd_handle = db->attrs[i + 1].handle;
			break;
		}
	}

	if (sc_handle == 0 || cccd_handle == 0) {
		LOG_GATT(1, "Service Changed: characteristic not found");
		return (0);
	}

	/* Check if the client has enabled indications via the CCCD */
	{
		bool ind_enabled = false;

		for (i = 0; i < ac->cccd_count; i++) {
			if (ac->cccds[i].handle == cccd_handle &&
			    (ac->cccds[i].value & GATT_CCCD_INDICATE) != 0) {
				ind_enabled = true;
				break;
			}
		}
		if (!ind_enabled) {
			LOG_GATT(1, "Service Changed: indications not "
			    "enabled (cccd_handle=%04x)", cccd_handle);
			return (0);
		}
	}

	/* Send the indication with the affected handle range */
	{
		uint8_t val[4];

		put_le16(val, start);
		put_le16(val + 2, end);
		if (att_send_indication(ac, sc_handle, val,
		    sizeof(val)) < 0) {
			LOG_GATT(1, "Service Changed indication send "
			    "failed");
			return (-1);
		}
		LOG_GATT(1, "Service Changed indication sent "
		    "(range %04x-%04x)", start, end);
		blued_ind_arm_timeout(pconn);
	}
	return (0);
}

/*
 * Peripheral connection setup thread.
 *
 * Gets the HCI connection handle, attempts SMP pairing as responder
 * (if the peer initiates it within 5 seconds), waits for encryption,
 * restores CCCDs, and registers the ATT fd with the kqueue event
 * loop via the self-pipe.
 *
 * Multiple peers may be active concurrently.  Mutable ATT state, including
 * CCCDs and prepared writes, lives in each connection's att_conn; the shared
 * GATT database contains only service and attribute definitions.
 */

/*
 * Write an accepted ATT Signed Write sign counter through to the bond
 * database so the replay floor (Core Spec Vol 3 Part H §2.4.5) survives
 * reconnection.  Installed on the bearer for bonded peers with a CSRK.
 */
static int
peripheral_persist_sign_counter(struct att_conn *ac, uint32_t counter)
{
	return (smp_bond_persist_sign_counter(blued_g.bond_db, ac->peer_csrk,
	    counter));
}

static void *
blued_conn_setup_peripheral_impl(void *arg)
{
	struct blued_conn *conn = arg;
	struct att_conn *ac = conn->att;
	struct blued_adapter *adp;

	adp = conn->adapter;
	if (adp == NULL) {
		blued_periph_setup_fail(conn);
		return (NULL);
	}

	/* Get connection handle -- poll with exponential backoff */
	{
		uint16_t ch = 0;
		int retries;
		useconds_t delay = CON_HANDLE_POLL_INIT_USEC;

		for (retries = 0; retries < CON_HANDLE_POLL_RETRIES;
		    retries++) {
			if (hci_get_con_handle(adp->hci_fd,
			    (const uint8_t *)&conn->dst, &ch) == 0)
				break;
			usleep(delay);
			delay *= 2;
		}
		if (retries < CON_HANDLE_POLL_RETRIES) {
			conn->con_handle = ch;
			conn->con_handle_valid = true;
			ac->con_handle = ch;

			/* Request DLE for peripheral connections */
			if (adp->le_features & LE_FEAT_DATA_LENGTH_EXT)
				hci_le_set_data_length(adp->hci_fd, ch,
				    0x00FB, 0x0848);
		}
	}
	blued_conn_apply_cached_local(conn);

	/*
	 * SMP responder: open an SMP channel and wait for the peer
	 * to initiate pairing.  Use poll() with a 5-second timeout
	 * to avoid blocking the connection if the peer never sends
	 * a Pairing Request (already bonded, or no security needed).
	 *
	 * SMP on LE uses fixed CID 0x0006.  The kernel's L2CAP layer
	 * requires bind(local) + connect(peer) even for fixed CIDs,
	 * matching the pattern used by smp_open() for central mode.
	 */
	if (conn->con_handle_valid && blued_g.bond_db != NULL) {
		struct smp_bond *bond;

		pthread_mutex_lock(&blued_g.bond_db_lock);
		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		if (bond == NULL) {
			struct smp_conn sc;
			struct pollfd pfd;
			int smp_fd, pr;

			smp_fd = socket(PF_BLUETOOTH,
			    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
			    BLUETOOTH_PROTO_L2CAP);
			if (smp_fd >= 0) {
				struct sockaddr_l2cap sa;

				/* Bind to local address, SMP CID */
				memset(&sa, 0, sizeof(sa));
				sa.l2cap_len = sizeof(sa);
				sa.l2cap_family = AF_BLUETOOTH;
				sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
				sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
				memcpy(&sa.l2cap_bdaddr, &adp->addr,
				    sizeof(sa.l2cap_bdaddr));

				if (bind(smp_fd, (struct sockaddr *)&sa,
				    sizeof(sa)) < 0) {
					warn("SMP bind");
					close(smp_fd);
					goto skip_smp;
				}

				/* Connect to peer on SMP CID */
				memset(&sa, 0, sizeof(sa));
				sa.l2cap_len = sizeof(sa);
				sa.l2cap_family = AF_BLUETOOTH;
				sa.l2cap_cid = htole16(NG_L2CAP_SMP_CID);
				sa.l2cap_bdaddr_type = conn->addr_type;
				memcpy(&sa.l2cap_bdaddr, &conn->dst,
				    sizeof(sa.l2cap_bdaddr));

				if (connect(smp_fd, (struct sockaddr *)&sa,
				    sizeof(sa)) < 0) {
					warn("SMP connect");
					close(smp_fd);
					goto skip_smp;
				}

				/*
				 * Wait up to 5 seconds for a Pairing Request.
				 * If the peer doesn't initiate, skip SMP and
				 * proceed with an unencrypted connection.
				 */
				pfd.fd = smp_fd;
				pfd.events = POLLIN;
				pr = poll(&pfd, 1, 5000);
				if (pr <= 0) {
					if (pr == 0)
						LOG_HOGP(2, "no pairing "
						    "request, skipping SMP");
					close(smp_fd);
					goto skip_smp;
				}

				if (smp_open_accepted(&sc, smp_fd,
				    (const uint8_t *)&conn->local_addr,
				    conn->local_addr_type,
				    (const uint8_t *)&conn->dst,
				    conn->addr_type,
				    adp->hci_fd, conn->con_handle,
				    blued_g.bond_db) < 0) {
					close(smp_fd);
					goto skip_smp;
				}
				/* Registered pairing agent's IO cap overrides
				 * the static config (the common pairing-agent model; Core
				 * Spec Vol 3 Part H §2.3.5.1). */
				sc.io_capability = blued_ctl_effective_io_cap(
				    blued_cfg.io_capability);
				sc.min_key_size = blued_cfg.min_key_size;
				sc.sc_only = blued_cfg.sc_mode == BLUED_SC_ONLY;
				sc.min_pairing_security =
				    blued_cfg.min_pairing_security;
				/* De-hardcoded AuthReq / key-dist policy. */
				sc.require_mitm = blued_cfg.mitm;
				sc.bondable = blued_cfg.bondable;
				sc.keypress = blued_cfg.keypress;
				sc.sc_enabled =
				    (blued_cfg.sc_mode != BLUED_SC_OFF);
				sc.our_key_dist = blued_cfg.key_dist;
				sc.their_key_dist = blued_cfg.key_dist;
				sc.passkey_cb = passkey_display;
				sc.passkey_cb_arg = conn;
				sc.numcmp_cb = numcmp_confirm;
				sc.numcmp_cb_arg = conn;
				/* Surface inbound keypress to push-event clients. */
				sc.keypress_cb = blued_keypress_notify;
				sc.keypress_cb_arg = &conn->dst;
				/* Operator PAIRABLE gate consulted by the
				 * responder (Core Spec Vol 3 Part H §3.5.1). */
				sc.reject_pairing = !atomic_load(&blued_pairable);

				if (smp_respond(&sc) == 0) {
					LOG_HOGP(1, "peripheral SMP pairing "
					    "complete, waiting for encryption");
					if (hci_wait_encryption(adp->hci_fd,
					    conn->con_handle, 10) < 0)
						warn("post-pairing encryption "
						    "timeout");
					else {
						struct smp_bond pb;
						bool have_pb = false;

						/*
						 * Open the ATT gate only if
						 * the just-completed pairing left
						 * a real LTK in the bond for this
						 * peer.  Snapshot the bond under
						 * bond_db_lock (finding 36): an
						 * unbond racing this read can
						 * memmove the table and hand back
						 * a stale key size, like the
						 * central path's
						 * hogp_bond_snapshot().
						 */
						pthread_mutex_lock(
						    &blued_g.bond_db_lock);
						{
							struct smp_bond *bp =
							    smp_find_bond(
							    sc.bond_db,
							    sc.remote_addr,
							    sc.remote_addr_type);
							if (bp != NULL) {
								pb = *bp;
								have_pb = true;
							}
						}
						pthread_mutex_unlock(
						    &blued_g.bond_db_lock);
						if (!att_conn_apply_encryption(
						    ac,
						    have_pb && pb.has_ltk,
						    have_pb && pb.is_mitm,
						    have_pb ? pb.key_size : 0,
						    16))
							LOG_HOGP(1, "post-pairing "
							    "encryption not backed "
							    "by stored bond key; "
							    "ATT gate stays closed");
						/* LE Ping: set auth payload
						 * timeout to 30s (3000 * 10ms)
						 * per Core Spec Vol 6 5.4 */
						hci_le_write_auth_payload_timeout(
						    adp->hci_fd,
						    conn->con_handle, 3000);
					}
				}
				smp_close(&sc);
			}
		}
	}
skip_smp:

	/*
	 * Reset per-connection CCCD state, then restore for a bonded
	 * device if applicable.  CCCDs are per-connection (stored in
	 * ac->cccds[]), not in the shared att_db.  This ensures unbonded
	 * connections start with all CCCDs at zero (Core Spec Vol 3
	 * Part G 2.5.3).
	 */
	att_server_reset(ac);

	/*
	 * GATT Robust Caching initial change-awareness (Core Spec Vol 3 Part G
	 * §2.5.2.1): "the initial state of a client without a trusted
	 * relationship is change-aware".  Default to change-aware here; the
	 * bonded-device Database Hash comparison below downgrades a client to
	 * change-unaware only when its cached database is known to be stale.
	 * Note: writing the Client Supported Features Robust Caching bit no
	 * longer forces change-awareness (see att_server_dispatch.c handle_write).
	 */
	ac->change_aware = true;

	pthread_mutex_lock(&blued_g.bond_db_lock);
	if (blued_g.bond_db != NULL) {
		struct smp_bond *bond;

		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		if (bond != NULL && bond->num_cccds > 0) {
			smp_bond_restore_cccds(bond, ac);
			LOG_HOGP(1, "restored %d CCCD(s) for bonded device",
			    bond->num_cccds);
		}

		/* Restore CSRK and sign counter for Signed Write verification */
		if (bond != NULL && bond->has_csrk) {
			memcpy(ac->peer_csrk, bond->csrk, 16);
			ac->has_peer_csrk = true;
			ac->peer_sign_counter = bond->peer_sign_counter;
			ac->has_peer_sign_counter =
			    (bond->peer_sign_counter > 0);
			ac->persist_sign_counter =
			    peripheral_persist_sign_counter;
			LOG_HOGP(1, "restored peer CSRK and sign "
			    "counter (%u) for bonded device",
			    bond->peer_sign_counter);
		}

		/*
		 * Service Changed indication for bonded devices.
		 * If the server's GATT database has changed since this
		 * client last connected (db_hash mismatch), send a
		 * Service Changed indication so the client invalidates
		 * its attribute cache (Core Spec Vol 3 Part G 2.5.2,
		 * 7.1).
		 */
		if (bond != NULL && bond->has_db_hash) {
			uint8_t cur_hash[16];

			attdb_compute_db_hash(&periph_gatt_db, cur_hash);
			if (memcmp(bond->db_hash, cur_hash, 16) != 0) {
				struct smp_bond previous = *bond;

				LOG_GATT(1, "db_hash changed for bonded "
				    "device, sending Service Changed");
				/*
				 * Core Spec Vol 3 Part G §2.5.2.1: a bonded
				 * client whose cached database has changed since
				 * its last connection starts change-unaware and
				 * must rediscover.  Only reading the Database
				 * Hash (or a Service Changed confirmation) will
				 * clear this — a Client Supported Features write
				 * will not.
				 */
				ac->change_aware = false;
				/*
				 * Finding 120: only advance the stored db_hash
				 * if the Service Changed indication was actually
				 * delivered.  If the send failed, leave the old
				 * hash so the next reconnect detects the change
				 * again and retries — otherwise the peer keeps a
				 * stale cache forever.
				 */
				if (gatt_send_service_changed(conn, ac,
				    &periph_gatt_db, 0x0001, 0xFFFF) == 0) {
					memcpy(bond->db_hash, cur_hash, 16);
					if (smp_bond_db_commit_bond(
					    blued_g.bond_db, bond,
					    &previous) != 0)
						warnx("saving peripheral "
						    "database hash");
				}
			}
		} else if (bond != NULL && !bond->has_db_hash) {
			struct smp_bond previous = *bond;

			/*
			 * First connection after bonding -- save the
			 * server's current db_hash so future reconnects
			 * can detect changes.
			 */
			attdb_compute_db_hash(&periph_gatt_db,
			    bond->db_hash);
			bond->has_db_hash = true;
			if (smp_bond_db_commit_bond(blued_g.bond_db, bond,
			    &previous) == 0)
				LOG_GATT(1, "saved server db_hash for bonded "
				    "device");
			else
				warnx("saving peripheral database hash");
		}
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);

	/*
	 * All diagnostics and the connection-parameter request touch conn
	 * and ac, so they must run BEFORE blued_conn_register() exposes
	 * conn to the main loop.  Once registered, an EV_EOF (peer
	 * disconnect) or idle timeout can free conn on the main thread,
	 * and this detached thread has no join barrier -- any later
	 * conn/ac access would be a use-after-free.
	 */
	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_HOGP(1, "peripheral client connected: %s "
		    "(handle=%04x encrypted=%d)",
		    addr_str, conn->con_handle, ac->encrypted);
		BLUED_PROBE_CONN_OPEN(addr_str, 1 /* peripheral */);
	}

	/* Log negotiated PHY */
	{
		uint8_t tx_phy, rx_phy;

		if (conn->con_handle_valid &&
		    hci_le_read_phy(adp->hci_fd, conn->con_handle,
		    &tx_phy, &rx_phy) == 0)
			LOG_HCI(1, "PHY: tx=%s rx=%s",
			    tx_phy == 2 ? "2M" : tx_phy == 3 ? "Coded" : "1M",
			    rx_phy == 2 ? "2M" : rx_phy == 3 ? "Coded" : "1M");
	}

	/*
	 * Request better connection parameters as peripheral.
	 * iOS/Android use conservative defaults (30ms interval).
	 * Request 30-50ms interval, 0 latency, 2s supervision timeout.
	 * Core Spec Vol 3 Part A 4.20.
	 */
	{
		if (l2cap_conn_param_update_req(
			    (const uint8_t *)&adp->addr,
			    (const uint8_t *)&conn->dst, conn->addr_type,
			    24, 40, 0, 200) < 0 && blued_verbose >= 2)
			warn("L2CAP conn param update");
	}

	/*
	 * Expose the connection to the event loop.  The idle timeout is
	 * armed before register so the main thread cannot race on
	 * conn->idle_timer between the two.  Past blued_conn_register()
	 * conn may be freed at any moment, so we only signal success on
	 * the (global) setup pipe and return -- no further conn/ac access.
	 */
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);
	blued_idle_arm(conn);
	if (blued_conn_register(conn) < 0) {
		warnx("peripheral conn register failed");
		blued_idle_disarm(conn);
		blued_periph_setup_fail(conn);
		return (NULL);
	}

	(void)write(blued_g.setup_pipe[1], "x", 1);
	return (NULL);
}

/* Keep conn alive for the complete lifetime of the detached setup worker. */
void *
blued_conn_setup_peripheral(void *arg)
{
	void *ret;

	ret = blued_conn_setup_peripheral_impl(arg);
	blued_setup_worker_finish((struct blued_conn *)arg);
	blued_conn_unref((struct blued_conn *)arg);
	return (ret);
}


/* ----------------------------------------------------------------
 *  Peripheral mode -- GATT server
 * ---------------------------------------------------------------- */

void
peripheral_build_gattdb(struct att_db *db, struct att_attr *attrs,
    uint8_t *val_buf, size_t val_size, const struct blued_config *cfgp)
{
	static const uint8_t appearance[] = { 0x00, 0x00 }; /* Unknown */

	attdb_init(db, attrs, 64, val_buf, val_size);

	/* GAP Service (required) */
	attdb_add_service(db, UUID_GAP_SERVICE);
	/*
	 * Device Name (0x2A00): reserve BLUED_GAP_NAME_MAXLEN of capacity in
	 * the value store so the SET_NAME operator verb can rename the device
	 * at runtime (attdb_set_char_value) up to that bound regardless of the
	 * startup name length.  value_len is trimmed to the real name below.
	 */
	{
		char namebuf[BLUED_GAP_NAME_MAXLEN];
		size_t nl = strlen(blued_peripheral_name);
		struct att_attr *na;
		uint16_t nh;

		if (nl > sizeof(namebuf))
			nl = sizeof(namebuf);
		memset(namebuf, 0, sizeof(namebuf));
		memcpy(namebuf, blued_peripheral_name, nl);
		nh = attdb_add_characteristic(db, UUID_DEVICE_NAME,
		    GATT_PROP_READ, ATT_PERM_READ, namebuf, sizeof(namebuf));
		na = attdb_find_by_handle(db, nh);
		if (na != NULL)
			na->value_len = (uint16_t)nl;
	}
	attdb_add_characteristic(db, UUID_APPEARANCE,
	    GATT_PROP_READ, ATT_PERM_READ,
	    appearance, sizeof(appearance));

	/*
	 * Central Address Resolution (UUID 0x2AA6), Core Spec Vol 3 Part C
	 * §12.4.  A dual-role device that also operates as a Central and
	 * supports LL Privacy (address resolution) shall expose this
	 * characteristic in its GAP service so a connected peer knows it may
	 * use Resolvable Private Addresses.  Read-only: 0x01 = address
	 * resolution supported, 0x00 = not supported.  Derived from whether LL
	 * privacy/address resolution is actually enabled on the adapter rather
	 * than hardcoded (finding 115): advertising 0x01 with resolution off
	 * would falsely invite a peer to rely on RPA resolution we do not do.
	 */
	{
		uint8_t car = blued_cfg.privacy ? 0x01 : 0x00;

		attdb_add_characteristic(db,
		    0x2AA6 /* Central Address Resolution */,
		    GATT_PROP_READ, ATT_PERM_READ, &car, 1);
	}

	/* GATT Service (required) with Service Changed characteristic */
	attdb_add_service(db, UUID_GATT_SERVICE);
	attdb_add_characteristic(db, 0x2A05 /* Service Changed */,
	    GATT_PROP_INDICATE, 0,
	    "\x01\x00\xFF\xFF", 4); /* handle range: 0x0001-0xFFFF */
	attdb_add_cccd(db);

	/*
	 * Client Supported Features (Core Spec Vol 3 Part G 7.2).
	 * Writable by client.  Bit 0 = Robust Caching, Bit 1 = EATT,
	 * Bit 2 = Multiple Handle Value Notifications.
	 *
	 * BT 5.1 GATT Robust Caching (7.3.1): when a client sets the
	 * Robust Caching bit (ATT_CLIENT_FEAT_ROBUST_CACHING), the
	 * server must track change-awareness and return
	 * ATT_ERR_DATABASE_OUT_OF_SYNC until the client becomes
	 * change-aware (by reading the Database Hash).  Since blued's
	 * GATT database is built once at startup and never changes at
	 * runtime, all clients are inherently change-aware after their
	 * first connection.  No out-of-sync errors will ever be
	 * generated, which is the correct behaviour for a static
	 * database per the spec.
	 */
	attdb_add_characteristic(db, UUID_CLIENT_SUPP_FEAT,
	    GATT_PROP_READ | GATT_PROP_WRITE, ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);

	/*
	 * Server Supported Features (Core Spec Vol 3 Part G 7.4).
	 * Read-only.  Bit 0 = EATT supported.
	 */
	{
		static const uint8_t ssf[] = { 0x01 }; /* EATT supported */
		attdb_add_characteristic(db, UUID_SERVER_SUPP_FEAT,
		    GATT_PROP_READ, ATT_PERM_READ,
		    ssf, sizeof(ssf));
	}

	/*
	 * Database Hash characteristic (Core Spec Vol 3 Part G 7.3).
	 * Must be inside the GATT Service attribute group.
	 * Placeholder value; computed after full DB build below.
	 */
	attdb_add_characteristic(db, UUID_DATABASE_HASH,
	    GATT_PROP_READ, ATT_PERM_READ,
	    "\x00\x00\x00\x00\x00\x00\x00\x00"
	    "\x00\x00\x00\x00\x00\x00\x00\x00", 16);

	/* Device Information Service */
	attdb_add_service(db, UUID_DIS_SERVICE);
	attdb_add_characteristic(db, UUID_MANUFACTURER,
	    GATT_PROP_READ, ATT_PERM_READ, "FreeBSD", 7);
	attdb_add_characteristic(db, UUID_MODEL_NUMBER,
	    GATT_PROP_READ, ATT_PERM_READ, "blued", 5);
	attdb_add_characteristic(db, UUID_FIRMWARE_REV,
	    GATT_PROP_READ, ATT_PERM_READ, "1.0", 3);

	/* Custom service with read/write/notify */
	attdb_add_service(db, UUID_CUSTOM_SERVICE);
	attdb_add_characteristic(db, UUID_CUSTOM_CHAR,
	    GATT_PROP_READ | GATT_PROP_WRITE | GATT_PROP_NOTIFY,
	    ATT_PERM_READ | ATT_PERM_WRITE,
	    "\x00", 1);
	attdb_add_cccd(db);

	/*
	 * Config-driven services: register any services defined in
	 * the configuration file's "service" blocks.
	 */
	if (cfgp != NULL) {
		for (int si = 0; si < cfgp->nservices; si++) {
			const struct blued_service_conf *svc;
			uint16_t sh;

			svc = &cfgp->services[si];
			if (svc->uuid16 != 0)
				sh = attdb_add_service(db, svc->uuid16);
			else
				sh = attdb_add_service128(db, svc->uuid128);
			if (sh == 0) {
				LOG_ATT(0, "config service '%s': "
				    "failed to add", svc->name);
				continue;
			}
			LOG_ATT(1, "config service '%s' added at "
			    "handle 0x%04x", svc->name, sh);

			for (int ii = 0; ii < svc->nincludes; ii++) {
				const struct blued_include_conf *inc =
				    &svc->includes[ii];

				attdb_add_include(db, sh, inc->start,
				    inc->end, inc->uuid16);
			}

			for (int ci = 0; ci < svc->nchars; ci++) {
				const struct blued_char_conf *ch;
				uint16_t ch_handle;

				ch = &svc->chars[ci];
				if (ch->uuid16 != 0) {
					ch_handle =
					    attdb_add_characteristic(db,
					    ch->uuid16, ch->properties,
					    ch->permissions,
					    ch->initial_value_len > 0 ?
					    ch->initial_value : NULL,
					    ch->initial_value_len);
				} else {
					ch_handle =
					    attdb_add_characteristic128(db,
					    ch->uuid128, ch->properties,
					    ch->permissions,
					    ch->initial_value_len > 0 ?
					    ch->initial_value : NULL,
					    ch->initial_value_len);
				}
				if (ch_handle == 0) {
					LOG_ATT(0, "config service '%s': "
					    "failed to add char", svc->name);
					continue;
				}
				if (ch->has_cccd)
					attdb_add_cccd(db);
				for (int di = 0; di < ch->ndescs; di++) {
					const struct blued_desc_conf *desc =
					    &ch->descs[di];

					if (desc->uuid16 != 0)
						attdb_add_descriptor(db,
						    desc->uuid16,
						    desc->permissions,
						    desc->value_len > 0 ?
						    desc->value : NULL,
						    desc->value_len);
					else
						attdb_add_descriptor128(db,
						    desc->uuid128,
						    desc->permissions,
						    desc->value_len > 0 ?
						    desc->value : NULL,
						    desc->value_len);
				}
			}
		}
	}

	/*
	 * Compute Database Hash and update the placeholder.
	 * The hash characteristic was added inside the GATT service above.
	 */
	{
		uint8_t db_hash[16];

		attdb_compute_db_hash(db, db_hash);
		for (int i = 0; i < db->count; i++) {
			if (db->attrs[i].uuid16 == UUID_DATABASE_HASH &&
			    db->attrs[i].value_len == 16) {
				memcpy(db->attrs[i].value, db_hash, 16);
				break;
			}
		}
	}

	/*
	 * periph_gatt_attrs is fixed at 64 entries (blued_internal.h).
	 * Warn if the database is nearing capacity so the admin knows
	 * to increase the array size or reduce configured services.
	 */
	if (db->count >= 56)
		LOG_ATT(0, "WARNING: GATT database has %d/%d attributes, "
		    "nearing capacity", db->count, 64);

	LOG_ATT(1, "GATT database built: %d attributes", db->count);
}

int
peripheral_att_listen(struct blued_adapter *adp)
{
	struct sockaddr_l2cap sa;
	int fd;

	if (adp == NULL)
		return (-1);

	fd = socket(PF_BLUETOOTH,
	    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		return (-1);

	{
		int one = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_cid = htole16(NG_L2CAP_ATT_CID);
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	memcpy(sa.l2cap_bdaddr.b, &adp->addr, sizeof(adp->addr));

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		warn("ATT listen bind (is another blued still running?)");
		close(fd);
		return (-1);
	}

	if (listen(fd, 1) < 0) {
		warn("ATT listen");
		close(fd);
		return (-1);
	}

	{
		char addr_str[18];
		bt_ntoa(&adp->addr, addr_str);
		LOG_ATT(1, "ATT listen socket fd=%d addr=%s cid=0x%04x "
		    "type=%d", fd, addr_str,
		    NG_L2CAP_ATT_CID, sa.l2cap_bdaddr_type);
	}

	return (fd);
}

/*
 * Bind and listen an L2CAP CoC socket for incoming Enhanced ATT (EATT)
 * bearers on the ATT PSM 0x0027 (Core Spec Vol 3 Part G §5.3, Part F
 * §5.3.2).  Enhanced bearers are dynamic L2CAP CoC channels (not the fixed
 * ATT CID 0x0004), so the listener binds by PSM.  Returns the listening fd,
 * or -1 (EATT is optional; the caller degrades to the fixed bearer only).
 */
int
blued_eatt_listen(struct blued_adapter *adp)
{
	struct sockaddr_l2cap sa;
	int ecbfc, encrypted, fd;

	if (adp == NULL)
		return (-1);

	fd = socket(PF_BLUETOOTH,
	    SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_CLOFORK,
	    BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		return (-1);

	/* PSM 0x0027 is EATT only in Enhanced Credit Based Flow Control mode. */
	ecbfc = 1;
	if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_ECBFC,
	    &ecbfc, sizeof(ecbfc)) < 0) {
		warn("EATT setsockopt SO_L2CAP_ECBFC");
		close(fd);
		return (-1);
	}
	encrypted = 1;
	if (setsockopt(fd, SOL_L2CAP, SO_L2CAP_ENCRYPTED,
	    &encrypted, sizeof(encrypted)) < 0) {
		warn("EATT setsockopt SO_L2CAP_ENCRYPTED");
		close(fd);
		return (-1);
	}

	{
		int one = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	memset(&sa, 0, sizeof(sa));
	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_psm = htole16(ATT_EATT_PSM);
	sa.l2cap_cid = 0;			/* dynamic CoC */
	sa.l2cap_bdaddr_type = BDADDR_LE_PUBLIC;
	memcpy(sa.l2cap_bdaddr.b, &adp->addr, sizeof(adp->addr));

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		warn("EATT listen bind (PSM 0x%04x)", ATT_EATT_PSM);
		close(fd);
		return (-1);
	}

	if (listen(fd, ATT_MAX_EATT_BEARERS) < 0) {
		warn("EATT listen");
		close(fd);
		return (-1);
	}

	LOG_ATT(1, "EATT listen socket fd=%d psm=0x%04x", fd, ATT_EATT_PSM);
	return (fd);
}

/*
 * Accept an incoming EATT bearer from the shared EATT listener and attach it
 * to the connection that owns the peer address.  Enhanced bearers multiplex
 * ATT PDUs in parallel with the fixed ATT channel; each accepted bearer is
 * registered with the kqueue (keyed on its owning connection) so ATT traffic
 * arriving on it is dispatched by blued_handle_readable() (Core Spec Vol 3
 * Part G §5.3).
 */
void
blued_eatt_accept(struct blued_adapter *adp)
{
	struct sockaddr_l2cap peer_sa;
	socklen_t peer_len;
	struct blued_conn *conn;
	int fd;

	peer_len = sizeof(peer_sa);
	fd = accept4(adp->eatt_listen_fd, (struct sockaddr *)&peer_sa,
	    &peer_len, SOCK_CLOEXEC | SOCK_CLOFORK);
	if (fd < 0) {
		if (errno != EINTR)
			warn("EATT accept");
		return;
	}

	/*
	 * An EATT bearer is only meaningful once the peer already has a
	 * (fixed-bearer) connection; route by peer address to that connection.
	 */
	conn = blued_conn_by_peer(adp,
	    (const bdaddr_t *)peer_sa.l2cap_bdaddr.b,
	    peer_sa.l2cap_bdaddr_type);
	if (conn == NULL || conn->att == NULL || !conn->att->encrypted) {
		LOG_ATT(1, "EATT: no matching connection, "
		    "or link is not encrypted; rejecting bearer");
		close(fd);
		return;
	}

	/*
	 * Finding 95: gate on att_ops_active, exactly as the EATT_OPEN verb
	 * does.  A GATT worker owning the ATT recv path must not have the EATT
	 * bearer array mutated under it; reject the inbound bearer (the peer may
	 * retry) rather than corrupt the array.
	 */
	if (atomic_load_explicit(&conn->att_ops_active,
	    memory_order_acquire) != 0) {
		LOG_ATT(1, "EATT: connection busy with a GATT operation; "
		    "rejecting bearer");
		close(fd);
		return;
	}

	/* Serialise the array mutation against the encryption-change teardown
	 * (att_close_eatt), which also holds att_sec_lock (finding 95). */
	pthread_mutex_lock(&blued_g.att_sec_lock);
	if (att_eatt_add_bearer(conn->att, fd) < 0) {
		pthread_mutex_unlock(&blued_g.att_sec_lock);
		LOG_ATT(1, "EATT: cannot attach bearer: %s", strerror(errno));
		close(fd);
		return;
	}
	pthread_mutex_unlock(&blued_g.att_sec_lock);

	{
		if (blued_conn_register_bearer(conn, fd) < 0) {
			warn("kevent eatt bearer");
			att_eatt_remove_bearer(conn->att, fd);
			return;
		}
	}

	{
		char addr_str[18];
		bt_ntoa(&conn->dst, addr_str);
		LOG_ATT(1, "EATT bearer accepted from %s (fd=%d)", addr_str, fd);
	}
}

/* peripheral_run() removed -- peripheral mode now uses the unified kqueue
 * event loop with blued_periph_accept() and blued_conn_setup_peripheral(). */
