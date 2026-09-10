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

	if (adp->adv_use_extended) {
		adv_err = hci_le_set_ext_adv_enable(adp->hci_fd, 1, 0x00);
	} else {
		/*
		 * On a legacy controller a mesh burst may have left its
		 * non-connectable advertisement on air, with ITS parameters
		 * and ITS data programmed in the controller's single
		 * advertising set.  Reclaim the resource fully -- stop plus
		 * our own ADV_IND parameters and our own payload -- so the
		 * re-enable below airs OUR advertisement rather than silently
		 * continuing mesh's.  A reclaim failure is treated as a
		 * re-advertise failure (retry path below) rather than airing
		 * mesh's stale PDU as if it were ours.
		 */
		if (blued_adv_legacy_reclaim(adp, NULL, 0,
		    adp->primary_scan_rsp_valid ? adp->primary_scan_rsp : NULL,
		    adp->primary_scan_rsp_len) < 0)
			adv_err = -1;
		else
			adv_err = hci_le_set_advertise_enable(adp->hci_fd, true);
	}
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
	/*
	 * Bound att_server_send() on this server socket: it runs on the
	 * event-loop thread under gatt_db_lock, so a stalled peer must not be
	 * able to block the whole GATT worker pool.  5s caps the priority
	 * inversion, well above any healthy L2CAP backpressure.
	 */
	{
		struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
		if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO,
		    &tv, sizeof(tv)) < 0)
			warn("setsockopt SO_SNDTIMEO");
	}
	/*
	 * calloc leaves bearer_fd == 0, which att_server_send() would select
	 * as fd 0 for every out-of-dispatch PDU (notifications, indications,
	 * Service Changed).  Mirror att_open()'s initializer: -1 means "use
	 * the primary ATT socket (ac->fd)".
	 */
	ac->bearer_fd = -1;
	for (int i = 0; i < ATT_MAX_EATT_BEARERS; i++)
		ac->eatt[i].fd = -1;
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
/*
 * Resolve the Service Changed characteristic value / CCCD handles and value
 * permissions from the GATT database.  This is the ONLY part of the Service
 * Changed path that reads the database, so callers hold gatt_db_lock across
 * just this lookup and can then send the indication (a blocking socket write)
 * with the lock released -- keeping the DB-mutating main event loop off a lock
 * held across the network send.  Returns 0 on success, -1 if the characteristic
 * is absent.
 */
static int
gatt_service_changed_lookup(struct att_db *db, uint16_t *sc_handle,
    uint16_t *cccd_handle, uint8_t *sc_perms)
{
	int i;

	*sc_handle = 0;
	*cccd_handle = 0;
	*sc_perms = 0;
	for (i = 0; i < db->count; i++) {
		if (db->attrs[i].uuid16 == 0x2A05 &&
		    db->attrs[i].is_char_value) {
			*sc_handle = db->attrs[i].handle;
			*sc_perms = db->attrs[i].perms;
			/* The CCCD immediately follows the char value */
			if (i + 1 < db->count &&
			    db->attrs[i + 1].uuid16 == GATT_UUID_CCCD)
				*cccd_handle = db->attrs[i + 1].handle;
			break;
		}
	}
	if (*sc_handle == 0 || *cccd_handle == 0)
		return (-1);
	return (0);
}

static int
gatt_send_service_changed(struct blued_conn *pconn, struct att_conn *ac,
    uint16_t sc_handle, uint16_t cccd_handle, uint8_t sc_perms, uint16_t start,
    uint16_t end)
{
	int i;

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
		/*
		 * A-F2 (peripheral path): do not push a protected characteristic
		 * value over a link that fails its encryption/authentication
		 * requirement.  If the Service Changed value attribute carries no
		 * ENCRYPT/AUTHEN bits this is satisfied trivially and delivery
		 * proceeds unchanged.
		 */
		if (att_check_security_perms(sc_perms, ac) != 0) {
			LOG_GATT(1, "Service Changed indication withheld: link "
			    "does not satisfy characteristic security");
			return (0);
		}
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
 * Record an accepted ATT Signed Write sign counter so the replay floor (Core
 * Spec Vol 3 Part H §2.4.5) survives reconnection.  Installed on the bearer
 * for bonded peers with a CSRK.
 *
 * C3-H2: this used to call smp_bond_persist_sign_counter(), which re-encrypts
 * and rewrites the ENTIRE bond database (PBKDF2 + AES-GCM + two fsyncs, under
 * bond_db_lock) for every single accepted counter.  Signed Writes are
 * unacknowledged ATT commands, so a bonded peer could drive that at will on
 * the ATT thread -- a trivially reachable denial of service against the whole
 * daemon.  The counter is now advanced in memory only and marked dirty; the
 * expensive write-out happens at most once per BLUED_SIGNCTR_FLUSH_SEC (and at
 * shutdown) via blued_sign_counter_flush().  Replay protection is unchanged
 * within a session because ac->peer_sign_counter and the bond record both
 * still rise monotonically on every accepted write.
 */
static atomic_bool blued_sign_ctr_dirty;

static int
peripheral_persist_sign_counter(struct att_conn *ac, uint32_t counter)
{
	struct smp_bond_db *db = blued_g.bond_db;
	int i;

	if (db == NULL || ac == NULL)
		return (-1);
	pthread_mutex_lock(&blued_g.bond_db_lock);
	for (i = 0; i < db->count; i++) {
		if (!db->bonds[i].has_csrk ||
		    timingsafe_bcmp(db->bonds[i].csrk, ac->peer_csrk,
		    sizeof(ac->peer_csrk)) != 0)
			continue;
		/*
		 * Advance a strictly newer counter, or record the very first
		 * verified one: a first accepted counter of 0 must still be
		 * stored (with has_peer_sign_counter) or its replay window
		 * would reopen on the next reconnect.
		 */
		if (!db->bonds[i].has_peer_sign_counter ||
		    counter > db->bonds[i].peer_sign_counter) {
			db->bonds[i].peer_sign_counter = counter;
			db->bonds[i].has_peer_sign_counter = true;
			atomic_store_explicit(&blued_sign_ctr_dirty, true,
			    memory_order_release);
		}
		break;
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
	return (0);
}

/*
 * Write out bond records whose Signed-Write replay floor advanced since the
 * last flush.  Called from the main loop's periodic timer and at shutdown.
 * A failed write leaves the dirty flag set so the next tick retries.
 */
void
blued_sign_counter_flush(void)
{
	struct smp_bond_db *db = blued_g.bond_db;

	if (db == NULL)
		return;
	if (!atomic_exchange_explicit(&blued_sign_ctr_dirty, false,
	    memory_order_acq_rel))
		return;
	pthread_mutex_lock(&blued_g.bond_db_lock);
	/* A DB with no atomic target is explicitly ephemeral (unit tests). */
	if (db->dir_fd >= 0 && db->file_name[0] != '\0' &&
	    smp_bond_db_save(db) != 0) {
		atomic_store_explicit(&blued_sign_ctr_dirty, true,
		    memory_order_release);
		warnx("persisting ATT Signed Write replay counters");
	}
	pthread_mutex_unlock(&blued_g.bond_db_lock);
}

/* Arm the repeating Signed-Write counter flush timer.  Idempotent. */
int
blued_sign_counter_timer_arm(void)
{
	static uintptr_t timer_id;
	struct kevent kev;

	if (blued_g.kq < 0 || timer_id != 0)
		return (0);
	timer_id = blued_next_timer_id++;
	EV_SET(&kev, timer_id, EVFILT_TIMER, EV_ADD | EV_ENABLE, NOTE_SECONDS,
	    BLUED_SIGNCTR_FLUSH_SEC, BLUED_KQ_SIGNCTR_FLUSH);
	if (kevent(blued_g.kq, &kev, 1, NULL, 0, NULL) < 0) {
		timer_id = 0;
		return (-1);
	}
	return (0);
}

/*
 * Install (or clear) a bond's ATT Signed-Write verification state -- the peer
 * CSRK, its replay floor and the write-through hook -- on a connection's ATT
 * bearer.
 *
 * Shared by the peripheral setup path and the success arm of periph_smp_run().
 * The setup path alone is not enough: a late re-pair on an already-ACTIVE
 * connection can distribute a CSRK for the first time (invisible for the life
 * of the connection) or rotate an existing one (leaving ac verifying against
 * the dead key).  `bond' may be NULL or carry no CSRK, in which case the state
 * is cleared rather than left stale -- a re-pair that drops SignKey must not
 * keep the previous key usable.
 *
 * The caller must hold blued_g.bond_db_lock: `bond' points into the bond table.
 */
static void
periph_restore_signed_write(struct att_conn *ac, const struct smp_bond *bond)
{

	if (ac == NULL)
		return;
	if (bond != NULL && bond->has_csrk) {
		memcpy(ac->peer_csrk, bond->csrk, sizeof(ac->peer_csrk));
		ac->has_peer_csrk = true;
		ac->peer_sign_counter = bond->peer_sign_counter;
		ac->has_peer_sign_counter = bond->has_peer_sign_counter;
		ac->persist_sign_counter = peripheral_persist_sign_counter;
		LOG_HOGP(1, "restored peer CSRK and sign counter (%u) for "
		    "bonded device", bond->peer_sign_counter);
		return;
	}
	explicit_bzero(ac->peer_csrk, sizeof(ac->peer_csrk));
	ac->has_peer_csrk = false;
	ac->peer_sign_counter = 0;
	ac->has_peer_sign_counter = false;
	ac->persist_sign_counter = NULL;
}

/*
 * Run the SMP responder to completion on an open, connected SMP channel
 * (fixed CID 0x0006) that has a Pairing Request pending.  Consumes SMP_FD.
 *
 * Called from a worker thread only: either the peripheral setup worker (a
 * Pairing Request arrived inside the setup poll window) or the late-pairing
 * worker (a bonded peer re-paired after its link was already up).  Never from
 * the main event loop -- pairing blocks for the whole handshake, including
 * operator passkey/numeric-comparison round trips.
 */
static void
periph_smp_run(struct blued_conn *conn, struct blued_adapter *adp, int smp_fd)
{
	struct att_conn *ac = conn->att;
	struct smp_conn sc;
	/* OOB storage for the responder, valid across smp_respond(). */
	struct smp_oob_legacy oob_lg;
	struct smp_oob_sc oob_sc;
	struct smp_oob_data oob_data;
	bool have_lg = false, have_sc = false;
	int respond_rc;

	/*
	 * C3-D31: claim the controller's LE LTK Request for this connection
	 * for the whole handshake.  The SMP library answers it itself; the
	 * main loop must not race it with a reply derived from the pre-pairing
	 * bond (a fresh pairing's encryption start carries ediv==0/rand==0,
	 * which is precisely the handler's Secure Connections match) nor with
	 * a negative reply.  Cleared the instant smp_respond() returns.
	 */
	atomic_store_explicit(&conn->smp_owns_ltk, true, memory_order_release);

	if (smp_open_accepted(&sc, smp_fd,
	    (const uint8_t *)&conn->local_addr, conn->local_addr_type,
	    (const uint8_t *)&conn->dst, conn->addr_type,
	    adp->hci_fd, conn->con_handle, blued_g.bond_db) < 0) {
		atomic_store_explicit(&conn->smp_owns_ltk, false,
		    memory_order_release);
		close(smp_fd);
		return;
	}
	/*
	 * Registered pairing agent's IO cap overrides the static config (the
	 * common pairing-agent model; Core Spec Vol 3 Part H §2.3.5.1).
	 */
	sc.io_capability = blued_ctl_effective_io_cap(blued_cfg.io_capability);
	sc.min_key_size = blued_cfg.min_key_size;
	sc.sc_only = blued_cfg.sc_mode == BLUED_SC_ONLY;
	sc.min_pairing_security = blued_cfg.min_pairing_security;
	/* De-hardcoded AuthReq / key-dist policy. */
	sc.require_mitm = blued_cfg.mitm;
	sc.bondable = blued_cfg.bondable;
	sc.keypress = blued_cfg.keypress;
	sc.sc_enabled = (blued_cfg.sc_mode != BLUED_SC_OFF);
	sc.our_key_dist = blued_cfg.key_dist;
	sc.their_key_dist = blued_cfg.key_dist;
	sc.passkey_cb = passkey_display;
	sc.passkey_cb_arg = conn;
	sc.numcmp_cb = numcmp_confirm;
	sc.numcmp_cb_arg = conn;
	/* Surface inbound keypress to push-event clients. */
	sc.keypress_cb = blued_keypress_notify;
	sc.keypress_cb_arg = &conn->dst;
	/*
	 * Operator PAIRABLE gate consulted by the responder (Core Spec Vol 3
	 * Part H §3.5.1).
	 */
	sc.reject_pairing = !atomic_load(&blued_pairable);

	/*
	 * Wire any operator-injected OOB for this peer so inbound SC-OOB /
	 * legacy-OOB pairing can complete (previously the responder never
	 * consumed OOB, so SC-OOB always fell back and failed).
	 */
	sc.oob = NULL;
	if (blued_oob_take((const uint8_t *)&conn->dst, &oob_lg, &have_lg,
	    &oob_sc, &have_sc) && (have_lg || have_sc)) {
		memset(&oob_data, 0, sizeof(oob_data));
		oob_data.legacy = have_lg ? &oob_lg : NULL;
		oob_data.sc = have_sc ? &oob_sc : NULL;
		sc.oob = &oob_data;
	}

	respond_rc = smp_respond(&sc);
	atomic_store_explicit(&conn->smp_owns_ltk, false, memory_order_release);
	if (respond_rc == 0) {
		struct smp_bond pb;
		bool have_pb = false;

		/*
		 * C3-H1: smp_respond() already waited for and consumed the HCI
		 * Encryption Change event internally (smp_sc.c:1498/1918,
		 * smp_legacy.c:220) and returns <0 if encryption did not turn
		 * on.  A redundant outer hci_wait_encryption() here would wait
		 * on an already-consumed one-shot event and always time out,
		 * mapping a completed pairing to failure and never opening the
		 * ATT gate.  Success => encryption is on; run the apply/gate
		 * path directly.
		 */
		LOG_HOGP(1, "peripheral SMP pairing complete");

		/*
		 * Open the ATT gate only if the just-completed pairing left a
		 * real LTK in the bond for this peer.  Snapshot the bond under
		 * bond_db_lock (finding 36): an unbond racing this read can
		 * memmove the table and hand back a stale key size, like the
		 * central path's hogp_bond_snapshot().
		 */
		pthread_mutex_lock(&blued_g.bond_db_lock);
		{
			struct smp_bond *bp = smp_find_bond(sc.bond_db,
			    sc.remote_addr, sc.remote_addr_type);

			if (bp != NULL) {
				pb = *bp;
				have_pb = true;
			}
			/*
			 * Refresh the ATT bearer's Signed-Write state from the
			 * bond this pairing just wrote.  Without this a late
			 * re-pair's newly distributed CSRK stays invisible for
			 * the life of the connection, and a rotated CSRK leaves
			 * the bearer verifying against the dead key.  Same
			 * lock discipline as the setup path (bond_db_lock held,
			 * bp points into the table).
			 */
			periph_restore_signed_write(ac, bp);
		}
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		/*
		 * Finding 95: the ATT security triple must be written under
		 * att_sec_lock, exactly as the central path does
		 * (blued_central.c).  Reached from the late-pairing worker this
		 * runs on a live ACTIVE connection, concurrently with the main
		 * loop's Encryption Change / Key Refresh handlers, which write
		 * the same fields.
		 */
		pthread_mutex_lock(&blued_g.att_sec_lock);
		if (!att_conn_apply_encryption(ac, have_pb && pb.has_ltk,
		    have_pb && pb.is_mitm, have_pb ? pb.key_size : 0, 16))
			LOG_HOGP(1, "post-pairing encryption not backed by "
			    "stored bond key; ATT gate stays closed");
		pthread_mutex_unlock(&blued_g.att_sec_lock);
		/*
		 * LE Ping: set auth payload timeout to 30s (3000 * 10ms) per
		 * Core Spec Vol 6 5.4.
		 */
		hci_le_write_auth_payload_timeout(adp->hci_fd, conn->con_handle,
		    3000);
		/*
		 * Finding H-L4: an inbound (peripheral-role) pairing that
		 * distributed a peer IRK must program it into the controller
		 * resolving list too — the central path already does this.
		 * Refresh (remove-then-add) so a rotated IRK replaces any prior
		 * entry.
		 */
		if (have_pb) {
			blued_reslist_sync_remove(adp->hci_fd, pb.addr,
			    pb.addr_type);
			blued_reslist_sync_add(adp->hci_fd, &pb);
		}
	} else {
		/*
		 * Failed (re-)pairing.  smp_respond() turns encryption on
		 * BEFORE key distribution and bond storage, so a late re-pair
		 * that fails afterwards -- the §2.4.2.4 downgrade guard
		 * refusing the store, or key distribution failing -- leaves the
		 * link re-keyed with the new, possibly weaker material while
		 * the ATT gate still records the pre-re-pair (stronger) level.
		 *
		 * Close the gate rather than disconnect, matching how the rest
		 * of the daemon treats a pairing that did not complete: the
		 * central path (blued_central.c) also only refuses to open the
		 * gate, and the main loop's Encryption Change failure arm
		 * (blued_event.c) uses exactly this clear + EATT teardown.  The
		 * peer keeps its ACL and may retry; every encrypt- or
		 * authenticate-required attribute is inaccessible until a
		 * pairing actually succeeds and re-opens the gate.
		 */
		pthread_mutex_lock(&blued_g.att_sec_lock);
		if (ac != NULL) {
			ac->encrypted = false;
			ac->authenticated = false;
			ac->enc_key_size = 0;
			att_close_eatt(ac);
		}
		pthread_mutex_unlock(&blued_g.att_sec_lock);
		LOG_HOGP(1, "peripheral SMP pairing failed; ATT security gate "
		    "closed");
	}
	smp_close(&sc);

	/*
	 * Clear OOB material once smp_respond() has consumed it (success or
	 * failure).  The SC-OOB ephemeral is detached here, not at take time
	 * (C1-H2), so the published local public key survived through pairing.
	 */
	explicit_bzero(&oob_lg, sizeof(oob_lg));
	explicit_bzero(&oob_sc, sizeof(oob_sc));
	if (have_sc)
		smp_sc_oob_clear_local();
}

/* Arguments handed to the detached late-pairing worker. */
struct periph_smp_late_arg {
	struct blued_conn	*conn;
	int			 fd;
};

/*
 * Late-pairing worker: a bonded peer sent a Pairing Request after its
 * connection was already established.  Owns FD and one connection reference,
 * plus one att_ops credit taken by the event loop (which keeps ATT dispatch
 * off this connection and defers teardown for the duration, exactly as for
 * the central pairing worker, finding H-H1).
 */
static void *
blued_periph_smp_late_worker(void *arg)
{
	struct periph_smp_late_arg *la = arg;
	struct blued_conn *conn = la->conn;
	int fd = la->fd;

	free(la);
	if (conn->adapter != NULL && conn->att != NULL &&
	    !atomic_load(&conn->disconnect_pending)) {
		LOG_HOGP(1, "bonded peer re-pairing after connection setup");
		periph_smp_run(conn, conn->adapter, fd);
	} else {
		close(fd);
	}
	blued_conn_att_ops_end(conn);
	blued_setup_worker_finish(conn);
	blued_conn_unref(conn);
	return (NULL);
}

/*
 * Main-loop dispatch for a readable armed SMP responder channel (udata
 * BLUED_KQ_SMP): a late Pairing Request from a bonded peer.  The fd is
 * unregistered and moved out of the connection here, so exactly one worker can
 * ever own it, and the blocking responder never runs on the event loop thread.
 */
void
blued_periph_smp_late_event(int fd, bool eof)
{
	struct periph_smp_late_arg *la;
	struct blued_conn *conn, *c;
	struct kevent kev;
	pthread_attr_t attr;
	pthread_t tid;

	if (fd < 0)
		return;
	EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	(void)kevent(blued_g.kq, &kev, 1, NULL, 0, NULL);

	conn = NULL;
	pthread_rwlock_wrlock(&blued_g.conns_lock);
	LIST_FOREACH(c, &blued_g.conns, entries) {
		if (c->smp_fd == fd) {
			conn = c;
			c->smp_fd = -1;	/* ownership moves to the worker */
			break;
		}
	}
	pthread_rwlock_unlock(&blued_g.conns_lock);
	if (conn == NULL) {
		/*
		 * No live connection claims this descriptor: its owner has been
		 * detached from the list but not yet destroyed (a worker still
		 * holds a reference).  The registration is already deleted
		 * above, so no further event can arrive; the owner closes the
		 * descriptor in blued_conn_destroy().  Closing it here would
		 * double-close -- possibly a recycled descriptor.
		 */
		return;
	}
	if (eof) {
		LOG_HOGP(2, "SMP responder channel closed by peer");
		close(fd);
		return;
	}

	la = malloc(sizeof(*la));
	if (la == NULL) {
		close(fd);
		return;
	}
	la->conn = conn;
	la->fd = fd;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	blued_conn_ref(conn);
	blued_setup_worker_start(conn);
	blued_conn_att_ops_begin(conn);
	if (pthread_create(&tid, &attr, blued_periph_smp_late_worker, la) != 0) {
		blued_conn_att_ops_end(conn);
		blued_setup_worker_finish(conn);
		blued_conn_unref(conn);
		warn("late SMP responder thread");
		free(la);
		close(fd);
	}
	pthread_attr_destroy(&attr);
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
			    (const uint8_t *)&conn->dst, conn->addr_type,
			    &ch) == 0)
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
	 * SMP responder: open an SMP channel and wait for the peer to initiate
	 * pairing.  SMP on LE uses fixed CID 0x0006.  The kernel's L2CAP layer
	 * requires bind(local) + connect(peer) even for fixed CIDs, matching
	 * the pattern used by smp_open() for central mode.
	 *
	 * Poll window: an UNBONDED peer that just connected is expected to pair
	 * now, so the setup path waits BLUED_SMP_RESPOND_POLL_MS for its
	 * Pairing Request.  A BONDED peer normally sends nothing on the SMP CID
	 * (it re-encrypts with the stored LTK), so blocking the setup path for
	 * seconds on every bonded reconnect would delay conn ACTIVE -- and HID
	 * input -- by that long.  Bonded peers therefore get only a short
	 * courtesy poll; if nothing arrives, the responder channel is kept OPEN
	 * and registered with the event loop (BLUED_KQ_SMP), so a later Pairing
	 * Request -- key loss, or the peer answering a Security Request -- is
	 * still served, on a worker thread, by blued_periph_smp_late_event().
	 */
	if (conn->con_handle_valid && blued_g.bond_db != NULL) {
		struct smp_bond *bond;
		bool bonded;

		pthread_mutex_lock(&blued_g.bond_db_lock);
		bond = smp_find_bond(blued_g.bond_db,
		    (const uint8_t *)&conn->dst, conn->addr_type);
		pthread_mutex_unlock(&blued_g.bond_db_lock);
		/*
		 * Open the responder SMP channel for BONDED peers too: a
		 * bonded central that lost its keys must be able to
		 * re-initiate pairing, and without a listening socket its
		 * Pairing Request had no consumer, so such a peer could
		 * never re-pair.  Accepting the request is safe -- the key
		 * store refuses forbidden overwrites
		 * (smp_bond_is_downgrade(), Core Spec Vol 3 Part H
		 * §2.4.2.4) and the PAIRABLE gate still applies.
		 */
		bonded = bond != NULL;
		if (bonded)
			LOG_HOGP(2, "bonded peer: SMP responder armed for "
			    "possible re-pair");
		{
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

				pfd.fd = smp_fd;
				pfd.events = POLLIN;
				pr = poll(&pfd, 1, bonded ?
				    BLUED_SMP_BONDED_POLL_MS :
				    BLUED_SMP_RESPOND_POLL_MS);
				if (pr > 0) {
					periph_smp_run(conn, adp, smp_fd);
				} else if (pr == 0 && bonded) {
					/*
					 * Nothing pending now.  Hand the open
					 * channel to the connection; the event
					 * loop registers it in
					 * blued_conn_register() and dispatches
					 * any later Pairing Request to the
					 * late-pairing worker.
					 */
					conn->smp_fd = smp_fd;
					LOG_HOGP(2, "bonded peer: no immediate "
					    "pairing request, SMP responder "
					    "left armed");
				} else {
					if (pr == 0)
						LOG_HOGP(2, "no pairing "
						    "request, skipping SMP");
					close(smp_fd);
				}
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
			uint8_t restore_hash[16];
			bool db_changed;
			int j, k;

			smp_bond_restore_cccds(bond, ac);
			/*
			 * The GATT database may have changed since the bond
			 * stored these CCCDs (services removed, handles
			 * reused): drop any restored entry whose handle no
			 * longer names a CCCD, or a stale subscription would
			 * silently attach to whatever attribute now owns the
			 * handle.  gatt_db_lock nests legally inside
			 * bond_db_lock here (see the Service Changed block
			 * below).  The value-level residual (same handle, a
			 * DIFFERENT characteristic's CCCD) is covered by
			 * Robust Caching / Service Changed.
			 */
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			/*
			 * C3-D29: "is it still a CCCD?" is far too weak.  If
			 * the database changed at all since this bond stored
			 * its subscriptions, a recycled handle can be a CCCD
			 * again while belonging to a completely different
			 * characteristic -- and the peer would be silently
			 * subscribed to it.  The bond already carries the
			 * Database Hash it last saw: on any mismatch drop
			 * EVERY restored CCCD and let the peer resubscribe
			 * after the Service Changed indication sent below.
			 * (A bond with no stored hash predates hash tracking
			 * and gets the same treatment.)
			 */
			/*
			 * Both sides of this comparison are in COMPUTATION
			 * order (raw AES-CMAC, most significant octet first):
			 * bond->db_hash is stored and persisted that way and
			 * attdb_compute_db_hash() produces it that way, so the
			 * Database Hash wire byte order (gatt.h) cannot affect
			 * the result.  That is deliberate -- flipping the knob
			 * must not invalidate every bond in the database.
			 */
			attdb_compute_db_hash(&periph_gatt_db, restore_hash);
			db_changed = !bond->has_db_hash ||
			    memcmp(bond->db_hash, restore_hash, 16) != 0;
			k = 0;
			for (j = 0; !db_changed && j < ac->cccd_count; j++) {
				struct att_attr *ra;

				ra = attdb_find_by_handle(&periph_gatt_db,
				    ac->cccds[j].handle);
				if (ra == NULL || ra->uuid16 != GATT_UUID_CCCD)
					continue;
				ac->cccds[k++] = ac->cccds[j];
			}
			ac->cccd_count = k;
			pthread_mutex_unlock(&blued_g.gatt_db_lock);
			if (db_changed)
				LOG_HOGP(1, "GATT database changed since "
				    "bonding; dropped all restored CCCDs");
			else
				LOG_HOGP(1, "restored %d CCCD(s) for bonded "
				    "device", k);
		}

		/* Restore CSRK and sign counter for Signed Write verification */
		periph_restore_signed_write(ac, bond);

		/*
		 * Same bond resolution settles the Table 10.2 column for ATT
		 * error selection while this reconnected link is still
		 * unencrypted: an LTK on file means "go and encrypt" (0x0F),
		 * none means "go and pair" (0x05).  Assigned unconditionally so
		 * an unbonded peer cannot inherit a stale true (att.h,
		 * att_check_read_perm()).
		 */
		ac->has_peer_key = (bond != NULL && bond->has_ltk);

		/*
		 * Service Changed indication for bonded devices.
		 * If the server's GATT database has changed since this
		 * client last connected (db_hash mismatch), send a
		 * Service Changed indication so the client invalidates
		 * its attribute cache (Core Spec Vol 3 Part G 2.5.2,
		 * 7.1).
		 */
		/*
		 * periph_gatt_db is guarded by gatt_db_lock, but this worker holds
		 * only bond_db_lock.  The main thread mutates the DB in place under
		 * gatt_db_lock (attdb_copy on GATT_COMMIT, attdb_set_char_value on
		 * SET_NAME), so reading/hashing it here without gatt_db_lock can see
		 * a half-copied DB and persist a torn Database Hash into the bond.
		 *
		 * Hold gatt_db_lock across ONLY the DB reads -- the Database Hash
		 * computation and the Service Changed handle lookup (a sink, legally
		 * nested inside bond_db_lock; neither callee re-acquires it).  The
		 * Service Changed indication is a BLOCKING socket send (bounded by
		 * SO_SNDTIMEO) and the bond commit is a disk write; both run after
		 * the lock is dropped so a peer that stalls its L2CAP TX cannot
		 * freeze the main event loop, which takes the same gatt_db_lock
		 * around every ATT dispatch.
		 */
		if (bond != NULL) {
			struct smp_bond previous = *bond;
			uint8_t cur_hash[16];
			uint16_t sc_handle = 0, cccd_handle = 0;
			uint8_t sc_perms = 0;
			bool send_sc = false, first_hash = false;

			/*
			 * Stored and computed hashes are both in computation
			 * order; no wire-order conversion belongs here (see
			 * the restore path above and gatt.h).
			 */
			pthread_mutex_lock(&blued_g.gatt_db_lock);
			if (bond->has_db_hash) {
				attdb_compute_db_hash(&periph_gatt_db, cur_hash);
				if (memcmp(bond->db_hash, cur_hash, 16) != 0) {
					send_sc = true;
					(void)gatt_service_changed_lookup(
					    &periph_gatt_db, &sc_handle,
					    &cccd_handle, &sc_perms);
				}
			} else {
				/*
				 * First connection after bonding -- snapshot the
				 * server's current db_hash so future reconnects
				 * can detect changes.
				 */
				attdb_compute_db_hash(&periph_gatt_db,
				    bond->db_hash);
				first_hash = true;
			}
			pthread_mutex_unlock(&blued_g.gatt_db_lock);

			if (send_sc) {
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
				    sc_handle, cccd_handle, sc_perms, 0x0001,
				    0xFFFF) == 0) {
					memcpy(bond->db_hash, cur_hash, 16);
					if (smp_bond_db_commit_bond(
					    blued_g.bond_db, bond,
					    &previous) != 0)
						warnx("saving peripheral "
						    "database hash");
				}
			} else if (first_hash) {
				bond->has_db_hash = true;
				if (smp_bond_db_commit_bond(blued_g.bond_db,
				    bond, &previous) == 0)
					LOG_GATT(1, "saved server db_hash for "
					    "bonded device");
				else
					warnx("saving peripheral database "
					    "hash");
			}
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
		if (l2cap_conn_param_update_req(conn->att_fd,
			    (const uint8_t *)&adp->addr,
			    (const uint8_t *)&conn->dst, conn->addr_type,
			    24, 40, 0, 200) < 0 && blued_verbose >= 2)
			warn("L2CAP conn param update");
	}

	/*
	 * Expose the connection to the event loop.  Past blued_conn_register()
	 * conn may be freed at any moment, so we only signal success on the
	 * (global) setup pipe and return -- no further conn/ac access.
	 *
	 * C3-M5: register FIRST, become ACTIVE only once it succeeded, exactly
	 * as the central twin does (blued_central.c, finding 86).  Flipping
	 * ACTIVE before a failed register left an ACTIVE connection with no
	 * registered bearers, and put blued_periph_setup_fail() on a collision
	 * course with a main-thread teardown without the CONNECTING state's
	 * deferral protection.  The idle timeout stays armed BEFORE the
	 * register, as it always was, so the main thread can never race this
	 * one on conn->idle_timer; only the ACTIVE flip moves after it.
	 */
	blued_idle_arm(conn);
	if (blued_conn_register(conn) < 0) {
		warnx("peripheral conn register failed");
		blued_idle_disarm(conn);
		blued_periph_setup_fail(conn);
		return (NULL);
	}
	blued_conn_set_state(conn, BLUED_CONN_ACTIVE);

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
					uint16_t du = desc->uuid16;

					/*
					 * C3-D30: apply the same three checks
					 * the ctl path enforces
					 * (ctl_gatt_add_desc_result).  A
					 * config block must not be able to
					 * declare a reserved GATT declaration
					 * type, nor a mis-sized 0x2902/0x2B29
					 * whose stored length disagrees with
					 * the per-connection state the server
					 * actually serves from.
					 */
					if (du == 0)
						(void)attdb_uuid128_base_alias(
						    desc->uuid128, &du);
					if ((du >= 0x2800 && du <= 0x2803) ||
					    (du == GATT_UUID_CCCD &&
					    desc->value_len != 2) ||
					    (du == 0x2B29 &&
					    desc->value_len != 1)) {
						LOG_ATT(0, "config service "
						    "'%s': rejected reserved "
						    "or mis-sized descriptor "
						    "0x%04x", svc->name, du);
						continue;
					}

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
	 * Wire site 1 of 4 (see gatt.h): the published octets follow the
	 * configured byte order.
	 */
	gatt_db_publish_hash(db);

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
