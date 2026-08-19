/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_H_
#define _BLUED_H_

#include <sys/queue.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <bluetooth.h>

#include "ipc_proto.h"
#include "blued_devmgr.h"

struct service_context;		/* libservice provider handles (opaque) */
struct service_provider;
struct service_listener;

extern atomic_int blued_verbose;
extern atomic_bool blued_shutting_down;

/* Forward declarations */
struct att_db;
extern struct att_db periph_gatt_db;

/* Forward declarations (att/smp/hogp) */
struct att_conn;
struct smp_conn;
struct smp_bond;
struct smp_bond_db;
struct hogp_device;
struct hci_adv_config;

#define BLUED_ROLE_CENTRAL	0
#define BLUED_ROLE_PERIPHERAL	1

#define BLUED_MAX_CONNS		16
#define BLUED_MAX_CTL		8
#define BLUED_CTL_TX_MAX	(64 * 1024)

/*
 * Upper bound on concurrently managed HCI adapters.  Each adapter owns
 * its own HCI socket, kqueue registration, and per-adapter link state;
 * clients address a specific adapter by its stable index (0 == primary).
 */
#define BLUED_MAX_ADAPTERS	8
#define BLUED_LOCAL_ID_CACHE	BLUED_MAX_CONNS

struct blued_local_identity {
	bdaddr_t		peer;
	bdaddr_t		peer_rpa;
	bdaddr_t		local;
	uint16_t		handle;
	uint64_t		controller_epoch;
	uint8_t		peer_type;
	uint8_t		local_type;
	bool			local_valid;
	bool			valid;
};

#define BLUED_EXT_ADV_SET_MAX 16
#define BLUED_PERIODIC_SYNC_MAX 0x0f00
#define BLUED_PERIODIC_SYNC_BYTES (BLUED_PERIODIC_SYNC_MAX / 8)
struct blued_ext_adv_set {
	bool			used;
	bool			configured;
	bool			enabled;
	uint8_t			handle;
	uint16_t		event_props;
	uint32_t		interval_min;
	uint32_t		interval_max;
	uint8_t			own_addr_type;
	uint8_t			filter_policy;
	uint8_t			primary_phy;
	uint8_t			secondary_phy;
	uint8_t			channel_map;
	int8_t			tx_power;
	uint8_t			peer_addr_type;
	uint8_t			peer_addr[6];
};

struct blued_adapter {
	int			hci_fd;
	int			index;		/* stable index; 0 == primary */
	char			name[16];	/* "ubt0" */
	bdaddr_t		addr;
	bdaddr_t		random_addr;	/* current controller Random_Address */
	bool			random_addr_valid;
	uint64_t		le_features;
	bool			active;
	uint64_t		controller_epoch; /* advanced after every HCI Reset */
	/*
	 * Operator runtime settings (common adapter-settings parity).  powered gates
	 * whether the controller is up (POWER on|off); a POWER-off quiesces
	 * advertising/scanning and drops this adapter's links but keeps the
	 * HCI socket open so POWER on can re-init.  discoverable reflects the
	 * DISCOVERABLE verb's general/limited discoverable advertising state.
	 */
	bool			powered;	/* default true at init */
	bool			power_quiescing;
	bool			discoverable;
	bool			disc_limited;	/* limited vs general disc mode */
	bool			privacy;	/* runtime LE privacy (RPA) enabled */
	/*
	 * Transport selected for advertising set 0.  Controller capability is not
	 * sufficient here: a caller may explicitly force legacy advertising on an
	 * extended-capable controller.  Data and enable commands must use the same
	 * procedure that successfully accepted the parameters.
	 */
	bool			adv_configured;
	bool			adv_use_extended;
	bool			adv_enabled;
	/* Primary advertising payload cache and DISCOVERABLE overlay snapshot. */
	uint8_t			primary_adv_data[31];
	uint8_t			primary_adv_data_len;
	bool			primary_adv_data_valid;
	uint8_t			primary_scan_rsp[31];
	uint8_t			primary_scan_rsp_len;
	bool			primary_scan_rsp_valid;
	bool			disc_saved_valid;
	bool			disc_saved_configured;
	bool			disc_saved_use_extended;
	bool			disc_saved_enabled;
	uint8_t			disc_saved_adv_data[31];
	uint8_t			disc_saved_adv_data_len;
	bool			disc_saved_adv_data_valid;
	uint8_t			disc_saved_scan_rsp[31];
	uint8_t			disc_saved_scan_rsp_len;
	bool			disc_saved_scan_rsp_valid;
	bool			periodic_adv_enabled;
	bool			periodic_sync_pending;
	uint8_t			periodic_syncs[BLUED_PERIODIC_SYNC_BYTES];
	struct hci_adv_config	*adv_config;
	/* Configured non-primary extended sets, independent of their owner. */
	struct blued_ext_adv_set ext_adv_sets[BLUED_EXT_ADV_SET_MAX];
	/* Resumable host-RPA rotation, one completion bit per address domain. */
	bool			rpa_pending;
	bool			rpa_pending_global;
	bool			rpa_pending_primary;
	bool			rpa_restore_legacy;
	bool			rpa_restore_primary;
	bool			rpa_pending_ext[BLUED_EXT_ADV_SET_MAX];
	bool			rpa_restore_ext[BLUED_EXT_ADV_SET_MAX];
	uint8_t			rpa_pending_addr[6];
	unsigned int		rpa_retry_count;
	/*
	 * Mesh bearer (broker step C): true while this adapter runs the
	 * always-on passive scan that feeds mesh-adv subscribers.  Toggled by
	 * the mesh subscriber refcount (ctl.c); a client SCAN burst that
	 * momentarily reprograms the scanner re-asserts it via
	 * blued_mesh_scan_resume().
	 */
	bool			mesh_scan_active;
	int			periph_listen_fd;	/* exact-address ATT listener */
	int			eatt_listen_fd;	/* exact-address EATT listener */
	uintptr_t		discoverable_timer;
	unsigned int		discoverable_stop_retries;
	unsigned int		readvertise_retries;
	uintptr_t		readvertise_timer;
	/* Host mirror of this controller's independent LE resolving list. */
	struct blued_reslist	reslist;
	/* Enhanced Connection Complete metadata that arrived before accept(). */
	struct blued_local_identity local_ids[BLUED_LOCAL_ID_CACHE];
	unsigned int		local_id_next;
	LIST_ENTRY(blued_adapter) entries;
};

struct blued_conn {
	int			att_fd;
	struct att_conn		*att;		/* from att.h */
	struct hogp_device	*hogp;		/* NULL if not HOGP */
	bdaddr_t		dst;
	uint8_t			addr_type;
	bdaddr_t		local_addr;	/* actual address used on this LE link */
	uint8_t			local_addr_type; /* internal BDADDR_LE_* domain */
	bool			local_addr_from_hci;
	bool			local_addr_resolved;
	uint8_t			local_own_addr_type; /* HCI Own_Address_Type, current attempt */
	uint16_t		con_handle;
	uint64_t		controller_epoch; /* adapter epoch that created this link */
	bool			con_handle_valid; /* 0x0000 is a valid HCI handle */
	struct blued_adapter	*adapter;
	bool			announced;	/* CONNECTED event emitted for this link */
	pthread_mutex_t		pairing_lock;
	pthread_cond_t		pairing_cond;
	uint32_t		passkey_reply;
	int			passkey_reply_status;
	int			numcmp_reply_status;
	bool			numcmp_reply;
	atomic_int		state;		/* BLUED_CONN_* */
	int			role;		/* BLUED_ROLE_CENTRAL or BLUED_ROLE_PERIPHERAL */
	struct att_conn		*att_owned;	/* heap-allocated att_conn (peripheral) */
	struct att_db		*gatt_db;	/* GATT db for peripheral, NULL for central */
	bool			reconnect;	/* auto-reconnect on disconnect */
	int			reconnect_delay;/* current backoff seconds */
	uintptr_t		reconnect_timer; /* kqueue timer ident, 0 if none */
	uintptr_t		idle_timer;	/* kqueue idle timeout ident, 0 if none */
	uint16_t		conn_interval;	/* units of 1.25ms */
	uint16_t		conn_latency;	/* slave latency */
	uint16_t		supervision_timeout; /* units of 10ms */
	/*
	 * Operator-requested initial connection parameters (from CONNECT
	 * <addr> ... itvl_min=/itvl_max=/latency=/timeout=/tx_phy=/rx_phy=).
	 * Applied by the central setup thread once the link is up, in place of
	 * the daemon defaults.  The has_* flags gate each group so a plain
	 * CONNECT keeps the historical defaults.
	 */
	bool			has_req_conn_params;
	bool			has_req_phy;
	uint16_t		req_itvl_min;	/* units of 1.25ms */
	uint16_t		req_itvl_max;	/* units of 1.25ms */
	uint16_t		req_latency;	/* slave latency */
	uint16_t		req_timeout;	/* units of 10ms */
	uint8_t			req_tx_phys;	/* PHY mask, 0 = no preference */
	uint8_t			req_rx_phys;	/* PHY mask, 0 = no preference */
	atomic_bool		needs_cleanup;	/* thread requests main-thread free */
	atomic_bool		needs_readvertise; /* thread requests main-thread re-adv */
	atomic_uint		att_ops_active;	/* blocking transactions across ATT bearers */
	atomic_bool		disconnect_pending;
	/*
	 * Reference count guarding the lifetime of this structure.  The
	 * global connection list holds one reference; each detached setup
	 * thread that operates on the connection holds another for its
	 * duration.  The heap object is released only when the count
	 * reaches zero, so a teardown that races a running setup thread
	 * cannot free memory still in use by that thread.
	 */
	atomic_int		refcount;
	/*
	 * Count of in-flight detached workers accounted for this connection in
	 * the global setup_workers barrier (finding H-L6).  A per-conn boolean
	 * undercounted when two workers overlapped on the same conn (the second
	 * start was swallowed, then the first finish cleared the flag and the
	 * barrier could drop to zero with a worker still running).  A counter
	 * tracks each worker exactly once.
	 */
	atomic_int		setup_worker_count;
	LIST_ENTRY(blued_conn)	entries;
};

/* Source compatibility for diagnostics/tests written before EATT parallelism. */
#define att_op_busy att_ops_active

#define BLUED_CONN_IDLE		0
#define BLUED_CONN_CONNECTING	1
#define BLUED_CONN_ACTIVE	2
#define BLUED_CONN_RECONNECTING	3

struct ctl_subscription {
	bdaddr_t		addr;
	uint16_t		handle;
	uint16_t		cccd_handle;
	uint16_t		cccd_value;
	uint8_t		addr_type;	/* internal BDADDR_LE_* domain */
	uint8_t		adapter_index;
	/* Visible during CCCD enable so the peer's first value can be routed. */
	bool			pending;	/* not established shared ownership yet */
};
#define CTL_MAX_SUBSCRIPTIONS	16

/*
 * Per-characteristic data-path acquire (the common GATT-characteristic
 * AcquireNotify / AcquireWrite pattern; Core Spec Vol 3 Part G notify/write).  A privileged
 * fd-passing client is handed one end of a SEQPACKET socketpair over SCM_RIGHTS
 * and the daemon keeps the other end: a NOTIFY acquire copies each incoming
 * notification/indication value for the characteristic to the client as one
 * datagram; a WRITE acquire turns each datagram the client sends into an ATT
 * Write-Without-Response PDU to the characteristic.  This moves a high-rate
 * GATT data path off the per-notification IPC event stream onto a direct,
 * capability-scoped fd.  One acquire per (connection, characteristic, direction).
 */
#define CTL_ACQ_NOTIFY		0
#define CTL_ACQ_WRITE		1

struct ctl_acquire {
	bdaddr_t		addr;		/* peer address = connection key */
	uint16_t		handle;		/* characteristic value handle */
	uint8_t			dir;		/* CTL_ACQ_NOTIFY | CTL_ACQ_WRITE */
	uint8_t			addr_type;
	uint8_t			adapter_index;
	uint16_t		mtu;		/* ATT MTU captured at acquire */
	int			daemon_fd;	/* daemon-side SEQPACKET end */
	struct blued_ctl_client *client;	/* owner, for client-close teardown */
	LIST_ENTRY(ctl_acquire)	entries;
};

struct blued_ctl_tx {
	uint8_t			*data;
	size_t			 len;
	size_t			 off;
	int			 passed_fd;	/* SCM_RIGHTS fd, or -1 */
	STAILQ_ENTRY(blued_ctl_tx) entries;
};

STAILQ_HEAD(blued_ctl_tx_head, blued_ctl_tx);

struct blued_ctl_client {
	int			fd;
	uint64_t		generation;	/* guards async replies against fd reuse */
	/*
	 * Framed IPC protocol state (length-prefixed binary, see ipc_proto.h).
	 * The daemon speaks the framed protocol only; a client negotiates
	 * version and features with an opening HELLO frame.
	 */
	bool			handshaked;	/* HELLO completed */
	bool			wants_events;	/* asynchronous events accepted */
	bool			wants_fdpass;	/* fd handoff accepted */
	bool			wants_mesh;	/* mesh bearer accepted */
	bool			mesh_sub;	/* active MESH_ADV subscriber */
	/* Peer credentials from getpeereid() at accept time (privilege tiers) */
	bool			peer_known;	/* getpeereid() succeeded */
	uid_t			peer_uid;
	gid_t			peer_gid;
	/* Framed receive accumulation buffer (header + payload) */
	uint8_t			rxbuf[IPC_HDR_SIZE + IPC_MAX_PAYLOAD];
	size_t			rxlen;
	/* Ordered output queue for partial nonblocking stream writes. */
	struct blued_ctl_tx_head	txq;
	size_t			tx_queued;
	bool			tx_write_enabled;
	bool			tx_error;
	bool			kq_registered;
	uint32_t		active_request_id;
	struct ctl_subscription	subs[CTL_MAX_SUBSCRIPTIONS];
	int			nsubs;
	/* Rate limiting for blocking ATT commands (DISCOVER/READ/WRITE/HOGP_*) */
	int			blocking_count;	/* blocking cmds in current window */
	time_t			blocking_window; /* window start (monotonic seconds) */
	LIST_ENTRY(blued_ctl_client) entries;
};

/* Global daemon context */
struct blued_ctx {
	int			kq;		/* kqueue fd */
	int			ctl_fd;		/* control socket */
	struct smp_bond_db	*bond_db;
	int			bond_fd;
	int			bond_dirfd;	/* parent directory for atomic saves */
	int			bond_lockfd;	/* lifetime singleton lock for bond DB */
	int			vhid_ctl_fd;
	LIST_HEAD(, blued_adapter) adapters;
	LIST_HEAD(, blued_conn)    conns;
	pthread_rwlock_t	conns_lock;	/* protects conns list */
	pthread_mutex_t		bond_db_lock;	/* protects bond_db array */
	pthread_mutex_t		gatt_db_lock;	/* protects periph_gatt_db */
	/*
	 * Serializes every mutation of each adapter's resolving-list shadow
	 * (adapter->reslist) and the paired controller resolving-list HCI
	 * programming (finding 92).  Setup threads sync the list after pairing
	 * while the dispatch thread services RESOLV_ADD/REMOVE/CLEAR and UNBOND;
	 * without this the count/memmove race and the shadow diverges from the
	 * controller.
	 */
	pthread_mutex_t		reslist_lock;
	/*
	 * Serializes writes to a connection's ATT security state
	 * (att->encrypted / authenticated / enc_key_size) and the EATT bearer
	 * teardown that rides on an encryption transition (finding 95).  Three
	 * threads write these fields: the HCI Encryption-Change / Key-Refresh
	 * handlers on the event loop, the GATT worker's ctl_elevate_security(),
	 * and the setup thread's post-pairing gate.  A read lock on conns_lock
	 * gives no mutual exclusion between them.
	 */
	pthread_mutex_t		att_sec_lock;
	LIST_HEAD(, blued_ctl_client) ctl_clients;
	pthread_mutex_t		ctl_clients_lock;	/* protects ctl_clients list */
	atomic_uint		setup_workers;	/* detached connection workers */
	/*
	 * Active per-characteristic AcquireNotify/AcquireWrite fds.  Touched only
	 * on the main event-loop thread (acquire verbs, notification routing, fd
	 * pump, teardown), so it shares ctl_clients_lock rather than adding a lock.
	 */
	LIST_HEAD(, ctl_acquire) ctl_acquires;
	pthread_t		main_thread;	/* main event loop thread (for assert) */
	int			setup_pipe[2];	/* self-pipe for thread->main signaling */
	bool			periph_active;	/* peripheral mode enabled */

	/*
	 * Preferred ATT MTU requested in the Exchange MTU procedure (SET_MTU;
	 * Core Spec Vol 3 Part F §3.4.2).  0 selects the compile-time maximum.
	 */
	uint16_t		att_preferred_mtu;

	int			config_fd;	/* pre-opened config file for SIGHUP reload */
	int			capprotect_fd;	/* /dev/cap_rt capprotect instance */
	int			persist_dirfd;	/* pre-opened state dir for blued_persist (openat/renameat) */

	/* serviced integration (provider libservice API). */
	struct service_context	*svc_ctx;
	struct service_provider	*svc_provider;
	struct service_listener	*svc_listener;	/* exposed name; dormant */

};

extern struct blued_ctx blued_g;

/*
 * These are inline so unit tests which exercise worker-spawning modules do
 * not need to link the daemon's main translation unit merely to account for
 * detached workers.  A connection can own at most one setup worker at once.
 */
static inline void
blued_setup_worker_start(struct blued_conn *conn)
{

	/*
	 * Finding H-L6: count every worker (overlapping workers on one conn
	 * included) so the shutdown barrier is accurate.
	 */
	atomic_fetch_add(&conn->setup_worker_count, 1);
	atomic_fetch_add(&blued_g.setup_workers, 1);
}

static inline void
blued_setup_worker_finish(struct blued_conn *conn)
{
	int c = atomic_load(&conn->setup_worker_count);

	/*
	 * Decrement only while this conn still has a counted worker, so a stray
	 * finish (no matching start) cannot underflow the global barrier.
	 */
	while (c > 0 && !atomic_compare_exchange_weak(&conn->setup_worker_count,
	    &c, c - 1))
		;
	if (c > 0)
		atomic_fetch_sub(&blued_g.setup_workers, 1);
}

/* Tag values for kevent udata to identify fd type */
extern const int _blued_kq_ctl_tag;
#define BLUED_KQ_CTL_LISTEN	((void *)(uintptr_t)&_blued_kq_ctl_tag)

/* AcquireNotify/AcquireWrite daemon-side SEQPACKET fds (identified by fd). */
extern const int _blued_kq_acquire_tag;
#define BLUED_KQ_ACQUIRE	((void *)(uintptr_t)&_blued_kq_acquire_tag)

extern const int _blued_kq_setup_pipe_tag;
#define BLUED_KQ_SETUP_PIPE	((void *)(uintptr_t)&_blued_kq_setup_pipe_tag)

extern const int _blued_kq_rpa_timer_tag;
#define BLUED_KQ_RPA_TIMER	((void *)(uintptr_t)&_blued_kq_rpa_timer_tag)

extern const int _blued_kq_rpa_retry_tag;
#define BLUED_KQ_RPA_RETRY	((void *)(uintptr_t)&_blued_kq_rpa_retry_tag)

/*
 * One-shot timer that re-enables the control-socket listener after it was
 * disabled on fd exhaustion (finding C-m1).  Timer ident is blued_g.ctl_fd
 * (distinct namespace from the EVFILT_READ filter on the same fd).
 */
extern const int _blued_kq_ctl_accept_retry_tag;
#define BLUED_KQ_CTL_ACCEPT_RETRY \
	((void *)(uintptr_t)&_blued_kq_ctl_accept_retry_tag)
void	blued_ctl_accept_retry_enable(void);

/* Central setup thread entry point — used by blued.c and ctl.c */
void	*blued_conn_setup_central(void *arg);

/*
 * Start (or restart) SMP pairing with an already-connected central-role peer
 * and, on success, open the ATT security gate and refresh the peer's
 * controller resolving-list entry.  Shared by the reactive path (GATT auth
 * error during connect setup) and the operator key-refresh verb (REKEY): a
 * fresh SMP exchange over the existing link distributes new LTK/IRK/CSRK that
 * atomically replace the peer's bond keys in place (Core Spec Vol 3 Part H
 * §2.4).  Returns 0 on a completed pairing, -1 on failure.
 */
int	blued_central_start_pairing(struct hogp_device *dev,
	    struct blued_conn *conn);

/*
 * Spawn a detached worker that runs blued_central_start_pairing() off the ctl
 * dispatch thread (finding 33).  Returns 0 if the worker was started (the
 * pairing then proceeds asynchronously), -1 if it could not be spawned.  Used
 * by the REKEY and PAIR verbs so a passkey/numcmp prompt can be answered by a
 * concurrent dispatch call instead of deadlocking the blocked event loop.
 */
int	blued_central_start_pairing_async(struct blued_conn *conn);

/*
 * Resolving-list lifecycle (blued.c) — keep the controller resolving list in
 * sync with the bond database incrementally.  add: program a freshly bonded
 * peer's IRK (no-op if the bond carries no IRK, idempotent, bounded).  remove:
 * drop a forgotten peer's IRK on unbond.  Both are best-effort and safe to
 * call with hci_fd < 0.
 */
void	blued_reslist_sync_add(int hci_fd, const struct smp_bond *bond);
void	blued_reslist_sync_remove(int hci_fd, const uint8_t addr[6],
	    uint8_t addr_type);

/*
 * Runtime LE privacy toggle (PRIVACY verb; Core Spec Vol 6 Part B §6.4).  When
 * enabling, (re)programs the controller resolving list from the bond database,
 * sets the RPA rotation timeout, enables address resolution, and switches the
 * scan own-address type to Resolvable Private Address; when disabling, turns
 * address resolution off and reverts to the public address.  Best-effort;
 * returns 0 on success, -1 on a controller error.
 */
int	blued_privacy_set(int hci_fd, bool on);
int	blued_adapter_set_privacy(struct blued_adapter *, bool);
void	blued_primary_adv_cache(struct blued_adapter *, bool,
	    const uint8_t *, uint8_t);
int	blued_set_rpa_timeout(int);
int	blued_ext_adv_set_track(struct blued_adapter *, uint8_t, uint16_t,
	    uint32_t, uint32_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
	    int8_t, uint8_t, const uint8_t *);
void	blued_ext_adv_set_enabled(struct blued_adapter *, uint8_t, bool);
void	blued_ext_adv_set_untrack(struct blued_adapter *, uint8_t);
void	blued_ctl_adapter_reset(struct blued_adapter *);
void	blued_ctl_adv_set_terminated(struct blued_adapter *, uint8_t handle);
bool	blued_ext_adv_set_used(const struct blued_adapter *, uint8_t);
int	blued_adv_set_privacy_prepare(struct blued_adapter *, uint8_t);
int	blued_adapter_rotate_rpa(struct blued_adapter *, const uint8_t [6]);
int	blued_rpa_retry_arm(void);
void	blued_rpa_retry_cancel(void);

/*
 * PC8 GATT robust-caching: true when the GATT cache restored from persistent
 * storage holds a matching Database Hash for this peer, so rediscovery on
 * reconnect can be skipped.  Backed by the cache applied at startup (blued.c).
 */
bool	blued_persist_gattcache_reuse(const uint8_t addr[6], uint8_t addr_type,
	    const uint8_t fresh_hash[16]);

/*
 * Runtime resolving-list IRK entries (finding 138).  A RESOLV_ADD with a
 * client-supplied IRK for a non-bonded address is recorded, persisted, and
 * reprogrammed at adapter init; forget/clear track REMOVE/CLEAR.  Called by the
 * ctl resolv handler under blued_g.reslist_lock; _load runs once at init.
 */
void	blued_runtime_resolv_load(void);
void	blued_runtime_resolv_record(const uint8_t addr[6], uint8_t addr_type,
	    const uint8_t irk[16]);
void	blued_runtime_resolv_forget(const uint8_t addr[6], uint8_t addr_type);
void	blued_runtime_resolv_clear(void);

/*
 * Runtime Filter Accept List entries (finding 135).  Operator-added non-bond
 * accept-list entries are recorded in a persisted shadow, programmed on every
 * powered adapter, and reprogrammed at init.  snapshot copies the shadow for
 * the LIST verb.  Called by the ctl accept-list handler.
 */
void	blued_acceptlist_load(void);
int	blued_acceptlist_record(const uint8_t addr[6], uint8_t addr_type);
int	blued_acceptlist_forget(const uint8_t addr[6], uint8_t addr_type);
void	blued_acceptlist_clear_all(void);
uint32_t blued_acceptlist_snapshot(struct blued_persist_accept_entry *out,
	    uint32_t max);
void	blued_acceptlist_reprogram(int hci_fd);

/*
 * Allocate and initialize a hogp_device for a new central connection.
 * Called from ctl.c CONNECT command.  The returned device must be
 * assigned to conn->hogp before spawning blued_conn_setup_central.
 * Returns NULL on failure.
 */
struct hogp_device *blued_hogp_alloc(struct blued_adapter *adp,
		    const uint8_t *addr, uint8_t addr_type, bool reconnect);

/* Peripheral setup thread entry point */
void	*blued_conn_setup_peripheral(void *arg);

/*
 * HOGP Feature report helpers — called from ctl.c.
 *
 * hogp_find_feature_handle: returns the ATT value handle for a Feature
 * report with the given report_id, or 0 if not found.
 */
uint16_t hogp_find_feature_handle(struct blued_conn *conn, uint8_t report_id);

#endif /* _BLUED_H_ */
