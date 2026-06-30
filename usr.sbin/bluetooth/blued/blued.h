/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_H_
#define _BLUED_H_

#include <sys/queue.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <bluetooth.h>

extern atomic_int blued_verbose;
extern atomic_bool blued_shutting_down;

/* Forward declarations */
struct att_db;
extern struct att_db periph_gatt_db;

/* Forward declarations (att/smp/hogp) */
struct att_conn;
struct smp_conn;
struct smp_bond_db;
struct hogp_device;

#define BLUED_ROLE_CENTRAL	0
#define BLUED_ROLE_PERIPHERAL	1

#define BLUED_MAX_CONNS		16
#define BLUED_MAX_CTL		8
#define BLUED_SOCK_POOL_DEFAULT	8
#define BLUED_SOCK_POOL_MAX	64

struct blued_adapter {
	int			hci_fd;
	char			name[16];	/* "ubt0" */
	bdaddr_t		addr;
	uint64_t		le_features;
	bool			active;
	LIST_ENTRY(blued_adapter) entries;
};

struct blued_conn {
	int			att_fd;
	struct att_conn		*att;		/* from att.h */
	struct hogp_device	*hogp;		/* NULL if not HOGP */
	bdaddr_t		dst;
	uint8_t			addr_type;
	uint16_t		con_handle;
	struct blued_adapter	*adapter;
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
	atomic_bool		needs_cleanup;	/* thread requests main-thread free */
	atomic_bool		needs_readvertise; /* thread requests main-thread re-adv */
	LIST_ENTRY(blued_conn)	entries;
};

#define BLUED_CONN_IDLE		0
#define BLUED_CONN_CONNECTING	1
#define BLUED_CONN_ACTIVE	2
#define BLUED_CONN_RECONNECTING	3

struct ctl_subscription {
	bdaddr_t		addr;
	uint16_t		handle;
};
#define CTL_MAX_SUBSCRIPTIONS	16

struct blued_ctl_client {
	int			fd;
	char			buf[256];
	size_t			buflen;
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
	int			vhid_ctl_fd;
	LIST_HEAD(, blued_adapter) adapters;
	LIST_HEAD(, blued_conn)    conns;
	pthread_rwlock_t	conns_lock;	/* protects conns list */
	pthread_mutex_t		bond_db_lock;	/* protects bond_db array */
	pthread_mutex_t		gatt_db_lock;	/* protects periph_gatt_db */
	LIST_HEAD(, blued_ctl_client) ctl_clients;
	pthread_mutex_t		ctl_clients_lock;	/* protects ctl_clients list */
	/* Pre-allocated socket pool for Capsicum */
	int			*att_pool;	/* pre-allocated L2CAP sockets */
	int			att_pool_size;	/* number of slots */
	int			att_pool_next;
	pthread_t		main_thread;	/* main event loop thread (for assert) */
	int			setup_pipe[2];	/* self-pipe for thread->main signaling */
	int			periph_listen_fd; /* peripheral ATT listen socket, -1 if not active */
	bool			periph_active;	/* peripheral mode enabled */

	/* Passkey/numeric comparison reply synchronization (SMP <-> ctl) */
	pthread_mutex_t		passkey_lock;
	pthread_cond_t		passkey_cond;
	uint32_t		passkey_reply;
	int			passkey_reply_status; /* 0=pending, 1=replied, -1=timeout */
	int			numcmp_reply_status;  /* 0=pending, 1=replied, -1=timeout */
	bool			numcmp_reply;
	bdaddr_t		passkey_target;	/* device address for current passkey/numcmp */
};

extern struct blued_ctx blued_g;

/* Tag values for kevent udata to identify fd type */
extern const int _blued_kq_ctl_tag;
#define BLUED_KQ_CTL_LISTEN	((void *)(uintptr_t)&_blued_kq_ctl_tag)

extern const int _blued_kq_setup_pipe_tag;
#define BLUED_KQ_SETUP_PIPE	((void *)(uintptr_t)&_blued_kq_setup_pipe_tag)

extern const int _blued_kq_periph_listen_tag;
#define BLUED_KQ_PERIPH_LISTEN	((void *)(uintptr_t)&_blued_kq_periph_listen_tag)

extern const int _blued_kq_rpa_timer_tag;
#define BLUED_KQ_RPA_TIMER	((void *)(uintptr_t)&_blued_kq_rpa_timer_tag)

/* Central setup thread entry point — used by blued.c and ctl.c */
void	*blued_conn_setup_central(void *arg);

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
