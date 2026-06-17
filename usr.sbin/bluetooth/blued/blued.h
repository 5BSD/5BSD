/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 * All rights reserved.
 */

#ifndef _BLUED_H_
#define _BLUED_H_

#include <sys/queue.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <bluetooth.h>

/* Forward declarations */
struct att_db;

/* Forward declarations (att/smp/hogp) */
struct att_conn;
struct smp_conn;
struct smp_bond_db;
struct hogp_device;

#define BLUED_ROLE_CENTRAL	0
#define BLUED_ROLE_PERIPHERAL	1

#define BLUED_MAX_ADAPTERS	8
#define BLUED_MAX_CONNS		16
#define BLUED_MAX_CTL		8
#define BLUED_SOCK_POOL		8

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
	int			reconnect_timer; /* kqueue timer ident */
	atomic_bool		needs_cleanup;	/* thread requests main-thread free */
	atomic_bool		needs_readvertise; /* thread requests main-thread re-adv */
	LIST_ENTRY(blued_conn)	entries;
};

#define BLUED_CONN_IDLE		0
#define BLUED_CONN_CONNECTING	1
#define BLUED_CONN_DISCOVERING	2
#define BLUED_CONN_ACTIVE	3
#define BLUED_CONN_RECONNECTING	4

struct blued_ctl_client {
	int			fd;
	char			buf[256];
	size_t			buflen;
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
	LIST_HEAD(, blued_ctl_client) ctl_clients;
	/* Pre-allocated socket pool for Capsicum */
	int			att_pool[BLUED_SOCK_POOL];
	int			att_pool_next;
	int			smp_pool[4];
	int			smp_pool_next;
	int			setup_pipe[2];	/* self-pipe for thread->main signaling */
	int			periph_listen_fd; /* peripheral ATT listen socket, -1 if not active */
	bool			periph_active;	/* peripheral mode enabled */
};

extern struct blued_ctx blued_g;

/* Tag values for kevent udata to identify fd type */
extern const int _blued_kq_ctl_tag;
#define BLUED_KQ_CTL_LISTEN	((void *)(uintptr_t)&_blued_kq_ctl_tag)

extern const int _blued_kq_setup_pipe_tag;
#define BLUED_KQ_SETUP_PIPE	((void *)(uintptr_t)&_blued_kq_setup_pipe_tag)

extern const int _blued_kq_periph_listen_tag;
#define BLUED_KQ_PERIPH_LISTEN	((void *)(uintptr_t)&_blued_kq_periph_listen_tag)

/* Central setup thread entry point — used by blued.c and ctl.c */
void	*blued_conn_setup_central(void *arg);

/* Peripheral setup thread entry point */
void	*blued_conn_setup_peripheral(void *arg);

#endif /* _BLUED_H_ */
