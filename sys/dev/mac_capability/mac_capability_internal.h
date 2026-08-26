/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability — framework internals.  Not for service modules.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_INTERNAL_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_INTERNAL_H_

#ifdef _KERNEL

#include "mac_capability.h"

#include <sys/queue.h>
#include <sys/event.h>
#include <sys/counter.h>
#include <sys/taskqueue.h>
#include <sys/_task.h>
#include <vm/uma.h>

/* Framework-internal limits. */
#define	MAC_CAPABILITY_MAX_QUEUED		MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH
					/* default RX queue depth */
#define	MAC_CAPABILITY_MAX_QUEUE_DEPTH	4096	/* max configurable queue depth */
#define	MAC_CAPABILITY_MAX_TX_LIMIT	4096	/* max configurable TX soft limit */
#define	MAC_CAPABILITY_TX_HARD_MULT	4	/* TX hard limit = queue_depth * this */
#define	MAC_CAPABILITY_DEF_INSTANCE_LIMIT	1024	/* default instances per service */
#define	MAC_CAPABILITY_MAX_INSTANCES	(1024 * 1024) /* max instances per service */
#define	MAC_CAPABILITY_MAX_SVC_THREADS	4	/* max taskqueue threads per service */
#define	MAC_CAPABILITY_POLL_TICKS		(hz / 20) /* 50ms refcount poll interval */

/*
 * Fixed-size message — 16384 bytes (4 pages).
 *
 * Layout:
 *   Header:  queue linkage, metadata, 32 fd slots  (2KB reserved)
 *   Payload: inline data buffer                     (14KB)
 *
 * The entire message is a single UMA slab allocation.
 * No malloc for payload or fd arrays.  Anything larger
 * than the payload area must be sent via an attached fd
 * (shared memory).
 */
/*
 * The UMA zone allocates sizeof(struct mac_capability_msg) + MAC_CAPABILITY_MSG_PAYLOAD_SIZE.
 * MAC_CAPABILITY_MSG_PAYLOAD_SIZE is the usable payload area for user data.
 * Anything larger must be sent via an attached fd (shared memory).
 */
#define	MAC_CAPABILITY_MSG_PAYLOAD_SIZE	14336

struct mac_capability_msg {
	/* Queue linkage. */
	STAILQ_ENTRY(mac_capability_msg) cm_link;

	/* Message metadata — kernel-stamped, unforgeable. */
	uint64_t	cm_badge;
	uint64_t	cm_reply_token;
	struct ucred	*cm_cred;
	uint32_t	cm_datalen;
	uint8_t		cm_nfds;

	/* Inline fd slots — 32 max, no separate allocation. */
	struct file	*cm_fds[MAC_CAPABILITY_MAX_FDS];
	struct filecaps	cm_fcaps[MAC_CAPABILITY_MAX_FDS];
	uint8_t		cm_xfer_state[MAC_CAPABILITY_MAX_FDS];
	uint8_t		cm_cloexec_state[MAC_CAPABILITY_MAX_FDS];
	uint8_t		cm_clofork_state[MAC_CAPABILITY_MAX_FDS];
	uint8_t		cm_fde_flags[MAC_CAPABILITY_MAX_FDS];

	/* Inline payload — user data copied directly here. */
	char		cm_data[];  /* sized by UMA zone: MAC_CAPABILITY_MSG_PAYLOAD_SIZE */
};

/* A list of messages detached from an instance queue, freed outside ci_mtx. */
STAILQ_HEAD(mac_capability_msgq, mac_capability_msg);

/* Instance flags (protected by ci_mtx). */
#define	MAC_CAPABILITY_SF_CLOSED		0x0001
#define	MAC_CAPABILITY_SF_REVOKED		0x0002
#define	MAC_CAPABILITY_SF_FINALIZED	0x0004
#define	MAC_CAPABILITY_SF_LINKED		0x0008	/* on service's instance list */
#define	MAC_CAPABILITY_SF_DEAD		(MAC_CAPABILITY_SF_CLOSED | MAC_CAPABILITY_SF_REVOKED)

/* Restriction flags — one-way latch, checked in ioctl handler. */
#define	MAC_CAPABILITY_RF_NO_SEND		0x0001
#define	MAC_CAPABILITY_RF_NO_RECV		0x0002
#define	MAC_CAPABILITY_RF_NO_CALL		0x0004
#define	MAC_CAPABILITY_RF_NO_MINT		0x0008

/*
 * Instance — one per struct file.  Internal layout.
 *
 * Locking:
 *   (I)   Immutable after creation.
 *   (M)   Protected by ci_mtx.
 *   (R)   Protected by refcount (ci_refcnt).
 *   (A)   Atomic operations only (one-way latch).
 *   (L)   Protected by mac_capability_registry_lock (xlock).
 */
struct mac_capability_instance {
	struct mac_capability_service *ci_service;	/* (I) owning service */
	void		*ci_priv;		/* (I) service-private data */
	uint64_t	ci_badge;		/* (I) connection badge */

	struct mac_capability_msgq ci_txq;	/* (M) outbound queue */
	int		ci_txqlen;		/* (M) outbound count */
	struct knlist	ci_rknotes;		/* (M) EVFILT_READ knotes */

	struct mac_capability_msgq ci_rxq;	/* (M) inbound queue */
	int		ci_rxqlen;		/* (M) inbound count */
	int		ci_rxqlimit;		/* (I) max RX depth */
	struct knlist	ci_wknotes;		/* (M) EVFILT_WRITE knotes */

	struct task	ci_task;		/* (I) taskqueue task */
	bool		ci_dispatching;		/* (M) task scheduled or running */
	bool		ci_kick_pending;	/* (M) retry wakeup raced dispatch */
	struct mtx	ci_mtx;			/* instance lock */
	volatile u_int	ci_refcnt;		/* (R) reference count */
	int		ci_flags;		/* (M) MAC_CAPABILITY_SF_* */
	int		ci_restricted;		/* (A) MAC_CAPABILITY_RF_* one-way latch */
	int		ci_inflight;		/* (M) active handler+call count */
	struct thread	*ci_handler_td;		/* (M) current handler thread */

	LIST_ENTRY(mac_capability_instance) ci_svc_link; /* (L) service list link */
};

#define	MAC_CAPABILITY_SVCF_DESTROYING	0x0001

/*
 * Registered service — internal layout.
 *
 * Locking:
 *   (I)   Immutable after mac_capability_service_create.
 *   (L)   Protected by mac_capability_registry_lock (xlock).
 *   (R)   Protected by refcount (csvc_refcnt).
 */
struct mac_capability_service {
	LIST_ENTRY(mac_capability_service) csvc_link;	/* (L) registry list link */
	char		csvc_name[MAC_CAPABILITY_MAXNAME]; /* (I) service name */
	const struct mac_capability_ops *csvc_ops;	/* (I) operation callbacks */
	void		*csvc_arg;		/* (I) callback argument */
	LIST_HEAD(, mac_capability_instance) csvc_instances; /* (L) instance list */
	int		csvc_ninstances;	/* (L) instance count */
	int		csvc_instance_limit;	/* (I) max instances */
	volatile u_int	csvc_refcnt;		/* (R) reference count */
	int		csvc_flags;		/* (L) MAC_CAPABILITY_SVCF_* */
	struct taskqueue *csvc_taskq;		/* (I) async dispatch queue */
	uint32_t	csvc_queue_depth;	/* (I) per-instance RX limit */
	uint32_t	csvc_tx_limit;		/* (I) per-instance TX soft limit */
	uint32_t	csvc_svc_flags;		/* (I) MAC_CAPABILITY_SVC_* from params */
};

/* Globals. */
extern struct sx mac_capability_registry_lock;
LIST_HEAD(mac_capability_service_list, mac_capability_service);
extern struct mac_capability_service_list mac_capability_services;
extern uma_zone_t mac_capability_instance_zone;
extern uma_zone_t mac_capability_msg_zone;
extern counter_u64_t mac_capability_stat_services;
extern counter_u64_t mac_capability_stat_instances;

/* Internal functions. */
int	mac_capability_init(void);
void	mac_capability_uninit(void);
struct mac_capability_service *mac_capability_service_lookup(const char *name);
void	mac_capability_msg_free(struct mac_capability_msg *msg);
struct mac_capability_instance *mac_capability_instance_init(struct mac_capability_service *svc,
	    uint64_t badge);
void	mac_capability_instance_free(struct mac_capability_instance *s);
int	mac_capability_service_reserve(struct mac_capability_service *svc);
void	mac_capability_service_unreserve(struct mac_capability_service *svc);
int	mac_capability_instance_link(struct mac_capability_service *svc, struct mac_capability_instance *s);
int	mac_capability_instance_create(struct mac_capability_service *svc, struct thread *td,
	    uint64_t badge, int *fdp);
void	mac_capability_dispatch_task(void *context, int pending);
void	mac_capability_instance_drain_txq(struct mac_capability_instance *s);
void	mac_capability_instance_drain_rxq(struct mac_capability_instance *s);
void	mac_capability_free_msgq(struct mac_capability_msgq *q);
void	mac_capability_service_free(struct mac_capability_service *svc);
extern const struct fileops mac_capability_instance_ops;

#endif /* _KERNEL */
#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_INTERNAL_H_ */
