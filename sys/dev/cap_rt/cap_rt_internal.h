/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — framework internals.  Not for service modules.
 */

#ifndef _DEV_CAP_RT_CAP_RT_INTERNAL_H_
#define _DEV_CAP_RT_CAP_RT_INTERNAL_H_

#ifdef _KERNEL

#include "cap_rt.h"

#include <sys/queue.h>
#include <sys/event.h>
#include <sys/counter.h>
#include <sys/taskqueue.h>
#include <sys/_task.h>
#include <vm/uma.h>

/* Framework-internal limits. */
#define	CAP_RT_MAX_QUEUED		CAP_RT_DEFAULT_QUEUE_DEPTH
					/* default RX queue depth */
#define	CAP_RT_MAX_QUEUE_DEPTH	4096	/* max configurable queue depth */
#define	CAP_RT_MAX_TX_LIMIT	4096	/* max configurable TX soft limit */
#define	CAP_RT_TX_HARD_MULT	4	/* TX hard limit = queue_depth * this */
#define	CAP_RT_DEF_INSTANCE_LIMIT	1024	/* default instances per service */
#define	CAP_RT_MAX_INSTANCES	(1024 * 1024) /* max instances per service */
#define	CAP_RT_MAX_SVC_THREADS	4	/* max taskqueue threads per service */
#define	CAP_RT_POLL_TICKS		(hz / 20) /* 50ms refcount poll interval */

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
 * The UMA zone allocates sizeof(struct cap_rt_msg) + CAP_RT_MSG_PAYLOAD_SIZE.
 * CAP_RT_MSG_PAYLOAD_SIZE is the usable payload area for user data.
 * Anything larger must be sent via an attached fd (shared memory).
 */
#define	CAP_RT_MSG_PAYLOAD_SIZE	14336

struct cap_rt_msg {
	/* Queue linkage. */
	STAILQ_ENTRY(cap_rt_msg) cm_link;

	/* Message metadata — kernel-stamped, unforgeable. */
	uint64_t	cm_badge;
	uint64_t	cm_reply_token;
	struct ucred	*cm_cred;
	uint32_t	cm_datalen;
	uint8_t		cm_nfds;

	/* Inline fd slots — 32 max, no separate allocation. */
	struct file	*cm_fds[CAP_RT_MAX_FDS];
	struct filecaps	cm_fcaps[CAP_RT_MAX_FDS];
	uint8_t		cm_xfer_state[CAP_RT_MAX_FDS];

	/* Inline payload — user data copied directly here. */
	char		cm_data[];  /* sized by UMA zone: CAP_RT_MSG_PAYLOAD_SIZE */
};

/* Instance flags (protected by ci_mtx). */
#define	CAP_RT_SF_CLOSED		0x0001
#define	CAP_RT_SF_REVOKED		0x0002
#define	CAP_RT_SF_FINALIZED	0x0004
#define	CAP_RT_SF_LINKED		0x0008	/* on service's instance list */
#define	CAP_RT_SF_DEAD		(CAP_RT_SF_CLOSED | CAP_RT_SF_REVOKED)

/* Restriction flags — one-way latch, checked in ioctl handler. */
#define	CAP_RT_RF_NO_SEND		0x0001
#define	CAP_RT_RF_NO_RECV		0x0002
#define	CAP_RT_RF_NO_CALL		0x0004
#define	CAP_RT_RF_NO_MINT		0x0008

/*
 * Instance — one per struct file.  Internal layout.
 *
 * Locking:
 *   (I)   Immutable after creation.
 *   (M)   Protected by ci_mtx.
 *   (R)   Protected by refcount (ci_refcnt).
 *   (A)   Atomic operations only (one-way latch).
 *   (L)   Protected by cap_rt_registry_lock (xlock).
 */
struct cap_rt_instance {
	struct cap_rt_service *ci_service;	/* (I) owning service */
	void		*ci_priv;		/* (I) service-private data */
	uint64_t	ci_badge;		/* (I) connection badge */

	STAILQ_HEAD(, cap_rt_msg) ci_txq;	/* (M) outbound queue */
	int		ci_txqlen;		/* (M) outbound count */
	struct knlist	ci_rknotes;		/* (M) EVFILT_READ knotes */

	STAILQ_HEAD(, cap_rt_msg) ci_rxq;	/* (M) inbound queue */
	int		ci_rxqlen;		/* (M) inbound count */
	int		ci_rxqlimit;		/* (I) max RX depth */
	struct knlist	ci_wknotes;		/* (M) EVFILT_WRITE knotes */

	struct task	ci_task;		/* (I) taskqueue task */
	struct mtx	ci_mtx;			/* instance lock */
	volatile u_int	ci_refcnt;		/* (R) reference count */
	int		ci_flags;		/* (M) CAP_RT_SF_* */
	int		ci_restricted;		/* (A) CAP_RT_RF_* one-way latch */
	int		ci_inflight;		/* (M) active handler+call count */
	struct thread	*ci_handler_td;		/* (M) current handler thread */

	LIST_ENTRY(cap_rt_instance) ci_svc_link; /* (L) service list link */
};

#define	CAP_RT_SVCF_DESTROYING	0x0001

/*
 * Registered service — internal layout.
 *
 * Locking:
 *   (I)   Immutable after cap_rt_service_create.
 *   (L)   Protected by cap_rt_registry_lock (xlock).
 *   (R)   Protected by refcount (csvc_refcnt).
 */
struct cap_rt_service {
	LIST_ENTRY(cap_rt_service) csvc_link;	/* (L) registry list link */
	char		csvc_name[CAP_RT_MAXNAME]; /* (I) service name */
	const struct cap_rt_ops *csvc_ops;	/* (I) operation callbacks */
	void		*csvc_arg;		/* (I) callback argument */
	LIST_HEAD(, cap_rt_instance) csvc_instances; /* (L) instance list */
	int		csvc_ninstances;	/* (L) instance count */
	int		csvc_instance_limit;	/* (I) max instances */
	volatile u_int	csvc_refcnt;		/* (R) reference count */
	int		csvc_flags;		/* (L) CAP_RT_SVCF_* */
	struct taskqueue *csvc_taskq;		/* (I) async dispatch queue */
	uint32_t	csvc_queue_depth;	/* (I) per-instance RX limit */
	uint32_t	csvc_tx_limit;		/* (I) per-instance TX soft limit */
	uint32_t	csvc_svc_flags;		/* (I) CAP_RT_SVC_* from params */
};

/* Globals. */
extern struct sx cap_rt_registry_lock;
LIST_HEAD(cap_rt_service_list, cap_rt_service);
extern struct cap_rt_service_list cap_rt_services;
extern uma_zone_t cap_rt_instance_zone;
extern uma_zone_t cap_rt_msg_zone;
extern counter_u64_t cap_rt_stat_services;
extern counter_u64_t cap_rt_stat_instances;

/* Internal functions. */
int	cap_rt_init(void);
void	cap_rt_uninit(void);
struct cap_rt_service *cap_rt_service_lookup(const char *name);
void	cap_rt_msg_free(struct cap_rt_msg *msg);
struct cap_rt_instance *cap_rt_instance_init(struct cap_rt_service *svc,
	    uint64_t badge);
void	cap_rt_instance_free(struct cap_rt_instance *s);
int	cap_rt_service_reserve(struct cap_rt_service *svc);
void	cap_rt_service_unreserve(struct cap_rt_service *svc);
int	cap_rt_instance_link(struct cap_rt_service *svc, struct cap_rt_instance *s);
int	cap_rt_instance_create(struct cap_rt_service *svc, struct thread *td,
	    uint64_t badge, int *fdp);
void	cap_rt_dispatch_task(void *context, int pending);
void	cap_rt_instance_drain_txq(struct cap_rt_instance *s);
void	cap_rt_instance_drain_rxq(struct cap_rt_instance *s);
void	cap_rt_service_free(struct cap_rt_service *svc);
extern const struct fileops cap_rt_instance_ops;

#endif /* _KERNEL */
#endif /* _DEV_CAP_RT_CAP_RT_INTERNAL_H_ */
