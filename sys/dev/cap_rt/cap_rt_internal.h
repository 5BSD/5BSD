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
/* CAP_RT_MSG_SIZE_LIMIT removed — messages are fixed at CAP_RT_MSG_SIZE. */
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
	uint8_t		cm_flags;
	uint16_t	cm_reserved;

	/* Inline fd slots — 32 max, no separate allocation. */
	struct file	*cm_fds[CAP_RT_MAX_FDS];
	struct filecaps	cm_fcaps[CAP_RT_MAX_FDS];

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

/*
 * Instance — one per struct file.  Internal layout.
 */
struct cap_rt_instance {
	struct cap_rt_service *ci_service;
	void		*ci_priv;
	uint64_t	ci_badge;

	STAILQ_HEAD(, cap_rt_msg) ci_txq;
	int		ci_txqlen;
	struct knlist	ci_rknotes;	/* EVFILT_READ */

	STAILQ_HEAD(, cap_rt_msg) ci_rxq;
	int		ci_rxqlen;
	int		ci_rxqlimit;
	struct knlist	ci_wknotes;	/* EVFILT_WRITE */

	struct task	ci_task;
	struct mtx	ci_mtx;
	volatile u_int	ci_refcnt;
	int		ci_flags;
	int		ci_restricted;	/* CAP_RT_RF_* one-way latch */
	int		ci_inflight;	/* active co_handler + co_call count */
	struct thread	*ci_handler_td;

	LIST_ENTRY(cap_rt_instance) ci_svc_link;
};

#define	CAP_RT_SVCF_DESTROYING	0x0001

/*
 * Registered service — internal layout.
 */
struct cap_rt_service {
	LIST_ENTRY(cap_rt_service) csvc_link;
	char		csvc_name[CAP_RT_MAXNAME];
	const struct cap_rt_ops *csvc_ops;
	void		*csvc_arg;
	LIST_HEAD(, cap_rt_instance) csvc_instances;
	int		csvc_ninstances;
	int		csvc_instance_limit;
	volatile u_int	csvc_refcnt;
	int		csvc_flags;
	struct taskqueue *csvc_taskq;
	uint32_t	csvc_queue_depth;
	uint32_t	csvc_tx_limit;
	uint32_t	csvc_svc_flags;	/* CAP_RT_SVC_* from params */
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
extern const struct fileops cap_rt_instance_noxfer_ops;

#endif /* _KERNEL */
#endif /* _DEV_CAP_RT_CAP_RT_INTERNAL_H_ */
