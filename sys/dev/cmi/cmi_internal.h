/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi — framework internals.  Not for service modules.
 */

#ifndef _DEV_CMI_CMI_INTERNAL_H_
#define _DEV_CMI_CMI_INTERNAL_H_

#ifdef _KERNEL

#include "cmi.h"

#include <sys/queue.h>
#include <sys/event.h>
#include <sys/counter.h>
#include <sys/taskqueue.h>
#include <sys/_task.h>
#include <vm/uma.h>

/* Framework-internal limits. */
#define	CMI_MAX_QUEUED		CMI_DEFAULT_QUEUE_DEPTH
					/* default RX queue depth */
#define	CMI_MAX_QUEUE_DEPTH	4096	/* max configurable queue depth */
#define	CMI_MAX_TX_LIMIT	4096	/* max configurable TX soft limit */
#define	CMI_TX_HARD_MULT	4	/* TX hard limit = queue_depth * this */
#define	CMI_DEF_INSTANCE_LIMIT	1024	/* default instances per service */
#define	CMI_MAX_INSTANCES	(1024 * 1024) /* max instances per service */
#define	CMI_MSG_SIZE_LIMIT	(64 * 1024 * 1024) /* absolute max msg_size */
#define	CMI_MAX_SVC_THREADS	4	/* max taskqueue threads per service */
#define	CMI_POLL_TICKS		(hz / 20) /* 50ms refcount poll interval */

/*
 * Queued message — internal to the framework.
 * Service handlers see this as const via co_handler(msg).
 */
struct cmi_msg {
	STAILQ_ENTRY(cmi_msg) cm_link;
	void		*cm_data;
	size_t		cm_datalen;
	struct file	**cm_fds;
	struct filecaps	*cm_fcaps;
	int		cm_nfds;
	uint64_t	cm_badge;
	uint64_t	cm_reply_token;
	struct ucred	*cm_cred;
	pid_t		cm_pid;
};

/* Instance flags (protected by ci_mtx). */
#define	CMI_SF_CLOSED		0x0001
#define	CMI_SF_REVOKED		0x0002
#define	CMI_SF_FINALIZED	0x0004
#define	CMI_SF_LINKED		0x0008	/* on service's instance list */
#define	CMI_SF_DEAD		(CMI_SF_CLOSED | CMI_SF_REVOKED)

/* Restriction flags — one-way latch, checked in ioctl handler. */
#define	CMI_RF_NO_SEND		0x0001
#define	CMI_RF_NO_RECV		0x0002
#define	CMI_RF_NO_CALL		0x0004

/*
 * Instance — one per struct file.  Internal layout.
 */
struct cmi_instance {
	struct cmi_service *ci_service;
	void		*ci_priv;
	uint64_t	ci_badge;
	uint64_t	ci_id;

	STAILQ_HEAD(, cmi_msg) ci_txq;
	int		ci_txqlen;
	struct knlist	ci_rknotes;	/* EVFILT_READ */

	STAILQ_HEAD(, cmi_msg) ci_rxq;
	int		ci_rxqlen;
	int		ci_rxqlimit;
	struct knlist	ci_wknotes;	/* EVFILT_WRITE */

	struct task	ci_task;
	struct mtx	ci_mtx;
	volatile u_int	ci_refcnt;
	int		ci_flags;
	int		ci_restricted;	/* CMI_RF_* one-way latch */
	int		ci_inflight;	/* active co_handler + co_call count */
	struct thread	*ci_handler_td;

	LIST_ENTRY(cmi_instance) ci_svc_link;
};

#define	CMI_SVCF_DESTROYING	0x0001

/*
 * Registered service — internal layout.
 */
struct cmi_service {
	LIST_ENTRY(cmi_service) csvc_link;
	char		csvc_name[CMI_MAXNAME];
	const struct cmi_ops *csvc_ops;
	void		*csvc_arg;
	LIST_HEAD(, cmi_instance) csvc_instances;
	int		csvc_ninstances;
	int		csvc_instance_limit;
	volatile u_int	csvc_refcnt;
	int		csvc_flags;
	struct taskqueue *csvc_taskq;
	uint32_t	csvc_msg_size;
	uint32_t	csvc_queue_depth;
	uint32_t	csvc_tx_limit;
	uint32_t	csvc_svc_flags;	/* CMI_SVC_* from params */
};

/* Globals. */
extern struct sx cmi_registry_lock;
LIST_HEAD(cmi_service_list, cmi_service);
extern struct cmi_service_list cmi_services;
extern uma_zone_t cmi_instance_zone;
extern uma_zone_t cmi_msg_zone;
extern counter_u64_t cmi_stat_services;
extern counter_u64_t cmi_stat_instances;

/* Internal functions. */
int	cmi_init(void);
void	cmi_uninit(void);
struct cmi_service *cmi_service_lookup(const char *name);
void	cmi_msg_free(struct cmi_msg *msg);
struct cmi_instance *cmi_instance_init(struct cmi_service *svc,
	    uint64_t badge);
void	cmi_instance_free(struct cmi_instance *s);
int	cmi_service_reserve(struct cmi_service *svc);
void	cmi_service_unreserve(struct cmi_service *svc);
int	cmi_instance_link(struct cmi_service *svc, struct cmi_instance *s);
int	cmi_instance_create(struct cmi_service *svc, struct thread *td,
	    uint64_t badge, int *fdp);
void	cmi_dispatch_task(void *context, int pending);
void	cmi_instance_drain_txq(struct cmi_instance *s);
void	cmi_instance_drain_rxq(struct cmi_instance *s);
void	cmi_service_free(struct cmi_service *svc);
extern const struct fileops cmi_instance_ops;
extern const struct fileops cmi_instance_noxfer_ops;

#endif /* _KERNEL */
#endif /* _DEV_CMI_CMI_INTERNAL_H_ */
