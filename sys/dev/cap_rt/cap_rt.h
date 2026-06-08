/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt — message-passing capability framework for kernel modules.
 *
 * Public kernel API for service modules.
 *
 * Architecture:
 *   CAP_RT_CALL invokes co_call synchronously in the caller's thread.
 *   CAP_RT_SENDMSG enqueues on the RX queue; returns EAGAIN if full.
 *   A per-service taskqueue dequeues and calls co_handler.
 *   The handler calls cap_rt_reply() to respond.
 *   CAP_RT_RECVMSG dequeues replies and notifications from the TX queue.
 *   kqueue EVFILT_READ/WRITE report TX/RX queue readiness for RECVMSG
 *   and SENDMSG.  Service events are delivered as RECVMSG payloads;
 *   kqueue notes are readiness notifications, not event payloads.
 *   read()/write() are disabled; all I/O uses structured ioctls.
 */

#ifndef _DEV_CAP_RT_CAP_RT_H_
#define _DEV_CAP_RT_CAP_RT_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/file.h>
#include <sys/refcount.h>

#include "cap_rt_ioctl.h"

/* Opaque types — internal layout is in cap_rt_internal.h. */
struct cap_rt_instance;
struct cap_rt_service;
struct cap_rt_msg;

/*
 * Revocation reason codes — passed to co_revoke.
 */
enum cap_rt_revoke_reason {
	CAP_RT_REVOKE_PEER_CLOSED,
	CAP_RT_REVOKE_BY_SERVICE,
	CAP_RT_REVOKE_UNLOAD,
};

/*
 * Service operations — implement these in your module.
 *
 * The framework holds NO cap_rt locks when calling any callback.
 *
 * co_connect(cred, arg, badge_out)
 *     Access control.  Runs in the ioctl caller's thread.
 *     Return 0 to allow, nonzero errno to deny.
 *     NULL → always allow (badge = 0).
 *     Set *badge_out to assign a badge to the instance.
 *
 * co_init(instance, arg)
 *     Per-instance setup.  Called after creation.
 *     Return 0 on success, nonzero errno to abort.
 *     NULL → no init needed.
 *
 * co_handler(instance, msg, arg)
 *     Asynchronous SENDMSG handler.  Runs from the service's taskqueue.
 *     May sleep.  No cap_rt locks held.
 *
 *     Access msg fields via:
 *       cap_rt_msg_data(msg), cap_rt_msg_datalen(msg)
 *       cap_rt_msg_fds(msg), cap_rt_msg_nfds(msg)
 *       cap_rt_msg_fcaps(msg)
 *       cap_rt_msg_badge(msg), cap_rt_msg_token(msg)
 *       cap_rt_msg_cred(msg)
 *
 *     Return 0: message consumed.  Call cap_rt_reply() if the client
 *         expects a response.  No reply = fire-and-forget.
 *     Return nonzero: automatic error reply sent to the client.
 *     Never concurrent with another co_handler for the same instance.
 *     msg valid only during the call.
 *
 * co_call(instance, req, reqlen, fds, fcaps, nfds,
 *         reply, replylenp, reply_fds, reply_nfdsp, arg)
 *     Synchronous CALL handler in the ioctl caller's thread.
 *     curthread IS the calling process — can jail_attach,
 *     modify credentials, create fds, etc.
 *     NULL = CAP_RT_CALL returns EOPNOTSUPP.
 *     fds/nfds are resolved file pointers from the caller.
 *     fcaps carries the caller's Capsicum rights for each fd
 *     (NULL if no fds attached).
 *     reply_fds/reply_nfdsp: output file pointers to return
 *     to the caller.  Set *reply_nfdsp to the count.  The
 *     framework installs them into the caller's fd table.
 *     NULL if no fds to return.
 *     Multiple co_call invocations may run concurrently —
 *     the service must serialize if needed.
 *     Do NOT call cap_rt_instance_revoke(s) from inside co_call.
 *     Returns 0 on success, errno on failure.
 *
 * Services may implement co_handler, co_call, or both.  Services may
 * also emit asynchronous outbound messages with cap_rt_notify() from
 * either model when CAP_RT_SVC_NOTIFY is set.
 *
 * co_revoke(instance, badge, reason, arg)
 *     Called exactly once when an instance dies.  Fires after all
 *     handlers and deferred work complete.
 *     NULL → no cleanup.
 *
 * co_fdclose(instance, fd, td, arg)
 *     Called when a specific fd pointing at this instance is closed,
 *     even if other fds still reference it (dup, SCM_RIGHTS).
 *     Lets services track handle count.  NOT called on final close
 *     (co_revoke covers that).
 *     NULL → no notification.
 */
struct cap_rt_ops {
	int	(*co_connect)(struct ucred *cred, void *arg,
		    uint64_t *badge_out);
	int	(*co_init)(struct cap_rt_instance *s, void *arg);
	int	(*co_handler)(struct cap_rt_instance *s,
		    const struct cap_rt_msg *msg, void *arg);
	void	(*co_revoke)(struct cap_rt_instance *s, uint64_t badge,
		    enum cap_rt_revoke_reason reason, void *arg);
	void	(*co_fdclose)(struct cap_rt_instance *s, int fd,
		    struct thread *td, void *arg);
	int	(*co_call)(struct cap_rt_instance *s,
		    const void *req, size_t reqlen,
		    struct file **fds, struct filecaps *fcaps, int nfds,
		    void *reply, size_t *replylenp,
		    struct file **reply_fds, int *reply_nfdsp,
		    void *arg);
};

/*
 * Service creation parameters.  Zero-initialize for defaults.
 */
/*
 * Service creation flags.
 */
#define	CAP_RT_SVC_NOTIFY		0x0002	/* emits async RECVMSG notifications */
#define	CAP_RT_SVC_MINTABLE		0x0004	/* instances can mint new instances */

struct cap_rt_service_params {
	const char		*name;
	const struct cap_rt_ops	*ops;
	void			*arg;
	uint32_t		queue_depth;	/* 0 = CAP_RT_DEFAULT_QUEUE_DEPTH */
	uint32_t		tx_limit;	/* 0 = CAP_RT_DEFAULT_TX_LIMIT */
	uint32_t		instance_limit;	/* 0 = CAP_RT_DEF_INSTANCE_LIMIT (1024) */
	uint32_t		flags;		/* CAP_RT_SVC_* */
};

/* ----------------------------------------------------------------
 * Public kernel API.
 * ---------------------------------------------------------------- */

/* Service lifecycle. */
int	cap_rt_service_create(const struct cap_rt_service_params *params,
	    struct cap_rt_service **svcp);
void	cap_rt_service_destroy(struct cap_rt_service *svc);

/*
 * Messaging — from co_handler or any sleeping context.
 * fcaps: per-fd Capsicum rights to preserve.  NULL = full rights
 *        (appropriate for kernel-minted fds).
 */
int	cap_rt_reply(struct cap_rt_instance *s, uint64_t reply_token,
	    const void *out, size_t outlen,
	    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds);
int	cap_rt_notify(struct cap_rt_instance *s, const void *data, size_t datalen,
	    struct file **fds, struct filecaps *fcaps, int nfds);
/*
 * Forward an existing userspace-originated message to another instance.
 * Preserves payload, fds, badge, reply_token, and sender credentials.
 */
int	cap_rt_forward(struct cap_rt_instance *s, const struct cap_rt_msg *msg);

/* Instance management. */
void	cap_rt_instance_revoke(struct cap_rt_instance *s);
void	cap_rt_instance_hold(struct cap_rt_instance *s);
void	cap_rt_instance_rele(struct cap_rt_instance *s);
void	cap_rt_instance_set_priv(struct cap_rt_instance *s, void *priv);
void   *cap_rt_instance_get_priv(struct cap_rt_instance *s);
uint64_t cap_rt_instance_get_badge(struct cap_rt_instance *s);

/*
 * Resolve target process from attached procdesc fd array, or self.
 *
 * If nfds > 0, the first fd must be a process descriptor.  If nfds == 0,
 * the calling process is used.
 *
 * On success, returns 0 with:
 *   - PROC_LOCK held on *pp
 *   - _PHOLD active on *pp (prevents exit)
 * The caller MUST call PROC_UNLOCK(*pp) and _PRELE(*pp) when done.
 *
 * On failure, returns an errno and *pp is unchanged.
 */
int	cap_rt_resolve_proc(struct file **fds, int nfds, struct proc **pp);

/* Minting — create a capability from handler context. */
int	cap_rt_mint_fp(struct cap_rt_service *svc, uint64_t badge,
	    struct file **fpp);

/* Message accessors — for use in co_handler. */
const void	*cap_rt_msg_data(const struct cap_rt_msg *msg);
size_t		 cap_rt_msg_datalen(const struct cap_rt_msg *msg);
struct file    **cap_rt_msg_fds(const struct cap_rt_msg *msg);
struct filecaps *cap_rt_msg_fcaps(const struct cap_rt_msg *msg);
int		 cap_rt_msg_nfds(const struct cap_rt_msg *msg);
uint64_t	 cap_rt_msg_badge(const struct cap_rt_msg *msg);
uint64_t	 cap_rt_msg_token(const struct cap_rt_msg *msg);
struct ucred	*cap_rt_msg_cred(const struct cap_rt_msg *msg);

/*
 * Common connect-callback pattern: assign a monotonic badge.
 * Usage: return (CAP_RT_CONNECT_BADGE(my_counter, badge_out));
 */
#define	CAP_RT_CONNECT_BADGE(counter, badge_out)		\
	(*(badge_out) = atomic_fetchadd_64(&(counter), 1), 0)

#endif /* _KERNEL */
#endif /* _DEV_CAP_RT_CAP_RT_H_ */
