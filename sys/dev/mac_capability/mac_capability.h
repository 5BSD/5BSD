/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * mac_capability — message-passing capability framework for kernel modules.
 *
 * Public kernel API for service modules.
 *
 * Architecture:
 *   MAC_CAPABILITY_CALL invokes co_call synchronously in the caller's thread.
 *   MAC_CAPABILITY_SENDMSG enqueues on the RX queue; returns EAGAIN if full.
 *   A per-service taskqueue dequeues and calls co_handler.
 *   The handler calls mac_capability_reply() to respond.
 *   MAC_CAPABILITY_RECVMSG dequeues replies and notifications from the TX queue.
 *   kqueue EVFILT_READ/WRITE report TX/RX queue readiness for RECVMSG
 *   and SENDMSG.  Service events are delivered as RECVMSG payloads;
 *   kqueue notes are readiness notifications, not event payloads.
 *   read()/write() are disabled; all I/O uses structured ioctls.
 */

#ifndef _DEV_MAC_CAPABILITY_MAC_CAPABILITY_H_
#define _DEV_MAC_CAPABILITY_MAC_CAPABILITY_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/file.h>
#include <sys/refcount.h>

#include "mac_capability_ioctl.h"

/* Opaque types — internal layout is in mac_capability_internal.h. */
struct mac_capability_instance;
struct mac_capability_service;
struct mac_capability_msg;

/*
 * Revocation reason codes — passed to co_revoke.
 */
enum mac_capability_revoke_reason {
	MAC_CAPABILITY_REVOKE_PEER_CLOSED,
	MAC_CAPABILITY_REVOKE_BY_SERVICE,
	MAC_CAPABILITY_REVOKE_UNLOAD,
};

/*
 * Service operations — implement these in your module.
 *
 * The framework holds NO mac_capability locks when calling any callback.
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
 *     May sleep.  No mac_capability locks held.
 *
 *     Access msg fields via:
 *       mac_capability_msg_data(msg), mac_capability_msg_datalen(msg)
 *       mac_capability_msg_fds(msg), mac_capability_msg_nfds(msg)
 *       mac_capability_msg_fcaps(msg)
 *       mac_capability_msg_badge(msg), mac_capability_msg_token(msg)
 *       mac_capability_msg_cred(msg)
 *
 *     Return 0: message consumed.  Call mac_capability_reply() if the client
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
 *     NULL = MAC_CAPABILITY_CALL returns EOPNOTSUPP.
 *     fds/nfds are resolved file pointers from the caller.
 *     fcaps carries the caller's Capsicum rights for each fd
 *     (NULL if no fds attached).
 *     reply_fds/reply_nfdsp: output file pointers to return
 *     to the caller.  Set *reply_nfdsp to the count.  The
 *     framework installs them into the caller's fd table.
 *     NULL if no fds to return.
 *     Multiple co_call invocations may run concurrently —
 *     the service must serialize if needed.
 *     Do NOT call mac_capability_instance_revoke(s) from inside co_call.
 *     Returns 0 on success, errno on failure.
 *
 * Services may implement co_handler, co_call, or both.  Services may
 * also emit asynchronous outbound messages with mac_capability_notify() from
 * either model when MAC_CAPABILITY_SVC_NOTIFY is set.
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
struct mac_capability_ops {
	int	(*co_connect)(struct ucred *cred, void *arg,
		    uint64_t *badge_out);
	int	(*co_init)(struct mac_capability_instance *s, void *arg);
	int	(*co_handler)(struct mac_capability_instance *s,
		    const struct mac_capability_msg *msg, void *arg);
	void	(*co_revoke)(struct mac_capability_instance *s, uint64_t badge,
		    enum mac_capability_revoke_reason reason, void *arg);
	void	(*co_fdclose)(struct mac_capability_instance *s, int fd,
		    struct thread *td, void *arg);
	int	(*co_call)(struct mac_capability_instance *s,
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
#define	MAC_CAPABILITY_SVC_NOTIFY		0x0002	/* emits async RECVMSG notifications */
#define	MAC_CAPABILITY_SVC_MINTABLE		0x0004	/* instances can mint new instances */

struct mac_capability_service_params {
	const char		*name;
	const struct mac_capability_ops	*ops;
	void			*arg;
	uint32_t		queue_depth;	/* 0 = MAC_CAPABILITY_DEFAULT_QUEUE_DEPTH */
	uint32_t		tx_limit;	/* 0 = MAC_CAPABILITY_DEFAULT_TX_LIMIT */
	uint32_t		instance_limit;	/* 0 = MAC_CAPABILITY_DEF_INSTANCE_LIMIT (1024) */
	uint32_t		flags;		/* MAC_CAPABILITY_SVC_* */
};

/* ----------------------------------------------------------------
 * Public kernel API.
 * ---------------------------------------------------------------- */

/* Service lifecycle. */
int	mac_capability_service_create(const struct mac_capability_service_params *params,
	    struct mac_capability_service **svcp);
void	mac_capability_service_destroy(struct mac_capability_service *svc);

/*
 * Messaging — from co_handler or any sleeping context.
 * fcaps: per-fd Capsicum rights to preserve.  NULL = full rights
 *        (appropriate for kernel-minted fds).
 */
int	mac_capability_reply(struct mac_capability_instance *s, uint64_t reply_token,
	    const void *out, size_t outlen,
	    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds);
int	mac_capability_notify(struct mac_capability_instance *s, const void *data, size_t datalen,
	    struct file **fds, struct filecaps *fcaps, int nfds);
/*
 * Forward an existing userspace-originated message to another instance.
 * Preserves payload, fds, badge, reply_token, and sender credentials.
 */
int	mac_capability_forward(struct mac_capability_instance *s, const struct mac_capability_msg *msg);

/* Instance management. */
void	mac_capability_instance_revoke(struct mac_capability_instance *s);
void	mac_capability_instance_hold(struct mac_capability_instance *s);
void	mac_capability_instance_rele(struct mac_capability_instance *s);
void	mac_capability_instance_set_priv(struct mac_capability_instance *s, void *priv);
void   *mac_capability_instance_get_priv(struct mac_capability_instance *s);
uint64_t mac_capability_instance_get_badge(struct mac_capability_instance *s);

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
int	mac_capability_resolve_proc(struct file **fds, int nfds, struct proc **pp);

/* Minting — create a capability from handler context. */
int	mac_capability_mint_fp(struct mac_capability_service *svc, uint64_t badge,
	    struct file **fpp);

/* Message accessors — for use in co_handler. */
const void	*mac_capability_msg_data(const struct mac_capability_msg *msg);
size_t		 mac_capability_msg_datalen(const struct mac_capability_msg *msg);
struct file    **mac_capability_msg_fds(const struct mac_capability_msg *msg);
struct filecaps *mac_capability_msg_fcaps(const struct mac_capability_msg *msg);
int		 mac_capability_msg_nfds(const struct mac_capability_msg *msg);
uint64_t	 mac_capability_msg_badge(const struct mac_capability_msg *msg);
uint64_t	 mac_capability_msg_token(const struct mac_capability_msg *msg);
struct ucred	*mac_capability_msg_cred(const struct mac_capability_msg *msg);

/*
 * Common connect-callback pattern: assign a monotonic badge.
 * Usage: return (MAC_CAPABILITY_CONNECT_BADGE(my_counter, badge_out));
 */
#define	MAC_CAPABILITY_CONNECT_BADGE(counter, badge_out)		\
	(*(badge_out) = atomic_fetchadd_64(&(counter), 1), 0)

#endif /* _KERNEL */
#endif /* _DEV_MAC_CAPABILITY_MAC_CAPABILITY_H_ */
