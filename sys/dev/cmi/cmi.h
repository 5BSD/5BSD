/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cmi — message-passing capability framework for kernel modules.
 *
 * Public kernel API for service modules.
 *
 * Architecture:
 *   CMI_SENDMSG enqueues on the RX queue; returns immediately.
 *   A per-service taskqueue dequeues and calls co_handler.
 *   The handler calls cmi_reply() to respond.
 *   CMI_RECVMSG dequeues from the TX queue; blocks if empty.
 *   read()/write() are disabled; all I/O uses structured ioctls.
 */

#ifndef _DEV_CMI_CMI_H_
#define _DEV_CMI_CMI_H_

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/file.h>
#include <sys/refcount.h>

#include "cmi_ioctl.h"

/* Opaque types — internal layout is in cmi_internal.h. */
struct cmi_instance;
struct cmi_service;
struct cmi_msg;

/*
 * Revocation reason codes — passed to co_revoke.
 */
enum cmi_revoke_reason {
	CMI_REVOKE_PEER_CLOSED,
	CMI_REVOKE_BY_SERVICE,
	CMI_REVOKE_UNLOAD,
};

/*
 * Service operations — implement these in your module.
 *
 * The framework holds NO cmi locks when calling any callback.
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
 *     Message handler.  Runs from the service's taskqueue.
 *     May sleep.  No cmi locks held.
 *
 *     Access msg fields via:
 *       cmi_msg_data(msg), cmi_msg_datalen(msg)
 *       cmi_msg_fds(msg), cmi_msg_nfds(msg)
 *       cmi_msg_fcaps(msg)
 *       cmi_msg_badge(msg), cmi_msg_token(msg)
 *       cmi_msg_cred(msg)
 *
 *     Return 0: message consumed.  Call cmi_reply() if the client
 *         expects a response.  No reply = fire-and-forget.
 *     Return nonzero: automatic error reply sent to the client.
 *     Never concurrent with another co_handler for the same instance.
 *     msg valid only during the call.
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
struct cmi_ops {
	int	(*co_connect)(struct ucred *cred, void *arg,
		    uint64_t *badge_out);
	int	(*co_init)(struct cmi_instance *s, void *arg);
	int	(*co_handler)(struct cmi_instance *s,
		    const struct cmi_msg *msg, void *arg);
	void	(*co_revoke)(struct cmi_instance *s, uint64_t badge,
		    enum cmi_revoke_reason reason, void *arg);
	void	(*co_fdclose)(struct cmi_instance *s, int fd,
		    struct thread *td, void *arg);
	/*
	 * co_call(instance, req, reqlen, fds, fcaps, nfds,
	 *         reply, replylenp, reply_fds, reply_nfdsp, arg)
	 *     Synchronous call in the ioctl caller's thread.
	 *     curthread IS the calling process — can jail_attach,
	 *     modify credentials, create fds, etc.
	 *     NULL = CMI_CALL returns EOPNOTSUPP.
	 *     fds/nfds are resolved file pointers from the caller.
	 *     fcaps carries the caller's Capsicum rights for each fd
	 *     (NULL if no fds attached).
	 *     reply_fds/reply_nfdsp: output file pointers to return
	 *     to the caller.  Set *reply_nfdsp to the count.  The
	 *     framework installs them into the caller's fd table.
	 *     NULL if no fds to return.
	 *     Multiple co_call invocations may run concurrently —
	 *     the service must serialize if needed.
	 *     Do NOT call cmi_instance_revoke(s) from inside co_call.
	 *     Returns 0 on success, errno on failure.
	 */
	int	(*co_call)(struct cmi_instance *s,
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
#define	CMI_SVC_NOXFER		0x0001	/* instances are non-transferable */

struct cmi_service_params {
	const char		*name;
	const struct cmi_ops	*ops;
	void			*arg;
	uint32_t		queue_depth;	/* 0 = CMI_DEFAULT_QUEUE_DEPTH */
	uint32_t		tx_limit;	/* 0 = CMI_DEFAULT_TX_LIMIT */
	uint32_t		instance_limit;	/* 0 = CMI_DEF_INSTANCE_LIMIT (1024) */
	uint32_t		flags;		/* CMI_SVC_* */
};

/* ----------------------------------------------------------------
 * Public kernel API.
 * ---------------------------------------------------------------- */

/* Service lifecycle. */
int	cmi_service_create(const struct cmi_service_params *params,
	    struct cmi_service **svcp);
void	cmi_service_destroy(struct cmi_service *svc);

/*
 * Messaging — from co_handler or any sleeping context.
 * fcaps: per-fd Capsicum rights to preserve.  NULL = full rights
 *        (appropriate for kernel-minted fds).
 */
int	cmi_reply(struct cmi_instance *s, uint64_t reply_token,
	    const void *out, size_t outlen,
	    struct file **out_fds, struct filecaps *out_fcaps, int out_nfds);
int	cmi_notify(struct cmi_instance *s, const void *data, size_t datalen,
	    struct file **fds, struct filecaps *fcaps, int nfds);
/*
 * Forward an existing userspace-originated message to another instance.
 * Preserves payload, fds, badge, reply_token, and sender credentials.
 */
int	cmi_forward(struct cmi_instance *s, const struct cmi_msg *msg);

/* Instance management. */
void	cmi_instance_revoke(struct cmi_instance *s);
void	cmi_instance_hold(struct cmi_instance *s);
void	cmi_instance_rele(struct cmi_instance *s);
void	cmi_instance_set_priv(struct cmi_instance *s, void *priv);
void   *cmi_instance_get_priv(struct cmi_instance *s);
uint64_t cmi_instance_get_badge(struct cmi_instance *s);

/* Minting — create a capability from handler context. */
int	cmi_mint_fp(struct cmi_service *svc, uint64_t badge,
	    struct file **fpp);

/* Message accessors — for use in co_handler. */
const void	*cmi_msg_data(const struct cmi_msg *msg);
size_t		 cmi_msg_datalen(const struct cmi_msg *msg);
struct file    **cmi_msg_fds(const struct cmi_msg *msg);
struct filecaps *cmi_msg_fcaps(const struct cmi_msg *msg);
int		 cmi_msg_nfds(const struct cmi_msg *msg);
uint64_t	 cmi_msg_badge(const struct cmi_msg *msg);
uint64_t	 cmi_msg_token(const struct cmi_msg *msg);
struct ucred	*cmi_msg_cred(const struct cmi_msg *msg);

#endif /* _KERNEL */
#endif /* _DEV_CMI_CMI_H_ */
