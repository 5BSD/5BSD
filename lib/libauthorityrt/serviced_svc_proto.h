/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Service-side channel protocol.
 *
 * Messages exchanged between a launched service and serviced over
 * the service's inherited channel fd (fd 3).  Uses MAC_CAPABILITY_SENDMSG/
 * MAC_CAPABILITY_RECVMSG with reply_token correlation.
 *
 * Services use this protocol to:
 *   - Check in each manifest-authorized listener (NAME_CLAIM)
 *   - Report readiness (READY)
 *   - Publish or fail one requested name (NAME_RESULT)
 *   - Withdraw a checked-in listener (NAME_WITHDRAW)
 *   - Connect to named services (LOOKUP)
 *
 * Serviced pushes connection notifications to registered services
 * when a client looks up their name.  The notification carries an
 * attached fd — the new client's end of a channel.
 *
 * Services should NOT include mac_capability headers.  The channel fd is an
 * opaque communication channel — mac_capability is an implementation detail
 * of the authority.
 */

#ifndef SERVICED_SVC_PROTO_H
#define SERVICED_SVC_PROTO_H

#include <sys/types.h>

#define	SERVICED_SVC_PROTO_VERSION	8

/* Maximum reverse-domain name length. */
#define	SERVICED_NAME_MAX		255

/*
 * Operation codes — first 4 bytes of every request payload.
 *
 * Service → serviced (requests):
 */
#define	SVC_OP_READY		1	/* service initialization complete */
#define	SVC_OP_NAME_RESULT	2	/* per-name activation result */
#define	SVC_OP_NAME_WITHDRAW	3	/* stop serving one active name */
#define	SVC_OP_LOOKUP		4	/* connect to a named service */
#define	SVC_OP_NAME_CLAIM	5	/* claim one provides[] listener */
#define	SVC_OP_QUIESCE_RESULT	6	/* managed shutdown completion */
#define	SVC_OP_WORKER_CHANNEL	7	/* private provider/worker channel */
#define	SVC_OP_IDLE		8	/* provider requests idle-timeout shutdown */
#define	SVC_OP_MINT_DOMAIN	9	/* mint a narrowed (USER, uid) lookup channel */
#define	SVC_OP_AMBIENT_HELLO	10	/* behavioral probe: is this THE lookup channel? */
#define	SVC_OP_HELPER_OPEN	11	/* launch + connect a bundle-local private helper */

/*
 * Serviced → service (notifications):
 */
#define	SVC_OP_ACTIVATE_NAME	127	/* initialize one reserved name */
#define	SVC_OP_NEW_CLIENT	128	/* new client connection (pushed) */
#define	SVC_OP_QUIESCE		129	/* stop admission and drain */

#define	SVC_QUIESCE_REASON_STOP		1
#define	SVC_QUIESCE_REASON_SHUTDOWN	2
#define	SVC_QUIESCE_REASON_RELOAD	3

struct svc_quiesce_msg {
	uint32_t	op;		/* SVC_OP_QUIESCE */
	uint32_t	reason;		/* SVC_QUIESCE_REASON_* */
	uint32_t	deadline_ms;
	uint32_t	flags;		/* reserved */
};

struct svc_quiesce_result_req {
	uint32_t	op;		/* SVC_OP_QUIESCE_RESULT */
	int32_t		status;		/* zero or positive errno */
};

/*
 * SVC_OP_IDLE
 *   req:  svc_idle_req
 *   reply: svc_reply { .status }
 *
 * A running provider declares that it has no active clients and requests that
 * serviced stop it after `seconds` of no new demand.  serviced arms a one-shot
 * idle timer; a new client lookup before it fires cancels the timer, while an
 * expiry gracefully stops the provider yet keeps its name reservations so the
 * next lookup relaunches it on demand.  seconds == 0 cancels a pending idle
 * timer; a fresh call re-arms (resetting the countdown).
 */
struct svc_idle_req {
	uint32_t	op;		/* SVC_OP_IDLE */
	uint32_t	seconds;	/* idle timeout; 0 cancels pending timer */
};

/*
 * SVC_OP_MINT_DOMAIN
 *   req:  svc_mint_domain_req
 *   reply: svc_reply { .status }
 *   reply_fds[0] = minted lookup channel endpoint (on success)
 *
 * Mint a fresh lookup channel for a session and return the caller's endpoint.
 * The `domain` field selects the minted channel's scope:
 *
 *   SVC_MINT_DOMAIN_USER (0, the zero-init default)
 *       a per-uid USER channel — resolves only the user-domain allow-list;
 *       every out-of-scope name returns ENOENT (§6 regular user).
 *   SVC_MINT_DOMAIN_SYSTEM (1)
 *       a SYSTEM (admin) channel — full discovery, resolves every registered
 *       name (§6 root/wheel session).  Minting SYSTEM is a privilege: it is
 *       refused with EPERM unless the REQUESTING channel is itself SYSTEM, so a
 *       user session can never widen its own scope.
 *
 * Only a SYSTEM-domain caller may mint AT ALL: a request arriving on an
 * already-narrowed (user-domain) channel is refused with EPERM, because domains
 * only ever narrow and never broaden.  The returned descriptor is an ambient
 * descriptor (survives every fork, survives exec, and is usable in capability
 * mode) so the login/session path can install it as a session leader's
 * inherited lookup channel (§21).
 */
#define	SVC_MINT_DOMAIN_USER	0U	/* per-uid scoped channel (default) */
#define	SVC_MINT_DOMAIN_SYSTEM	1U	/* full-discovery admin channel */

struct svc_mint_domain_req {
	uint32_t	op;		/* SVC_OP_MINT_DOMAIN */
	uint32_t	flags;		/* reserved, must be 0 */
	uint32_t	uid;		/* target uid for a USER domain */
	uint32_t	domain;		/* SVC_MINT_DOMAIN_USER | _SYSTEM */
};

/*
 * SVC_OP_AMBIENT_HELLO
 *   req:  svc_ambient_hello_req  { .op = SVC_OP_AMBIENT_HELLO }
 *   reply: svc_ambient_hello_reply { .status = 0, .magic = SVC_AMBIENT_HELLO_MAGIC }
 *
 * A behavioral handshake that lets an inheriting process confirm the fd it
 * probes really is a serviced ambient LOOKUP channel and not some other
 * mac_capability channel that happens to answer MAC_CAPABILITY_GETINFO — most
 * dangerously a service's unit control channel, which shares fd 3
 * (SVC_CHANNEL_FD == SERVICE_LOOKUP_FIXED_FD) and the generic per-instance
 * channel identity, so name/badge cannot discriminate it.
 *
 * Only a lookup-channel handler (domain.c) answers this op with status 0 and
 * the magic ack.  A unit control channel's dispatcher (svc_proto.c) does NOT
 * list SVC_OP_AMBIENT_HELLO and returns ENOTSUP from its default case — exactly
 * the discriminator.  The probe is best-effort and strictly bounded: a timeout,
 * an error, a wrong/short reply, or an ENOTSUP all mean "not the lookup
 * channel", and the caller degrades to holding no ambient channel.  It must
 * never block a login or an su.
 */
#define	SVC_AMBIENT_HELLO_MAGIC	0x414d4248U	/* "AMBH" */

struct svc_ambient_hello_req {
	uint32_t	op;		/* SVC_OP_AMBIENT_HELLO */
};

struct svc_ambient_hello_reply {
	int32_t		status;		/* 0 on a genuine lookup channel */
	uint32_t	magic;		/* SVC_AMBIENT_HELLO_MAGIC when status == 0 */
};

/*
 * Common request header — for ops with no extra params (READY).
 */
struct svc_req_hdr {
	uint32_t	op;
};

/*
 * SVC_OP_WORKER_CHANNEL
 *   req:  svc_req_hdr { .op = SVC_OP_WORKER_CHANNEL }
 *   reply: svc_reply { .status }
 *   reply_fds[0] = provider endpoint
 *   reply_fds[1] = worker endpoint
 *
 * Create an unnamed capability-channel pair for an internal provider worker.
 * The pair is not registered in the global namespace.  libservice applies
 * one-fork and non-transferable propagation policy before returning it.
 */

/*
 * SVC_OP_READY
 *   req:  svc_req_hdr { .op = SVC_OP_READY }
 *   reply: svc_reply { .status }
 *
 * Application readiness advisory.  Every provides[] name must already have
 * been claimed.  serviced does not promote a process to RUNNING from this
 * message; it independently observes and verifies NOTE_CAPMODE on the process
 * descriptor.  Per-name publication remains demand-driven after both gates.
 */

/*
 * SVC_OP_NAME_RESULT
 *   req:  svc_name_result_req
 *   reply: svc_reply { .status }
 *
 * Complete a preceding ACTIVATE_NAME event.  status is zero when the
 * endpoint is operational, otherwise a positive errno value.  Publication
 * is authorized only for names reserved by this process's provides[].
 */
struct svc_name_result_req {
	uint32_t	op;		/* SVC_OP_NAME_RESULT */
	uint32_t	flags;		/* reserved, must be 0 */
	int32_t		status;		/* 0 or positive errno */
	uint32_t	reserved;
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_NAME_CLAIM
 *   req:  svc_name_claim_req
 *   reply: svc_reply { .status }
 *
 * Check in one local listener for a manifest-reserved provides[] name.
 * Every declared name must be claimed before the initial READY succeeds.
 * Claiming does not publish or initialize the endpoint; client demand still
 * drives ACTIVATE_NAME independently for each name.
 */
/*
 * The provider decides, in its own code at expose time, whether the sessions
 * delivered for this name may be forwarded.  Default (0): serviced attenuates
 * each delivered client endpoint to CAP_XFER_NONE.  With SENDABLE the endpoint
 * is left CAP_XFER_UNLIMITED, so the consumer may re-send it (and attenuate per
 * hop).  This is the service's own protocol contract, not operator policy, so
 * it rides the claim rather than the manifest.
 */
#define	SVC_NAME_CLAIM_SENDABLE	0x1u

struct svc_name_claim_req {
	uint32_t	op;		/* SVC_OP_NAME_CLAIM */
	uint32_t	flags;		/* SVC_NAME_CLAIM_* */
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_NAME_WITHDRAW
 *   req:  svc_name_withdraw_req
 *   reply: svc_reply { .status }
 *
 * Withdraw one claimed name without terminating the process.  Existing
 * direct sessions remain valid, but new lookups wait for a new claim and
 * activation.
 */
struct svc_name_withdraw_req {
	uint32_t	op;		/* SVC_OP_NAME_WITHDRAW */
	uint32_t	flags;		/* reserved, must be 0 */
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_LOOKUP
 *   req:  svc_lookup_req
 *   reply: svc_reply { .status }
 *   reply_fds[0] = channel endpoint to the named service (on success)
 *
 * Request a connection to a named service.  serviced creates a
 * new channel, sends one end to the requester (in the reply), and
 * pushes the other end to the provider via SVC_OP_NEW_CLIENT.
 * ENOENT if the name is not registered.
 */
struct svc_lookup_req {
	uint32_t	op;		/* SVC_OP_LOOKUP */
	uint32_t	flags;		/* reserved, must be 0 */
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_HELPER_OPEN
 *   req:   svc_helper_req { .op, .name = bundle-local helper unit name }
 *   reply: svc_req_hdr { .status } + one fd (the caller's channel end)
 *
 * Launch a private helper unit declared in the CALLER's own bundle and return
 * a connected channel to it.  serviced resolves the name bundle-locally (never
 * the global system.* namespace), launches the helper in the caller's
 * coalition so it dies with the parent, and returns the caller's socketpair
 * end.  ENOENT if the caller's bundle has no such helper unit; EACCES if the
 * named unit exists but is not a helper.
 */
struct svc_helper_req {
	uint32_t	op;		/* SVC_OP_HELPER_OPEN */
	uint32_t	flags;		/* reserved, must be 0 */
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_ACTIVATE_NAME (event, serviced -> service)
 *
 * The manifest has already reserved the name.  libservice dispatches this
 * event to the name's activation handler.  No descriptors are attached.
 */
struct svc_activate_name_msg {
	uint32_t	op;
	uint32_t	flags;
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_NEW_CLIENT (notification, serviced → service)
 *   payload: svc_new_client_msg
 *   fds[0] = channel endpoint to the new client
 *
 * Pushed to a registered service when a client looks up its name.
 * The service should read this from its channel fd and add the
 * attached fd to its event loop.
 */
struct svc_new_client_msg {
	uint32_t	op;		/* SVC_OP_NEW_CLIENT */
	uint32_t	flags;		/* reserved */
	char		service_name[SERVICED_NAME_MAX + 1];
	char		client_label[64]; /* label of the connecting service */
};

/*
 * Generic reply — returned for all service requests.
 */
struct svc_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

#endif /* SERVICED_SVC_PROTO_H */
