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
 *   - Report readiness (READY)
 *   - Register reverse-domain names (REGISTER)
 *   - Connect to named services (LOOKUP)
 *   - Deregister names (UNREGISTER)
 *
 * Serviced pushes connection notifications to registered services
 * when a client looks up their name.  The notification carries an
 * attached fd — the new client's end of a channel.
 *
 * Services should NOT include mac_capability headers.  The channel fd is an
 * opaque communication channel — mac_capability is an implementation detail
 * of the oracle.
 */

#ifndef SERVICED_SVC_PROTO_H
#define SERVICED_SVC_PROTO_H

#include <sys/types.h>

#define	SERVICED_SVC_PROTO_VERSION	1

/* Maximum reverse-domain name length. */
#define	SERVICED_NAME_MAX		255

/*
 * Operation codes — first 4 bytes of every request payload.
 *
 * Service → serviced (requests):
 */
#define	SVC_OP_READY		1	/* service initialization complete */
#define	SVC_OP_REGISTER		2	/* register a reverse-domain name */
#define	SVC_OP_UNREGISTER	3	/* deregister a name */
#define	SVC_OP_LOOKUP		4	/* connect to a named service */

/*
 * Serviced → service (notifications):
 */
#define	SVC_OP_NEW_CLIENT	128	/* new client connection (pushed) */

/*
 * Common request header — for ops with no extra params (READY).
 */
struct svc_req_hdr {
	uint32_t	op;
};

/*
 * SVC_OP_READY
 *   req:  svc_req_hdr { .op = SVC_OP_READY }
 *   reply: svc_reply { .status }
 *
 * Service reports it has completed initialization and is ready
 * to accept clients.  Dependents waiting on this service's
 * provides[] will not start until READY is received.
 */

/*
 * SVC_OP_REGISTER
 *   req:  svc_register_req
 *   reply: svc_reply { .status }
 *
 * Register a reverse-domain name (e.g., "org.5bsd.sshd").
 * The name is bound to the calling service.  Only one service
 * may own a name at a time.  EEXIST if already registered.
 *
 * After registration, when a client issues LOOKUP for this name,
 * serviced pushes a SVC_OP_NEW_CLIENT notification to this
 * service with the client's channel endpoint attached as a fd.
 */
struct svc_register_req {
	uint32_t	op;		/* SVC_OP_REGISTER */
	uint32_t	flags;		/* reserved, must be 0 */
	char		name[SERVICED_NAME_MAX + 1];
};

/*
 * SVC_OP_UNREGISTER
 *   req:  svc_unregister_req
 *   reply: svc_reply { .status }
 *
 * Deregister a previously registered name.  ENOENT if not
 * registered by this service.
 */
struct svc_unregister_req {
	uint32_t	op;		/* SVC_OP_UNREGISTER */
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
	char		client_label[64]; /* label of the connecting service */
};

/*
 * Generic reply — returned for all service requests.
 */
struct svc_reply {
	int32_t		status;		/* 0 = success, errno on failure */
};

#endif /* SERVICED_SVC_PROTO_H */
