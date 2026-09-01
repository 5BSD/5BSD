/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) storage daemon protocol.
 *
 * Shared between tzfsd(8), its clients (libtzfsd, serviced(8), tzfsctl(8)),
 * and authorityd(8) during the storage-ownership transition.  Requests are
 * exchanged over an AF_UNIX SOCK_SEQPACKET socket; the minted TrustedZFS
 * handle is returned as an SCM_RIGHTS-attached fd on the reply, never as an
 * integer in the payload.
 *
 * A non-sandboxed client connects TZFSD_SOCK_PATH; a sandboxed one (e.g. a
 * capability service, or serviced after cap_enter) is handed a pre-connected
 * channel fd at bootstrap and never names the path.  tzfsd itself cap_enter()s
 * once its pool handle and listening socket are open, and mints every handle
 * from its retained pool capability.
 */

#ifndef TZFSD_PROTO_H
#define TZFSD_PROTO_H

#include <sys/types.h>

#define	TZFSD_PROTO_VERSION_MAJOR	0
#define	TZFSD_PROTO_VERSION_MINOR	1
#define	TZFSD_PROTO_VERSION_PATCH	0
#define	TZFSD_PROTO_VERSION		2

/*
 * tzfsd is a socket-free service_provider: clients reach it over a held
 * mac_capability channel obtained by name (service_open), exactly like every
 * other capability-plane daemon.  The request/reply structs below are the
 * channel message payloads (a request is the message data; a granted handle
 * rides back as the reply's single SCM fd).
 */
#define	TZFSD_SERVICE_NAME		"system.Storage"

/*
 * Field sizes.  dataset[] matches ORT_STORAGE_DATASET_MAX (== the ZFS max
 * dataset name length) so a resolved name round-trips through the manifest
 * claim without truncation.
 */
#define	TZFSD_NAME_MAX			64	/* opaque dataset key, incl. NUL */
#define	TZFSD_DATASET_MAX		256	/* == ORT_STORAGE_DATASET_MAX */
#define	TZFSD_SESSION_MAX		33	/* 128-bit hex id + NUL */

/*
 * Lifetimes.  Numerically identical to ORT_STORAGE_* so a manifest claim's
 * lifetime maps straight through; kept as distinct names so tzfsd clients do
 * not have to pull in the authorityrt manifest header.
 */
#define	TZFSD_PERSISTENT		0
#define	TZFSD_CACHE			1
#define	TZFSD_BOOT			2
#define	TZFSD_LEASE			3

/*
 * Operation codes — first 4 bytes of every request payload.
 */
#define	TZFSD_OP_REQUEST		1	/* mint a storage handle */
#define	TZFSD_OP_RELEASE		2	/* tear down a lease claim */
#define	TZFSD_OP_PING			4	/* liveness check */
#define	TZFSD_OP_BEGIN_SESSION		5	/* select/reconcile lease generation */

/*
 * TZFSD_OP_REQUEST
 *   req:   struct tzfsd_request
 *   reply: struct tzfsd_reply { .status, .dataset }
 *   reply_fds[0] = TrustedZFS dataset handle fd (on success)
 *
 * A bare dataset claim: the named dataset is opened (persistent) or created
 * then opened (ephemeral), exactly as authorityd's handle_mint_storage did.
 * rights are the ZH_* mask to grant; the returned handle carries no more than
 * these.
 */
struct tzfsd_request {
	uint32_t	op;			/* TZFSD_OP_REQUEST */
	uint32_t	flags;			/* ZHF_* (subtree, etc.) */
	uint64_t	rights;			/* ZH_* mask to grant */
	uint8_t		lifetime;		/* TZFSD_* lifecycle */
	uint8_t		_reserved[3];
	uint32_t	owner_uid;		/* chown dataset root at mint; 0=skip */
	uint32_t	owner_gid;
	char		dataset[TZFSD_NAME_MAX]; /* opaque stable leaf key */
	char		session[TZFSD_SESSION_MAX];
};

/*
 * TZFSD_OP_RELEASE
 *   req:   struct tzfsd_request (op, name; rights/flags ignored)
 *   reply: struct tzfsd_reply { .status }
 *
 * Destroy the lease dataset previously granted under this key.  A missing
 * target is success (idempotent stop).
 */

/*
 * Reply for REQUEST/RELEASE/PING.  status is an errno (0 == success).  On a
 * successful REQUEST the handle fd rides SCM_RIGHTS and dataset[] carries the
 * resolved dataset name for audit; on other replies dataset[] is empty.
 */
struct tzfsd_reply {
	int32_t		status;			/* 0 or errno */
	uint32_t	_reserved;
	char		dataset[TZFSD_DATASET_MAX];
};

#endif /* TZFSD_PROTO_H */
