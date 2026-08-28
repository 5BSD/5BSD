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

/* Well-known listening socket for non-sandboxed clients. */
#define	TZFSD_SOCK_PATH			"/var/run/tzfsd.sock"

/* Readiness handshake file, mirroring serviced.ready. */
#define	TZFSD_READY_PATH		"/var/run/tzfsd.ready"

/*
 * Field sizes.  dataset[] matches ORT_STORAGE_DATASET_MAX (== the ZFS max
 * dataset name length) so a resolved name round-trips through the manifest
 * claim without truncation.
 */
#define	TZFSD_FLAVOR_MAX		32	/* incl. NUL */
#define	TZFSD_NAME_MAX			64	/* opaque dataset key, incl. NUL */
#define	TZFSD_DATASET_MAX		256	/* == ORT_STORAGE_DATASET_MAX */
#define	TZFSD_MAX_FLAVORS		16	/* LIST_FLAVORS reply cap */
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
#define	TZFSD_OP_REQUEST		1	/* mint/clone a storage handle */
#define	TZFSD_OP_RELEASE		2	/* tear down a lease claim */
#define	TZFSD_OP_LIST_FLAVORS		3	/* enumerate offered flavors */
#define	TZFSD_OP_PING			4	/* liveness check */
#define	TZFSD_OP_BEGIN_SESSION		5	/* select/reconcile lease generation */

/*
 * TZFSD_OP_REQUEST
 *   req:   struct tzfsd_request
 *   reply: struct tzfsd_reply { .status, .dataset }
 *   reply_fds[0] = TrustedZFS dataset handle fd (on success)
 *
 * flavor[0] == '\0' requests a bare dataset claim (no template): the named
 * dataset is opened (persistent) or created then opened (ephemeral), exactly
 * as authorityd's handle_mint_storage did.  A non-empty flavor clones that
 * flavor's template origin into the bundle's ephemeral/persistent space and
 * returns a handle on the clone.  rights are the ZH_* mask to grant; the
 * returned handle carries no more than these.
 */
struct tzfsd_request {
	uint32_t	op;			/* TZFSD_OP_REQUEST */
	uint32_t	flags;			/* ZHF_* (subtree, etc.) */
	uint64_t	rights;			/* ZH_* mask to grant */
	uint8_t		lifetime;		/* TZFSD_* lifecycle */
	uint8_t		_reserved[7];
	char		flavor[TZFSD_FLAVOR_MAX];
	char		dataset[TZFSD_NAME_MAX]; /* opaque stable leaf key */
	char		session[TZFSD_SESSION_MAX];
};

/*
 * TZFSD_OP_RELEASE
 *   req:   struct tzfsd_request (op, name; flavor/rights/flags ignored)
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

/*
 * TZFSD_OP_LIST_FLAVORS
 *   req:   struct tzfsd_request (op only)
 *   reply: struct tzfsd_flavor_list
 *
 * Enumerates the flavors tzfsd currently offers.  A flavor whose template is
 * unavailable (not baked, not built, disabled) is omitted, so the list is the
 * exact set tzfsd_request will honor.
 */
struct tzfsd_flavor {
	char		name[TZFSD_FLAVOR_MAX];
	uint8_t		is_default;		/* the opinionated default */
	uint8_t		_reserved[7];
};
struct tzfsd_flavor_list {
	int32_t		status;			/* 0 or errno */
	uint32_t	count;			/* valid entries in flavors[] */
	struct tzfsd_flavor flavors[TZFSD_MAX_FLAVORS];
};

#endif /* TZFSD_PROTO_H */
