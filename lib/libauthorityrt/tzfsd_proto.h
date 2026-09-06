/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) storage daemon protocol.
 *
 * Shared between tzfsd(8) and its clients (libtzfsd, tzfsctl(8), and
 * libservice's service_storage_open(3)).  tzfsd is a socket-free
 * service_provider: there is no AF_UNIX socket and no path to name.  A client
 * reaches it over a held mac_capability channel obtained by name (service_open
 * of TZFSD_SERVICE_NAME), exactly like every other capability-plane daemon;
 * serviced brokers nothing here.  A request is the channel message payload and
 * the minted TrustedZFS handle rides back as the reply's single SCM_RIGHTS fd,
 * never as an integer in the payload.
 *
 * tzfsd cap_enter()s once its pool handle is open, mints every handle from its
 * retained pool capability, and scopes each client to a per-service dataset
 * subtree derived from the connecting channel's unforgeable label (never a wire
 * argument), so a client can only ever reach its own storage.
 */

#ifndef TZFSD_PROTO_H
#define TZFSD_PROTO_H

#include <sys/types.h>
#include <sys/param.h>		/* PATH_MAX */

#define	TZFSD_PROTO_VERSION_MAJOR	0
#define	TZFSD_PROTO_VERSION_MINOR	2
#define	TZFSD_PROTO_VERSION_PATCH	0
#define	TZFSD_PROTO_VERSION		3

/* The well-known name a client resolves with service_open(3) to reach tzfsd. */
#define	TZFSD_SERVICE_NAME		"system.Filesystem"

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
#define	TZFSD_OP_OPEN			6	/* open an isolated path descriptor */
#define	TZFSD_OP_DESTROY		7	/* reclaim a persistent/cache claim */

/*
 * TZFSD_OP_OPEN
 *   req:   struct tzfsd_open_request
 *   reply: struct tzfsd_reply { .status }
 *   reply_fds[0] = the opened, rights-limited descriptor (on success)
 *
 * Ask tzfsd to open an existing filesystem path on the caller's behalf and hand
 * back a Capsicum-rights-limited descriptor.  This is how a sandboxed
 * (capability-mode) service reaches an existing path it cannot name itself — a
 * device node, a shared directory, a socket — without the manifest declaring
 * anything.  Authority is the connecting channel's unforgeable label: tzfsd
 * consults its own per-label policy (default-deny) and opens only the exact
 * paths that label is granted, so a compromised consumer cannot widen its reach.
 * tzfsd opens relative to a root directory fd it retained before cap_enter(),
 * so the open is capsicum-legal; the returned fd carries no more than the
 * requested rights.
 */
#define	TZFSD_OPEN_READ			0x1u	/* CAP_READ */
#define	TZFSD_OPEN_WRITE		0x2u	/* CAP_WRITE */
#define	TZFSD_OPEN_EXEC			0x4u	/* CAP_FEXECVE */
#define	TZFSD_OPEN_LOOKUP		0x8u	/* CAP_LOOKUP (dirs, for openat) */
#define	TZFSD_OPEN_IOCTL		0x10u	/* CAP_IOCTL (device control nodes) */
#define	TZFSD_OPEN_RIGHTS_ALL \
	(TZFSD_OPEN_READ | TZFSD_OPEN_WRITE | TZFSD_OPEN_EXEC | \
	 TZFSD_OPEN_LOOKUP | TZFSD_OPEN_IOCTL)

/*
 * tzfsd_request.deliver — the shape of the descriptor tzfsd returns for a
 * ZH_MOUNT claim.  DELIVER_HANDLE (default, 0) returns the TrustedZFS dataset
 * handle and the caller mounts it itself.  DELIVER_MOUNTED asks tzfsd — which
 * is privileged and outside capability mode — to perform the ZFS mount and
 * return the mounted directory descriptor, so a born-in-capability-mode
 * consumer receives a ready store dir without ever issuing the mount (which
 * the sandbox forbids at the VFS layer).
 */
#define	TZFSD_DELIVER_HANDLE		0u
#define	TZFSD_DELIVER_MOUNTED		1u

struct tzfsd_open_request {
	uint32_t	op;		/* TZFSD_OP_OPEN */
	uint32_t	rights;		/* TZFSD_OPEN_* mask (at least one bit) */
	uint8_t		is_dir;		/* 1 = require a directory (O_DIRECTORY) */
	uint8_t		_reserved[7];
	char		path[PATH_MAX];	/* absolute path to open */
};

/*
 * TZFSD_OP_REQUEST
 *   req:   struct tzfsd_request
 *   reply: struct tzfsd_reply { .status, .dataset }
 *   reply_fds[0] = TrustedZFS dataset handle fd (on success)
 *
 * A bare dataset claim: the named dataset is opened (persistent) or created
 * then opened (ephemeral), exactly as authorityd's handle_mint_storage did.
 * rights are the ZH_* mask to grant; the returned handle carries no more than
 * these.  quota, when nonzero, is this claim's refquota ceiling in bytes and
 * overrides the daemon's configured default_refquota; 0 selects the default.
 * A too-small quota (below the daemon's floor) is rejected with EINVAL.
 */
struct tzfsd_request {
	uint32_t	op;			/* TZFSD_OP_REQUEST */
	uint32_t	flags;			/* ZHF_* (subtree, etc.) */
	uint64_t	rights;			/* ZH_* mask to grant */
	uint64_t	quota;			/* per-claim refquota, bytes; 0=default */
	uint8_t		lifetime;		/* TZFSD_* lifecycle */
	uint8_t		deliver;		/* TZFSD_DELIVER_* (fd shape) */
	uint8_t		_reserved[2];
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
 * TZFSD_OP_DESTROY
 *   req:   struct tzfsd_request (op, dataset, lifetime; rights/flags/quota/
 *          session all zero)
 *   reply: struct tzfsd_reply { .status }
 *
 * Reclaim a persistent (TZFSD_PERSISTENT) or cache (TZFSD_CACHE) claim
 * previously granted under this key, freeing its pool space.  Unlike REQUEST
 * these claims are never torn down implicitly, so without this op a claim can
 * only ever be created — the persistent tree grows without bound.  The claim is
 * resolved under the CALLER's own namespace (derived from the connecting
 * channel's unforgeable label, exactly as REQUEST does), so a caller can never
 * name — and therefore never destroy — another label's claim.  It carries no
 * path or fd.  An absent claim replies ENOENT (not idempotent success, so a
 * caller can tell a real reclaim from a no-op); status 0 on success.
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
