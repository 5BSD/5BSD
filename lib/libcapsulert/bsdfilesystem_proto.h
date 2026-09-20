/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) storage daemon protocol.
 *
 * Shared between bsdfilesystem(8) and its clients (libbsdfilesystem, tzfsctl(8), and
 * libservice's service_storage_open(3)).  bsdfilesystem is a socket-free
 * service_provider: there is no AF_UNIX socket and no path to name.  A client
 * reaches it over a held mac_capability channel obtained by name (service_open
 * of BSDFILESYSTEM_SERVICE_NAME), exactly like every other capability-plane daemon;
 * switchboard brokers nothing here.  A request is the channel message payload and
 * the minted TrustedZFS handle rides back as the reply's single SCM_RIGHTS fd,
 * never as an integer in the payload.
 *
 * bsdfilesystem cap_enter()s once its pool handle is open, mints every handle from its
 * retained pool capability, and scopes each client to a per-service dataset
 * subtree derived from the connecting channel's unforgeable label (never a wire
 * argument), so a client can only ever reach its own storage.
 */

#ifndef BSDFILESYSTEM_PROTO_H
#define BSDFILESYSTEM_PROTO_H

#include <sys/types.h>
#include <sys/param.h>		/* PATH_MAX */

#define	BSDFILESYSTEM_PROTO_VERSION_MAJOR	0
#define	BSDFILESYSTEM_PROTO_VERSION_MINOR	5
#define	BSDFILESYSTEM_PROTO_VERSION_PATCH	0
#define	BSDFILESYSTEM_PROTO_VERSION		6

/* The well-known name a client resolves with service_open(3) to reach bsdfilesystem. */
#define	BSDFILESYSTEM_SERVICE_NAME		"system.Filesystem"

/*
 * Field sizes.  dataset[] matches ORT_STORAGE_DATASET_MAX (== the ZFS max
 * dataset name length) so a resolved name round-trips through the manifest
 * claim without truncation.
 */
#define	BSDFILESYSTEM_NAME_MAX			64	/* opaque dataset key, incl. NUL */
#define	BSDFILESYSTEM_DATASET_MAX		256	/* == ORT_STORAGE_DATASET_MAX */
#define	BSDFILESYSTEM_SESSION_MAX		33	/* 128-bit hex id + NUL */

/*
 * Lifetimes.  Numerically identical to ORT_STORAGE_* so a manifest claim's
 * lifetime maps straight through; kept as distinct names so bsdfilesystem clients do
 * not have to pull in the capsulert manifest header.
 */
#define	BSDFILESYSTEM_PERSISTENT		0
#define	BSDFILESYSTEM_CACHE			1
#define	BSDFILESYSTEM_BOOT			2
#define	BSDFILESYSTEM_LEASE			3

/*
 * Operation codes — first 4 bytes of every request payload.
 */
#define	BSDFILESYSTEM_OP_REQUEST		1	/* mint a storage handle */
#define	BSDFILESYSTEM_OP_RELEASE		2	/* tear down a lease claim */
#define	BSDFILESYSTEM_OP_PING			4	/* liveness check */
#define	BSDFILESYSTEM_OP_BEGIN_SESSION		5	/* select/reconcile lease generation */
#define	BSDFILESYSTEM_OP_OPEN			6	/* open an isolated path descriptor */
#define	BSDFILESYSTEM_OP_DESTROY		7	/* reclaim a persistent/cache claim */
#define	BSDFILESYSTEM_OP_LIST			8	/* enumerate the caller's own claims */

/*
 * BSDFILESYSTEM_OP_OPEN
 *   req:   struct bsdfilesystem_open_request
 *   reply: struct bsdfilesystem_reply { .status }
 *   reply_fds[0] = the opened, rights-limited descriptor (on success)
 *
 * Ask bsdfilesystem to open an existing filesystem path on the caller's behalf and hand
 * back a Capsicum-rights-limited descriptor.  This is how a sandboxed
 * (capability-mode) service reaches an existing path it cannot name itself — a
 * device node, a shared directory, a socket — without the manifest declaring
 * anything.  Authority is the connecting channel's unforgeable label: bsdfilesystem
 * consults its own per-label policy (default-deny) and opens only the exact
 * paths that label is granted, so a compromised consumer cannot widen its reach.
 * bsdfilesystem opens relative to a root directory fd it retained before cap_enter(),
 * so the open is capsicum-legal; the returned fd carries no more than the
 * requested rights.
 */
#define	BSDFILESYSTEM_OPEN_READ			0x1u	/* CAP_READ */
#define	BSDFILESYSTEM_OPEN_WRITE		0x2u	/* CAP_WRITE */
#define	BSDFILESYSTEM_OPEN_EXEC			0x4u	/* CAP_FEXECVE */
#define	BSDFILESYSTEM_OPEN_LOOKUP		0x8u	/* CAP_LOOKUP (dirs, for openat) */
#define	BSDFILESYSTEM_OPEN_IOCTL		0x10u	/* CAP_IOCTL (device control nodes) */
#define	BSDFILESYSTEM_OPEN_RIGHTS_ALL \
	(BSDFILESYSTEM_OPEN_READ | BSDFILESYSTEM_OPEN_WRITE | BSDFILESYSTEM_OPEN_EXEC | \
	 BSDFILESYSTEM_OPEN_LOOKUP | BSDFILESYSTEM_OPEN_IOCTL)

/*
 * bsdfilesystem_request.deliver — the shape of the descriptor bsdfilesystem returns for a
 * ZH_MOUNT claim.  DELIVER_HANDLE (default, 0) returns the TrustedZFS dataset
 * handle and the caller mounts it itself.  DELIVER_MOUNTED asks bsdfilesystem — which
 * is privileged and outside capability mode — to perform the ZFS mount and
 * return the mounted directory descriptor, so a born-in-capability-mode
 * consumer receives a ready store dir without ever issuing the mount (which
 * the sandbox forbids at the VFS layer).
 */
#define	BSDFILESYSTEM_DELIVER_HANDLE		0u
#define	BSDFILESYSTEM_DELIVER_MOUNTED		1u
/*
 * DELIVER_MOUNTED_RO: as DELIVER_MOUNTED, but the delivered directory carries
 * read-only Capsicum rights (lookup, read, stat, mmap-read; no write, create,
 * unlink, or attribute change), so every descriptor derived under it is
 * read-only too.  The store itself is mounted read-write and shared with the
 * bundle's writers: a read-only claim never changes the store's ownership or
 * writability, it only narrows this caller's view.  This is how a bundle's
 * units read one shared environment (Data/<bundle>/shared/env) that a
 * designated unit writes.
 */
#define	BSDFILESYSTEM_DELIVER_MOUNTED_RO	2u

struct bsdfilesystem_open_request {
	uint32_t	op;		/* BSDFILESYSTEM_OP_OPEN */
	uint32_t	rights;		/* BSDFILESYSTEM_OPEN_* mask (at least one bit) */
	uint8_t		is_dir;		/* 1 = require a directory (O_DIRECTORY) */
	uint8_t		_reserved[7];
	char		path[PATH_MAX];	/* absolute path to open */
};

/*
 * BSDFILESYSTEM_OP_REQUEST
 *   req:   struct bsdfilesystem_request
 *   reply: struct bsdfilesystem_reply { .status, .dataset }
 *   reply_fds[0] = TrustedZFS dataset handle fd (on success)
 *
 * A bare dataset claim: the named dataset is opened (persistent) or created
 * then opened (ephemeral), exactly as capsule's handle_mint_storage did.
 * rights are the ZH_* mask to grant; the returned handle carries no more than
 * these.  quota, when nonzero, is this claim's refquota ceiling in bytes and
 * overrides the daemon's configured default_refquota; 0 selects the default.
 * A too-small quota (below the daemon's floor) is rejected with EINVAL.
 */
struct bsdfilesystem_request {
	uint32_t	op;			/* BSDFILESYSTEM_OP_REQUEST */
	uint32_t	flags;			/* ZHF_* (subtree, etc.) */
	uint64_t	rights;			/* ZH_* mask to grant */
	uint64_t	quota;			/* per-claim refquota, bytes; 0=default */
	uint8_t		lifetime;		/* BSDFILESYSTEM_* lifecycle */
	uint8_t		deliver;		/* BSDFILESYSTEM_DELIVER_* (fd shape) */
	uint8_t		scope;			/* BSDFILESYSTEM_SCOPE_* (durable claims) */
	uint8_t		_reserved[1];
	uint32_t	owner_uid;		/* chown dataset root at mint; 0=skip */
	uint32_t	owner_gid;
	char		dataset[BSDFILESYSTEM_NAME_MAX]; /* opaque stable leaf key */
	char		session[BSDFILESYSTEM_SESSION_MAX];
	/*
	 * Container scope of a durable (persistent/cache) claim
	 * (docs/capability-container-model.md "Storage and delivery"):
	 *   UNIT    Data/<bundle>/<unit>/   the caller's private container;
	 *   SHARED  Data/<bundle>/shared/   shared by the bundle's units;
	 *   GROUP   Data/Shared/<group>/    a cross-bundle group container the
	 *           caller's bundle declares membership in (`group` names it).
	 * `group` must be empty unless scope is GROUP.  Ephemeral claims ignore
	 * scope.
	 */
	char		group[BSDFILESYSTEM_NAME_MAX];
};

#define	BSDFILESYSTEM_SCOPE_UNIT		0u
#define	BSDFILESYSTEM_SCOPE_SHARED		1u
#define	BSDFILESYSTEM_SCOPE_GROUP		2u

/*
 * BSDFILESYSTEM_OP_RELEASE
 *   req:   struct bsdfilesystem_request (op, name; rights/flags ignored)
 *   reply: struct bsdfilesystem_reply { .status }
 *
 * Destroy the lease dataset previously granted under this key.  A missing
 * target is success (idempotent stop).
 */

/*
 * BSDFILESYSTEM_OP_DESTROY
 *   req:   struct bsdfilesystem_request (op, dataset, lifetime; rights/flags/quota/
 *          session all zero)
 *   reply: struct bsdfilesystem_reply { .status }
 *
 * Reclaim a persistent (BSDFILESYSTEM_PERSISTENT) or cache (BSDFILESYSTEM_CACHE) claim
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
 * BSDFILESYSTEM_OP_LIST
 *   req:   struct bsdfilesystem_list_request (op, cursor; flags/_reserved zero)
 *   reply: struct bsdfilesystem_list_reply { .status, .count, .next_cursor, .entries }
 *   no fd delivered (data-only reply)
 *
 * Enumerate the CALLER's own persistent/cache claims.  A granted storage handle
 * is scoped to a single claim leaf, so a consumer that has forgotten a claim's
 * name cannot DESTROY it; LIST closes that gap.  It is strictly owner-scoped:
 * bsdfilesystem walks only the caller's own namespace (derive_ns of the connecting
 * channel's unforgeable label, exactly as REQUEST/DESTROY do), so a caller can
 * never observe — let alone name — another label's claims.  Authority is the
 * held channel's identity, never a wire argument; there is no way to ask for a
 * different label's list.  Each entry folds in the claim's cheaply-available
 * usage (bytes referenced) and refquota ceiling (0 == none) from the same walk,
 * and carries the claim's `lifetime` (BSDFILESYSTEM_PERSISTENT / _CACHE) so a
 * consumer can DESTROY it under the correct namespace; both the persistent and
 * the cache namespaces are walked and merged into the one sorted, paged set.
 *
 * The reply carries at most BSDFILESYSTEM_LIST_MAX entries; when the caller has more,
 * next_cursor is nonzero and the caller re-issues LIST with request.cursor set
 * to it to fetch the next page.  next_cursor == 0 marks the final page.  A
 * caller with no namespace yet lists empty (count 0), never an error.
 */
#define	BSDFILESYSTEM_LIST_MAX			32	/* claim entries per reply page */

struct bsdfilesystem_list_request {
	uint32_t	op;		/* BSDFILESYSTEM_OP_LIST */
	uint32_t	flags;		/* reserved; must be 0 */
	uint32_t	cursor;		/* 0 = first page; else a prior next_cursor */
	uint32_t	_reserved;	/* must be 0 */
};

/* One enumerated claim: its opaque key plus cheap usage accounting. */
struct bsdfilesystem_claim_entry {
	char		name[BSDFILESYSTEM_NAME_MAX];	/* claim key (NUL-terminated) */
	uint64_t	used;			/* bytes referenced */
	uint64_t	refquota;		/* refquota ceiling, bytes; 0=none */
	uint8_t		lifetime;		/* BSDFILESYSTEM_PERSISTENT / _CACHE */
	uint8_t		_reserved[7];		/* must be zero */
};

struct bsdfilesystem_list_reply {
	int32_t		status;		/* 0 or errno */
	uint32_t	count;		/* entries filled in this page */
	uint32_t	next_cursor;	/* 0 = last page; else pass back as cursor */
	uint32_t	_reserved;
	struct bsdfilesystem_claim_entry entries[BSDFILESYSTEM_LIST_MAX];
};

/*
 * Reply for REQUEST/RELEASE/PING.  status is an errno (0 == success).  On a
 * successful REQUEST the handle fd rides SCM_RIGHTS and dataset[] carries the
 * resolved dataset name for audit; on other replies dataset[] is empty.
 */
struct bsdfilesystem_reply {
	int32_t		status;			/* 0 or errno */
	uint32_t	_reserved;
	char		dataset[BSDFILESYSTEM_DATASET_MAX];
};

#endif /* BSDFILESYSTEM_PROTO_H */
