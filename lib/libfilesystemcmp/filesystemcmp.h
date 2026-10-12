/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _FILESYSTEMCMP_H_
#define _FILESYSTEMCMP_H_

/* The system.Filesystem client (formerly part of libservice). */
#include <libservice.h>

__BEGIN_DECLS
int	service_storage_open(struct service_context *, const char *name,
	    int *dirfdp);
/*
 * As service_storage_open(3), but bound the persistent claim's refquota to
 * `quota` bytes (0 = bsdfilesystem's configured default; a value below the daemon's
 * floor is rejected with EINVAL).  service_storage_open is this with quota=0.
 */
int	service_storage_open_quota(struct service_context *, const char *name,
	    uint64_t quota, int *dirfdp);
/*
 * Reclaim (destroy) a persistent storage claim previously granted under `name`,
 * freeing its pool space; symmetric with service_storage_open(3).  The claim is
 * resolved under the caller's own label-scoped namespace, so a caller can never
 * name another's.  Returns 0, or -1 with errno (ENOENT if the claim is absent).
 */
int	service_storage_destroy(struct service_context *, const char *name);

/*
 * One persistent claim's live usage: bytes referenced, the refquota ceiling
 * (0 == none), and bytes still writable under it.  Filled by service_storage_stat(3).
 */
struct service_storage_stat_result {
	uint64_t	used;
	uint64_t	refquota;
	uint64_t	available;
};

/*
 * Report one of the caller's own persistent claims' live usage (an O(1)
 * single-claim query, versus walking the whole namespace with
 * service_storage_list(3)).  Owner-scoped to the caller's label; returns 0 with
 * *out filled, or -1 with errno (ENOENT if the claim is absent).
 */
int	service_storage_stat(struct service_context *, const char *name,
	    struct service_storage_stat_result *out);

/*
 * Raise or lower one of the caller's own persistent claims' refquota after the
 * mint (quota bytes; 0 removes the ceiling).  Same floor and authority as the
 * original claim.  Returns 0, or -1 with errno (EINVAL below the floor, ENOENT
 * if the claim is absent).
 */
int	service_storage_set_quota(struct service_context *, const char *name,
	    uint64_t quota);

/*
 * Snapshots as app-visible time-travel (system.Filesystem #2).  A version is a
 * snapshot of one of the caller's own persistent claims, named by an opaque id
 * (<= SERVICE_STORAGE_VERSION_MAX including the NUL).  All are owner-scoped: a
 * caller can only ever version its own storage.
 */
#define	SERVICE_STORAGE_VERSION_MAX	64

/* Snapshot `name` now; the assigned version id is copied into `version`. */
int	service_storage_snapshot(struct service_context *, const char *name,
	    char *version, size_t vsz);
/* Page the claim's version ids; *cursorp is 0 for the first page and is
 * advanced to the next (0 at the end). */
int	service_storage_list_versions(struct service_context *, const char *name,
	    char (*versions)[SERVICE_STORAGE_VERSION_MAX], size_t max,
	    size_t *countp, uint32_t *cursorp);
/* Roll `name` back to `version` (destructive: newer versions are discarded). */
int	service_storage_rollback(struct service_context *, const char *name,
	    const char *version);
/* Mount `version` read-only and hand back its directory fd (non-destructive).
 * Needs an active session (service_storage BEGIN); the clone is reaped with it. */
int	service_storage_open_version(struct service_context *, const char *name,
	    const char *version, int *dirfdp);

/*
 * Atomic multi-file transactions (system.Filesystem #3): txn_begin hands back a
 * writable staging clone of `name` (its dir fd) plus a txn id; the caller edits
 * the clone, then txn_commit atomically swaps it in (the caller must have
 * released its own claim mount first, else EBUSY) or txn_abort discards it.
 */
int	service_storage_txn_begin(struct service_context *, const char *name,
	    char *txn_id, size_t tsz, int *dirfdp);
int	service_storage_txn_commit(struct service_context *, const char *name,
	    const char *txn_id);
int	service_storage_txn_abort(struct service_context *, const char *name,
	    const char *txn_id);
/*
 * Drop this process's mount anchor on a UNIT claim without destroying it, so it
 * can then be committed to or rolled back (a mounted dataset cannot be swapped
 * or rolled back -- EBUSY).  Idempotent.  Close any delivered directory fd for
 * the claim first.  The _cache variant releases the unit's cache sub-container.
 */
int	service_storage_release(struct service_context *, const char *name);
int	service_storage_release_cache(struct service_context *, const char *name);
/* SHARED / GROUP variants, symmetric with the open_/destroy_ scope variants. */
int	service_storage_release_shared(struct service_context *, const char *name);
int	service_storage_release_group(struct service_context *,
	    const char *group, const char *name);

/*
 * Container scopes (docs/book/src/plane/containers-and-storage.md "Storage and
 * delivery").  service_storage_open(3) claims live in the unit's PRIVATE
 * container Data/<bundle>/<unit>/persistent/<name>.  The bundle-SHARED variant
 * claims Data/<bundle>/shared/persistent/<name>, reachable by every unit of the
 * bundle and reaped with the bundle.  The GROUP variant claims
 * Data/Shared/<group>/persistent/<name>, a cross-bundle group container the
 * unit's bundle must declare membership in (Bundle.ucl `groups`; switchboard
 * stamps the membership on the connection, bsdfilesystem enforces it: EPERM
 * otherwise); it is reaped only when no installed bundle claims the group.
 * `group` is a single safe component.  The destroy variants are symmetric.
 */
/*
 * The unit's CACHE sub-container Data/<bundle>/<unit>/cache/<name>: regenerable
 * data, claimed and reaped exactly like persistent storage (it is part of the
 * unit's container) but kept apart so an operator or a future policy can drop
 * it without touching durable state.  Same rights and delivery as
 * service_storage_open(3).
 */
int	service_storage_open_cache(struct service_context *, const char *name,
	    int *dirfdp);
int	service_storage_destroy_cache(struct service_context *,
	    const char *name);
int	service_storage_open_shared(struct service_context *, const char *name,
	    int *dirfdp);
/*
 * A READ-ONLY view of a bundle-shared store: the same claim as
 * service_storage_open_shared(3) (created if absent, shared with the bundle's
 * writers, reaped with the bundle) but the delivered directory carries
 * read-only Capsicum rights, so every descriptor derived under it can look up,
 * read, stat and map, never write, create, unlink or change attributes
 * (ENOTCAPABLE).  Several units may hold the same store at once, read-only
 * and read-write alike: it is mounted once and shared.  The SHARED ENVIRONMENT
 * is the conventional such store, SERVICE_STORAGE_ENV ("env"): one unit of the
 * bundle writes it through service_storage_open_shared(ctx, "env"), every
 * other unit reads it through service_storage_open_env(3).
 */
#define	SERVICE_STORAGE_ENV	"env"
/*
 * Bound on one storage request to system.Filesystem.  The provider answers
 * a claim in well under a second; a request that gets no reply at all means
 * the worker serving this connection died (its provider was relaunched), and
 * the session is then treated as dead and reopened on the next claim.
 */
#define	SERVICE_STORAGE_CALL_TIMEOUT_MS	10000
int	service_storage_open_shared_readonly(struct service_context *,
	    const char *name, int *dirfdp);
int	service_storage_open_env(struct service_context *, int *dirfdp);
int	service_storage_open_group(struct service_context *, const char *group,
	    const char *name, int *dirfdp);
int	service_storage_destroy_shared(struct service_context *,
	    const char *name);
int	service_storage_destroy_group(struct service_context *,
	    const char *group, const char *name);
/*
 * One enumerated storage claim: its opaque key plus cheap usage accounting
 * (bytes referenced, and the refquota ceiling in bytes; refquota 0 == none).
 * name[] is sized to match bsdfilesystem's BSDFILESYSTEM_NAME_MAX so a claim key round-trips
 * without truncation.  `lifetime` (SERVICE_STORAGE_PERSISTENT / _CACHE) is the
 * namespace the claim lives in, so a caller can service_storage_destroy(3) it
 * with the matching lifetime.
 */
#define	SERVICE_STORAGE_PERSISTENT	0	/* == BSDFILESYSTEM_PERSISTENT */
#define	SERVICE_STORAGE_CACHE		1	/* == BSDFILESYSTEM_CACHE */
struct service_storage_claim {
	char		name[64];
	uint64_t	used;
	uint64_t	refquota;
	uint8_t		lifetime;
};
/*
 * Enumerate the caller's OWN persistent/cache storage claims (those granted via
 * service_storage_open(3)), so a consumer that has forgotten a claim's name can
 * still find it to service_storage_destroy(3) it.  bsdfilesystem scopes the walk to the
 * caller's own label-derived namespace, so this can only ever return the
 * caller's claims and never another label's.  Up to `max` entries are written to
 * `claims` and their number stored in *countp.  Enumeration is paged: pass
 * *cursorp == 0 for the first page; on return *cursorp is nonzero when more
 * claims remain (re-issue with that value) and 0 when the last page was
 * returned.  A buffer of SERVICE_STORAGE_LIST_MAX entries always holds a whole
 * page; a smaller `max` that cannot hold the returned page fails EMSGSIZE
 * (never a silent truncation).  Returns 0, or -1 with errno.
 */
#define	SERVICE_STORAGE_LIST_MAX	32	/* claims per page (== provider) */
int	service_storage_list(struct service_context *,
	    struct service_storage_claim *claims, size_t max, size_t *countp,
	    uint32_t *cursorp);
/*
 * As service_storage_list(3), but enumerate the bundle-SHARED
 * (Data/<bundle>/shared) or a GROUP (Data/Shared/<group>) container the caller
 * can claim in, so a forgotten SHARED/GROUP claim is discoverable to
 * service_storage_destroy_shared(3) / service_storage_destroy_group(3).  The
 * group variant enumerates only a group the caller's bundle declares membership
 * in (EPERM-equivalent: an empty page otherwise).  Same paging and owner-scoping
 * as the unit list.
 */
int	service_storage_list_shared(struct service_context *,
	    struct service_storage_claim *claims, size_t max, size_t *countp,
	    uint32_t *cursorp);
int	service_storage_list_group(struct service_context *, const char *group,
	    struct service_storage_claim *claims, size_t max, size_t *countp,
	    uint32_t *cursorp);
/*
 * Open this service's writable, label-scoped configuration area (the well-known
 * "config" claim under its per-service home) and return its mounted directory
 * root.  A place for configuration files outside the shared UNIX directories,
 * scoped so a service only ever reaches its own.  Thin wrapper over
 * service_storage_open(3).  Returns 0 with *dirfdp set, or -1 with errno.
 */
int	service_open_config(struct service_context *, int *dirfdp);

/*
 * Open an existing filesystem path via bsdfilesystem's per-label policy (default-deny)
 * and return a Capsicum-rights-limited, close-on-exec descriptor.  Lets a
 * sandboxed service reach a device node, shared directory, or config file it
 * cannot open by path itself, with nothing declared in the manifest.  `rights`
 * is a SERVICE_OPEN_* mask; `is_dir` requires a directory.  Returns 0 with *fdp
 * set, or -1 with errno (EACCES if the label is not granted the path).
 */
#define	SERVICE_OPEN_READ	0x1u	/* CAP_READ */
#define	SERVICE_OPEN_WRITE	0x2u	/* CAP_WRITE */
#define	SERVICE_OPEN_EXEC	0x4u	/* CAP_FEXECVE */
#define	SERVICE_OPEN_LOOKUP	0x8u	/* CAP_LOOKUP (directories, for openat) */
#define	SERVICE_OPEN_IOCTL	0x10u	/* CAP_IOCTL + CAP_EVENT (device nodes) */
int	service_open_isolated(struct service_context *, const char *path,
	    unsigned rights, int is_dir, int *fdp);

__END_DECLS

#endif
