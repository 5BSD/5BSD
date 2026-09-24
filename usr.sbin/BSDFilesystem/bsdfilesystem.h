/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * bsdfilesystem(8) — the [TZFS] storage daemon.  Internal definitions.
 */

#ifndef BSDFILESYSTEM_H
#define BSDFILESYSTEM_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "bsdfilesystem_proto.h"

#define	BSDFILESYSTEM_MAXPATH		256	/* dataset name buffer */
#define	BSDFILESYSTEM_DEFAULT_CONF	"/Capabilities/Config/bsdfilesystem.ucl"

/*
 * Default per-claim space ceiling (refquota, bytes).  Bounds any single claim
 * so one tenant cannot fill the pool and starve the others; overridable via the
 * "default_refquota" config key, 0 disables the ceiling.
 */
#define	BSDFILESYSTEM_DEFAULT_REFQUOTA	(1ULL << 30)	/* 1 GiB */
/*
 * Container reconcile cadence: seconds between timer passes, which is also the
 * grace window (an orphan is destroyed only when seen gone on two consecutive
 * passes).  "reclaim_interval" config key; bounded so a typo can neither make
 * the grace vanish nor stop reclaim for a day.
 */
#define	BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT	300
#define	BSDFILESYSTEM_RECLAIM_INTERVAL_MIN	10
#define	BSDFILESYSTEM_RECLAIM_INTERVAL_MAX	86400

/*
 * Floor for a per-request refquota override (bsdfilesystem_request.quota).  ZFS refquota
 * must cover a dataset's own metadata overhead; an absurdly small ceiling makes
 * a claim useless (even an empty dataset cannot be written).  Reject anything
 * below this with EINVAL.
 */
#define	BSDFILESYSTEM_MIN_REFQUOTA	(1ULL << 20)	/* 1 MiB */

/*
 * Per-label isolated-open policy (BSDFILESYSTEM_OP_OPEN), loaded from the config file's
 * "open_paths" array.  Default-deny: a client may open a path only if some entry
 * matches its unforgeable label exactly and covers the requested rights.  Exact
 * path match only — no prefixes or globs — so a compromised consumer cannot walk
 * outside the precise paths its label is granted.
 */
#define	BSDFILESYSTEM_MAX_OPEN_POLICY	32
struct bsdfilesystem_open_policy {
	char		label[64];		/* == service_identity.client_label */
	char		path[BSDFILESYSTEM_MAXPATH];	/* absolute path (or prefix) granted */
	uint32_t	rights;			/* BSDFILESYSTEM_OPEN_* the label may request */
	bool		prefix;			/* path is a prefix: matches path + one
						 * trailing non-'/' component (e.g. a
						 * device unit /dev/vhid -> /dev/vhidN),
						 * never a subdirectory */
};

struct bsdfilesystem_config {
	char		pool[BSDFILESYSTEM_MAXPATH];
	char		base[BSDFILESYSTEM_MAXPATH];		/* zroot/Capabilities */
	char		persistent[BSDFILESYSTEM_MAXPATH];	/* .../persistent */
	char		ephemeral[BSDFILESYSTEM_MAXPATH];	/* .../ephemeral */
	char		mountpoint[BSDFILESYSTEM_MAXPATH];	/* /Capabilities */
	char		ephemeral_sync[16];		/* zfs sync= value */
	uint64_t	default_refquota;		/* per-claim ceiling, bytes; 0=off */
	unsigned	reclaim_interval;		/* timer-pass grace, seconds */
	unsigned	staging_idle_grace;		/* idle-reap min clone age, seconds */
	struct bsdfilesystem_open_policy open_policy[BSDFILESYSTEM_MAX_OPEN_POLICY];
	unsigned	nopen_policy;
};

/*
 * Retained capability handles, opened by name before cap_enter() and used to
 * derive/create/clone/destroy in capability mode thereafter.  ZH_ALL_RIGHTS +
 * ZHF_SUBTREE; the daemon attenuates before handing anything to a client.
 */
struct bsdfilesystem_state {
	struct bsdfilesystem_config cfg;
	int		persistent_fd;	/* handle on cfg.persistent */
	int		ephemeral_fd;	/* handle on cfg.ephemeral */
	int		boot_fd;	/* current kernel-boot generation */
	int		lease_fd;	/* current switchboard session, per connection */
	char		boot_name[BSDFILESYSTEM_NAME_MAX];
	char		lease_name[BSDFILESYSTEM_NAME_MAX];
	/*
	 * Plain root ("/") directory fd, opened before cap_enter().  Used to
	 * openat(2) an isolated path descriptor for BSDFILESYSTEM_OP_OPEN in capability
	 * mode (openat from a retained dir fd with a relative path is
	 * capsicum-legal, unlike open() by absolute path).
	 */
	int		root_fd;
	/*
	 * Borrowed /dev/zfs descriptor from the switchboard-delivered /dev
	 * directory (openat(dev_dirfd, "zfs")).  A born-in-capmode broker cannot
	 * open ZFS_DEV by name, so the pool-root mint runs on this fd
	 * (tzfs_pool_open_fd).  -1 when ZFS is unavailable (isolated-open only).
	 */
	int		zfs_fd;
};

/* config.c */
void	bsdfilesystem_config_defaults(struct bsdfilesystem_config *cfg);
int	bsdfilesystem_config_load(struct bsdfilesystem_config *cfg, const char *path);
/* Load from a descriptor (born-in-capmode: openat under the delivered "/"); takes fd. */
int	bsdfilesystem_config_load_fd(struct bsdfilesystem_config *cfg, int fd);

/* layout.c */
int	bsdfilesystem_ensure_zfs(int dev_dirfd);
bool	bsdfilesystem_pool_missing_expected(int error);
int	bsdfilesystem_layout_provision(struct bsdfilesystem_state *st);
int	bsdfilesystem_ensure_path(int root_fd, const char *relpath, uint64_t rights);
/* Live mounted claims one connection may hold at once (persistent + cache +
 * shared stores of a busy unit fit comfortably). */
#define	BSDFILESYSTEM_CONN_MAX_CLAIMS	32
/* Datasets (distinct claim names) one namespace may hold; a NEW claim past
 * this is refused EDQUOT, existing claims always reopen. */
#define	BSDFILESYSTEM_NS_MAX_CLAIMS	64
/* Data/Shared/<group>/ containers live under this reserved bundle name. */
#define	BSDFILESYSTEM_SHARED_DIR	"Shared"
int	bsdfilesystem_count_children(int fd);
int	bsdfilesystem_count_snapshots(int fd);
/*
 * Maximum snapshots one claim may hold.  refquota bounds only a claim's live
 * referenced data, not the space its snapshots pin, and there is no per-snapshot
 * destroy verb, so without a cap a caller could retain unbounded snapshot space.
 * Each snapshot's unique data is bounded by refquota, so bounding the count
 * bounds total snapshot space.  Generous -- legitimate versioning stays well
 * under it.
 */
#define	BSDFILESYSTEM_MAX_SNAPSHOTS	256
/* A mount racing the previous holder's teardown is retried this often. */
#define	BSDFILESYSTEM_MOUNT_BUSY_RETRIES	20
#define	BSDFILESYSTEM_MOUNT_BUSY_WAIT_US	100000
int	bsdfilesystem_limit_readonly_dir(int dfd);
int	bsdfilesystem_destroy_tree(int parent_fd, const char *relname);
int	bsdfilesystem_destroy_snapshots(int target);
int	bsdfilesystem_nvl_names(const void *buf, size_t len, char ***namesp,
	    size_t *countp);
void	bsdfilesystem_nvl_names_free(char **names, size_t count);

int	bsdfilesystem_session_begin(struct bsdfilesystem_state *st, const char *session);
int	bsdfilesystem_reap_leases(struct bsdfilesystem_state *st);
int	bsdfilesystem_reap_staging(struct bsdfilesystem_state *st);
int	bsdfilesystem_reap_idle_staging(struct bsdfilesystem_state *st);
/*
 * True iff `s` has the reserved TXN staging/version-id shape gen_version_id()
 * mints: a leading 'v' followed by >=16 hex digits.  A caller-chosen claim name
 * must never take this shape (request.c valid_dataset reserves it), so the
 * reaper's name-shape guard and the origin binding cannot be spoofed by name.
 */
bool	bsdfilesystem_is_version_id_name(const char *s);
void	bsdfilesystem_start_reaper(struct bsdfilesystem_state *st);
/*
 * A stamped staging clone must be at least this many seconds old before the
 * live-system idle reap will reclaim it.  The value only has to exceed the
 * sub-second TXN_BEGIN clone-before-mount window (a live txn is protected by its
 * mount regardless of age); a few minutes leaves generous margin.  Operator-
 * tunable via the "staging_idle_grace" config key, bounded like the interval.
 */
#define	BSDFILESYSTEM_STAGING_IDLE_GRACE	300
#define	BSDFILESYSTEM_STAGING_IDLE_GRACE_MIN	1
#define	BSDFILESYSTEM_STAGING_IDLE_GRACE_MAX	86400

/*
 * Reserved prefix for the transient del-<id> clone TXN_COMMIT renames the old
 * base claim to mid-swap, and the user property TXN_BEGIN stamps on a staging
 * clone to bind it to its origin claim.  Shared by request.c (which sets them)
 * and layout.c's boot-scoped staging sweep (which reaps by them).  A ZFS
 * `origin` read cannot serve the binding: the kernel get-one-prop path returns
 * origin as a (meaningless) integer, but a user property round-trips as a string.
 */
#define	BSDFILESYSTEM_STAGING_PREFIX	"del-"
#define	BSDFILESYSTEM_TXN_BASE_PROP	"bsdfilesystem:txnbase"
/* Recursion bound for the persistent-tree staging walk (real depth is ~5). */
#define	BSDFILESYSTEM_STAGING_WALK_MAX	16
/*
 * Recursion bound for bsdfilesystem_destroy_tree.  A real container nests only a
 * few levels, but a caller with ZH_CREATE on a subtree handle can build an
 * arbitrarily deep chain of child datasets; without a bound the recursive
 * destroy (in a worker, or worse the privileged reaper) would overflow its
 * stack.  Past the bound the destroy fails rather than recurses.
 */
#define	BSDFILESYSTEM_DESTROY_MAX_DEPTH	64

/* request.c */
int	bsdfilesystem_serve(struct bsdfilesystem_state *st);

#ifdef BSDFILESYSTEM_TESTING
/* Test-only accessors from the implementation units. */
bool	bsdfilesystem_test_derive_ns(const char *client, char *out, size_t outsz);
bool	bsdfilesystem_test_valid_dataset(const char *name);
bool	bsdfilesystem_test_has_dotdot_component(const char *path);
bool	bsdfilesystem_test_pool_missing_expected(const char *fstype, uint64_t flags,
	    int error);
bool	bsdfilesystem_test_valid_request(const struct bsdfilesystem_request *rq);
struct tzfs_conn;
struct tzfs_conn *bsdfilesystem_test_conn_new(void);
int	bsdfilesystem_test_anchor_add(struct tzfs_conn *, const char *dataset, int fd);
void	bsdfilesystem_test_anchor_drop(struct tzfs_conn *, const char *dataset);
bool	bsdfilesystem_test_valid_container(const char *);
unsigned bsdfilesystem_test_anchor_live(const struct tzfs_conn *);
void	bsdfilesystem_test_conn_free(struct tzfs_conn *);
int	bsdfilesystem_test_grant_open(struct bsdfilesystem_state *st, const char *client,
	    const struct bsdfilesystem_open_request *rq);
bool	bsdfilesystem_test_scoped_ns(const char *, const char (*)[64], uint8_t,
	    const char *, uint32_t, char *, size_t);
int	bsdfilesystem_test_grant(struct bsdfilesystem_state *st, const char *client,
	    const struct bsdfilesystem_request *rq, char *dataset, size_t dsz);
int	bsdfilesystem_test_worker(struct bsdfilesystem_state *st, int fd, const char *client);
int	bsdfilesystem_test_grant_list(struct bsdfilesystem_state *st, const char *client,
	    const struct bsdfilesystem_list_request *rq, struct bsdfilesystem_list_reply *rp);
#endif /* BSDFILESYSTEM_TESTING */

#endif /* BSDFILESYSTEM_H */
