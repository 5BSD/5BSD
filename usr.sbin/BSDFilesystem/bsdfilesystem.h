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

#include <storage_namespace.h>

#include <filesystem_policy.h>

/*
 * Retained capability handles, opened by name before cap_enter() and used to
 * derive/create/clone/destroy in capability mode thereafter.  ZH_ALL_RIGHTS +
 * ZHF_SUBTREE; the daemon attenuates before handing anything to a client.
 */
struct bsdfilesystem_namespace_view;
struct bsdfilesystem_state {
	struct bsdfilesystem_namespace_view *worker_namespaces;
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
	 * Startup-only /dev/zfs descriptor, opened through the delivered
	 * /dev directory and closed after acquiring the bounded dataset base.
	 */
	int		zfs_fd;
	/*
	 * True once the capability pool + persistent/ephemeral handles are
	 * provisioned.  Gates the boot-scoped GC (reap_leases / reap_staging)
	 * and the reconcile reaper, which bsdfilesystem_serve() runs AFTER it
	 * signals provider-ready (so a slow cold-start GC does not delay the
	 * ready() that on-demand waiters block on) but BEFORE it accepts any
	 * client request (so the GC still never races a live lease/txn).
	 */
	bool		storage_available;
};

/* layout.c */
int	bsdfilesystem_ensure_zfs(int dev_dirfd);
bool	bsdfilesystem_pool_missing_expected(int error);
int	bsdfilesystem_layout_provision(struct bsdfilesystem_state *st);
/* Borrows a dataset handle matching cfg.base; no raw device or pool access. */
int	bsdfilesystem_layout_provision_fd(struct bsdfilesystem_state *st, int base_fd);
int	bsdfilesystem_ensure_path(int root_fd, const char *relpath, uint64_t rights);
/* Live mounted claims one connection may hold at once (persistent + cache +
 * shared stores of a busy unit fit comfortably). */
#define	BSDFILESYSTEM_CONN_MAX_CLAIMS	32
/* Datasets (distinct claim names) one namespace may hold; a NEW claim past
 * this is refused EDQUOT, existing claims always reopen. */
#define	BSDFILESYSTEM_NS_MAX_CLAIMS	64
/* Data/Shared/<group>/ containers live under this reserved bundle name. */
#define	BSDFILESYSTEM_SHARED_DIR	STORAGE_NAMESPACE_SHARED_DIR
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
 * Reserved prefix for the transient del-<id> clone TXN_COMMIT renames the old
 * base claim to mid-swap, and the user property TXN_BEGIN stamps on a staging
 * clone to bind it to its origin claim.  Shared by request.c (which sets them)
 * and layout.c's boot-scoped staging sweep (which reaps by them).  A ZFS
 * `origin` read cannot serve the binding: the kernel get-one-prop path returns
 * origin as a (meaningless) integer, but a user property round-trips as a string.
 */
#define	BSDFILESYSTEM_STAGING_PREFIX	STORAGE_NAMESPACE_STAGING_PREFIX
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
int bsdfilesystem_test_selected_session(struct bsdfilesystem_state *st, const char *session);
int bsdfilesystem_test_empty_selection(struct bsdfilesystem_state *st);
#include <capreclaim.h>
int bsdfilesystem_test_reclaim_bundles(int, struct capreclaim *,
    enum capreclaim_when);
bool bsdfilesystem_test_oes_admit(unsigned, unsigned, unsigned);
int bsdfilesystem_test_harden_delivery(int, bool);
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
