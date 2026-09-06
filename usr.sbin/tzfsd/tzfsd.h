/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * tzfsd(8) — the [TZFS] storage daemon.  Internal definitions.
 */

#ifndef TZFSD_H
#define TZFSD_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "tzfsd_proto.h"

#define	TZFSD_MAXPATH		256	/* dataset name buffer */
#define	TZFSD_DEFAULT_CONF	"/Capabilities/Config/tzfsd.ucl"

/*
 * Default per-claim space ceiling (refquota, bytes).  Bounds any single claim
 * so one tenant cannot fill the pool and starve the others; overridable via the
 * "default_refquota" config key, 0 disables the ceiling.
 */
#define	TZFSD_DEFAULT_REFQUOTA	(1ULL << 30)	/* 1 GiB */

/*
 * Floor for a per-request refquota override (tzfsd_request.quota).  ZFS refquota
 * must cover a dataset's own metadata overhead; an absurdly small ceiling makes
 * a claim useless (even an empty dataset cannot be written).  Reject anything
 * below this with EINVAL.
 */
#define	TZFSD_MIN_REFQUOTA	(1ULL << 20)	/* 1 MiB */

/*
 * Per-label isolated-open policy (TZFSD_OP_OPEN), loaded from the config file's
 * "open_paths" array.  Default-deny: a client may open a path only if some entry
 * matches its unforgeable label exactly and covers the requested rights.  Exact
 * path match only — no prefixes or globs — so a compromised consumer cannot walk
 * outside the precise paths its label is granted.
 */
#define	TZFSD_MAX_OPEN_POLICY	32
struct tzfsd_open_policy {
	char		label[64];		/* == service_identity.client_label */
	char		path[TZFSD_MAXPATH];	/* absolute path (or prefix) granted */
	uint32_t	rights;			/* TZFSD_OPEN_* the label may request */
	bool		prefix;			/* path is a prefix: matches path + one
						 * trailing non-'/' component (e.g. a
						 * device unit /dev/vhid -> /dev/vhidN),
						 * never a subdirectory */
};

struct tzfsd_config {
	char		pool[TZFSD_MAXPATH];
	char		base[TZFSD_MAXPATH];		/* zroot/Capabilities */
	char		persistent[TZFSD_MAXPATH];	/* .../persistent */
	char		ephemeral[TZFSD_MAXPATH];	/* .../ephemeral */
	char		mountpoint[TZFSD_MAXPATH];	/* /Capabilities */
	char		ephemeral_sync[16];		/* zfs sync= value */
	uint64_t	default_refquota;		/* per-claim ceiling, bytes; 0=off */
	struct tzfsd_open_policy open_policy[TZFSD_MAX_OPEN_POLICY];
	unsigned	nopen_policy;
};

/*
 * Retained capability handles, opened by name before cap_enter() and used to
 * derive/create/clone/destroy in capability mode thereafter.  ZH_ALL_RIGHTS +
 * ZHF_SUBTREE; the daemon attenuates before handing anything to a client.
 */
struct tzfsd_state {
	struct tzfsd_config cfg;
	int		persistent_fd;	/* handle on cfg.persistent */
	int		ephemeral_fd;	/* handle on cfg.ephemeral */
	int		boot_fd;	/* current kernel-boot generation */
	int		lease_fd;	/* current serviced session, per connection */
	char		boot_name[TZFSD_NAME_MAX];
	char		lease_name[TZFSD_NAME_MAX];
	/*
	 * Plain root ("/") directory fd, opened before cap_enter().  Used to
	 * openat(2) an isolated path descriptor for TZFSD_OP_OPEN in capability
	 * mode (openat from a retained dir fd with a relative path is
	 * capsicum-legal, unlike open() by absolute path).
	 */
	int		root_fd;
};

/* config.c */
void	tzfsd_config_defaults(struct tzfsd_config *cfg);
int	tzfsd_config_load(struct tzfsd_config *cfg, const char *path);

/* layout.c */
int	tzfsd_ensure_zfs(struct tzfsd_config *cfg);
int	tzfsd_layout_provision(struct tzfsd_state *st);
int	tzfsd_ensure_path(int root_fd, const char *relpath, uint64_t rights);
int	tzfsd_destroy_tree(int parent_fd, const char *relname);
int	tzfsd_nvl_names(const void *buf, size_t len, char ***namesp,
	    size_t *countp);
void	tzfsd_nvl_names_free(char **names, size_t count);

int	tzfsd_session_begin(struct tzfsd_state *st, const char *session);
int	tzfsd_reap_leases(struct tzfsd_state *st);

/* request.c */
int	tzfsd_serve(struct tzfsd_state *st);

#ifdef TZFSD_TESTING
/* request.c test-only accessors (see the TZFSD_TESTING block in request.c). */
bool	tzfsd_test_derive_ns(const char *client, char *out, size_t outsz);
bool	tzfsd_test_valid_dataset(const char *name);
bool	tzfsd_test_has_dotdot_component(const char *path);
bool	tzfsd_test_valid_request(const struct tzfsd_request *rq);
int	tzfsd_test_grant_open(struct tzfsd_state *st, const char *client,
	    const struct tzfsd_open_request *rq);
int	tzfsd_test_grant(struct tzfsd_state *st, const char *client,
	    const struct tzfsd_request *rq, char *dataset, size_t dsz);
int	tzfsd_test_worker(struct tzfsd_state *st, int fd, const char *client);
int	tzfsd_test_grant_list(struct tzfsd_state *st, const char *client,
	    const struct tzfsd_list_request *rq, struct tzfsd_list_reply *rp);
#endif /* TZFSD_TESTING */

#endif /* TZFSD_H */
