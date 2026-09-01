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
 * Per-label isolated-open policy (TZFSD_OP_OPEN), loaded from the config file's
 * "open_paths" array.  Default-deny: a client may open a path only if some entry
 * matches its unforgeable label exactly and covers the requested rights.  Exact
 * path match only — no prefixes or globs — so a compromised consumer cannot walk
 * outside the precise paths its label is granted.
 */
#define	TZFSD_MAX_OPEN_POLICY	32
struct tzfsd_open_policy {
	char		label[64];		/* == service_identity.client_label */
	char		path[TZFSD_MAXPATH];	/* exact absolute path granted */
	uint32_t	rights;			/* TZFSD_OPEN_* the label may request */
};

struct tzfsd_config {
	char		pool[TZFSD_MAXPATH];
	char		base[TZFSD_MAXPATH];		/* zroot/Capabilities */
	char		persistent[TZFSD_MAXPATH];	/* .../persistent */
	char		ephemeral[TZFSD_MAXPATH];	/* .../ephemeral */
	char		mountpoint[TZFSD_MAXPATH];	/* /Capabilities */
	char		ephemeral_sync[16];		/* zfs sync= value */
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

#endif /* TZFSD_H */
