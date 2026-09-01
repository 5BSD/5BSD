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

struct tzfsd_config {
	char		pool[TZFSD_MAXPATH];
	char		base[TZFSD_MAXPATH];		/* zroot/Capabilities */
	char		persistent[TZFSD_MAXPATH];	/* .../persistent */
	char		ephemeral[TZFSD_MAXPATH];	/* .../ephemeral */
	char		mountpoint[TZFSD_MAXPATH];	/* /Capabilities */
	char		ephemeral_sync[16];		/* zfs sync= value */
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
	int		listen_fd;	/* TZFSD_SOCK_PATH listener */
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

/* request.c */
void	tzfsd_serve(struct tzfsd_state *st);

#endif /* TZFSD_H */
