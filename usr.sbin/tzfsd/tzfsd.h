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
#define	TZFSD_DEFAULT_CONFD	"/Capabilities/Config/tzfsd.d"	/* flavor catalog drop-ins */

/* The @snapshot every flavor template exposes as its clone origin. */
#define	TZFSD_TEMPLATE_SNAP	"ready"

/*
 * How a flavor's template is populated, in precedence order (see
 * docs/tzfsd-design.md §3.1).
 */
enum tzfsd_build {
	TZFSD_BUILD_LIVE = 0,	/* constructed from the running system */
	TZFSD_BUILD_BAKED,	/* zfs recv of a shipped send-stream */
	TZFSD_BUILD_SOURCE,	/* fetch/unpack from a configured source */
};

struct tzfsd_flavor_def {
	char		name[TZFSD_FLAVOR_MAX];
	char		source[TZFSD_MAXPATH];	/* send-stream / rootfs path */
	enum tzfsd_build build;
	bool		enabled;		/* config may turn it off */
	bool		is_default;
	bool		available;		/* template@ready present now */
};

struct tzfsd_config {
	char		pool[TZFSD_MAXPATH];
	char		base[TZFSD_MAXPATH];		/* zroot/Capabilities */
	char		persistent[TZFSD_MAXPATH];	/* .../persistent */
	char		ephemeral[TZFSD_MAXPATH];	/* .../ephemeral */
	char		templates[TZFSD_MAXPATH];	/* .../.templates */
	char		mountpoint[TZFSD_MAXPATH];	/* /Capabilities */
	char		ephemeral_sync[16];		/* zfs sync= value */

	struct tzfsd_flavor_def flavors[TZFSD_MAX_FLAVORS];
	unsigned	nflavors;
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
	int		templates_fd;	/* handle on cfg.templates */
	int		listen_fd;	/* TZFSD_SOCK_PATH listener */
};

/* config.c */
void	tzfsd_config_defaults(struct tzfsd_config *cfg);
int	tzfsd_config_load(struct tzfsd_config *cfg, const char *path);
int	tzfsd_config_load_confd(struct tzfsd_config *cfg, const char *dir);
struct tzfsd_flavor_def *tzfsd_flavor_find(struct tzfsd_config *cfg,
	    const char *name);

/* layout.c */
int	tzfsd_ensure_zfs(struct tzfsd_config *cfg);
int	tzfsd_layout_provision(struct tzfsd_state *st);
int	tzfsd_flavors_prepare(struct tzfsd_state *st);
int	tzfsd_ensure_path(int root_fd, const char *relpath, uint64_t rights);
int	tzfsd_destroy_tree(int parent_fd, const char *relname);
int	tzfsd_nvl_names(const void *buf, size_t len, char ***namesp,
	    size_t *countp);
void	tzfsd_nvl_names_free(char **names, size_t count);

int	tzfsd_session_begin(struct tzfsd_state *st, const char *session);

/* request.c */
void	tzfsd_serve(struct tzfsd_state *st);

#endif /* TZFSD_H */
