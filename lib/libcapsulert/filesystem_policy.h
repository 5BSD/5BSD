/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 Kory Heard
 * Shared filesystem policy model and parser.
 */
#ifndef _FILESYSTEM_POLICY_H_
#define _FILESYSTEM_POLICY_H_
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <bsdfilesystem_proto.h>
#include <storage_namespace.h>

#define BSDFILESYSTEM_MAXPATH 256
#define BSDFILESYSTEM_DEFAULT_CONF "/Capabilities/Config/bsdfilesystem.ucl"
/* Per-claim quota; zero configured value disables the ceiling. */
#define BSDFILESYSTEM_DEFAULT_REFQUOTA (1ULL << 30)
#define BSDFILESYSTEM_MIN_REFQUOTA (1ULL << 20)
#define BSDFILESYSTEM_RECLAIM_INTERVAL_DEFAULT 300
#define BSDFILESYSTEM_RECLAIM_INTERVAL_MIN 10
#define BSDFILESYSTEM_RECLAIM_INTERVAL_MAX 86400
/* Legacy age setting does not authorize automatic deletion. */
#define BSDFILESYSTEM_STAGING_IDLE_GRACE 300
#define BSDFILESYSTEM_STAGING_IDLE_GRACE_MIN 1
#define BSDFILESYSTEM_STAGING_IDLE_GRACE_MAX 86400
#define BSDFILESYSTEM_MAX_OPEN_POLICY 32
struct bsdfilesystem_open_policy {
	char label[64];
	char path[BSDFILESYSTEM_MAXPATH];
	uint32_t rights;
	bool verify;
	/* Prefix permits one trailing non-slash component, never a subdirectory. */
	bool prefix;
};

struct bsdfilesystem_config {
	char pool[BSDFILESYSTEM_MAXPATH];
	char base[BSDFILESYSTEM_MAXPATH];
	char persistent[BSDFILESYSTEM_MAXPATH];
	char ephemeral[BSDFILESYSTEM_MAXPATH];
	char mountpoint[BSDFILESYSTEM_MAXPATH];
	char ephemeral_sync[16];
	uint64_t default_refquota;
	unsigned reclaim_interval;
	unsigned staging_idle_grace;
	struct bsdfilesystem_open_policy open_policy[BSDFILESYSTEM_MAX_OPEN_POLICY];
	unsigned nopen_policy;
};

void bsdfilesystem_config_defaults(struct bsdfilesystem_config *);
int bsdfilesystem_config_load(struct bsdfilesystem_config *, const char *);
/* Descriptor loaders consume fd; parse errors leave the configuration intact. */
int bsdfilesystem_config_load_fd(struct bsdfilesystem_config *, int);
#endif
