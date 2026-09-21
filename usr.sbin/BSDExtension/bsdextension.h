/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface for bsdextension(8) — the system-extension broker.
 *
 * The allow-list configuration type and the pure-logic entry points live here
 * so the daemon translation unit and its unit tests share one definition.  In a
 * normal build the pure-logic functions stay file-static (SYSEXT_STATIC ==
 * static) and nothing beyond this type escapes.  Under -DBSDEXTENSION_TESTING the
 * daemon's main() is compiled out, the pure-logic functions gain external
 * linkage, and a test-only serve entry point (sysext_test_serve) is exposed so a
 * test can drive the real request handler over a real channel.  There is no
 * behavioural difference between the two builds — only linkage and the presence
 * of main().
 */

#ifndef _BSDEXTENSION_H_
#define _BSDEXTENSION_H_

#include <stddef.h>
#include <stdbool.h>
#include <libservice.h>

#include "sysext_proto.h"	/* SYSEXT_NAME_MAX */

#define	SYSEXT_MAX_ALLOW	32	/* allow-list capacity */
#define	SYSEXT_DEFAULT_CONF	"/Capabilities/Config/bsdextension.ucl"
/*
 * Bundle-relative config filename, opened via the switchboard-delivered Config
 * descriptor (service_config_open) since a born-in-capmode broker has no global
 * namespace access.
 */
#define	SYSEXT_CONFIG_NAME	"bsdextension.ucl"

struct sysext_config {
	char	allow[SYSEXT_MAX_ALLOW][SYSEXT_NAME_MAX];
	size_t	nallow;
};

struct sysext_policy;
struct sysext_policy *sysext_policy_create(const struct sysext_config *);
void sysext_policy_destroy(struct sysext_policy *);
int sysext_policy_snapshot(struct sysext_policy *, struct sysext_config *);
int sysext_policy_reload(struct sysext_policy *, const char *, service_rights_t);
/* Reload from an already-open config descriptor (capmode-safe; borrows fd). */
int sysext_policy_reload_fd(struct sysext_policy *, int fd, service_rights_t);
int sysext_config_reload(struct sysext_config *, const char *);
/* Parse the allow-list from an already-open descriptor (capmode-safe reload). */
int sysext_config_load_fd(struct sysext_config *cfg, int fd);

/*
 * The held SYS_GATE_KLDLOAD/KLDUNLOAD "system" token (defined in
 * bsdextension.c), or -1.  bsdextension.c loads and reclaim.c unloads THROUGH
 * it when born in capability mode.
 */
extern int sysext_kld_token;

#ifdef BSDEXTENSION_TESTING
void sysext_test_policy_abandon(struct sysext_policy *);
#define	SYSEXT_STATIC		/* external linkage: reachable from tests */

/* Pure-logic entry points, unit-tested directly (see allowlist_test.c). */
bool	valid_module_name(const char *name);
void	sysext_config_defaults(struct sysext_config *cfg);
bool	extension_allowed(const struct sysext_config *cfg, const char *name);
int	sysext_config_load(struct sysext_config *cfg, const char *path);
int	sysext_config_load_fd(struct sysext_config *cfg, int fd);

/*
 * Test-only serve entry point.  Installs cfg as the resolved allow-list and
 * runs the real per-client worker (sysext_worker -> sysext_request) on fd until
 * the client closes, exactly as a pdfork'd worker would in production.  Returns
 * the worker exit status (0 on clean close).  Used by provider_test.c.
 */
int	sysext_test_serve(int fd, const char *client,
	    const struct sysext_config *cfg);
#else
#define	SYSEXT_STATIC	static
#endif /* BSDEXTENSION_TESTING */

#endif /* _BSDEXTENSION_H_ */
