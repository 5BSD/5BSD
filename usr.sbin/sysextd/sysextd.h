/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Internal interface for sysextd(8) — the system-extension broker.
 *
 * The allow-list configuration type and the pure-logic entry points live here
 * so the daemon translation unit and its unit tests share one definition.  In a
 * normal build the pure-logic functions stay file-static (SYSEXT_STATIC ==
 * static) and nothing beyond this type escapes.  Under -DSYSEXTD_TESTING the
 * daemon's main() is compiled out, the pure-logic functions gain external
 * linkage, and a test-only serve entry point (sysext_test_serve) is exposed so a
 * test can drive the real request handler over a real channel.  There is no
 * behavioural difference between the two builds — only linkage and the presence
 * of main().
 */

#ifndef _SYSEXTD_H_
#define _SYSEXTD_H_

#include <stddef.h>
#include <stdbool.h>

#include "sysext_proto.h"	/* SYSEXT_NAME_MAX */

#define	SYSEXT_MAX_ALLOW	32	/* allow-list capacity */
#define	SYSEXT_DEFAULT_CONF	"/Capabilities/Config/sysextd.ucl"

struct sysext_config {
	char	allow[SYSEXT_MAX_ALLOW][SYSEXT_NAME_MAX];
	size_t	nallow;
};

#ifdef SYSEXTD_TESTING
#define	SYSEXT_STATIC		/* external linkage: reachable from tests */

/* Pure-logic entry points, unit-tested directly (see allowlist_test.c). */
bool	valid_module_name(const char *name);
void	sysext_config_defaults(struct sysext_config *cfg);
bool	extension_allowed(const struct sysext_config *cfg, const char *name);
int	sysext_config_load(struct sysext_config *cfg, const char *path);

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
#endif /* SYSEXTD_TESTING */

#endif /* _SYSEXTD_H_ */
