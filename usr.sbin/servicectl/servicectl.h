/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared prototypes for servicectl command modules.
 */

#ifndef SERVICECTL_H
#define	SERVICECTL_H

/* install.c and deps.c */
int	cmd_install(const char *bundle_path);
int	cmd_deps(const char *program);

/* verify.c */
int	cmd_verify(int argc, char *argv[]);
int	cmd_policy_check(const char *path);
int	cmd_bundles(void);

#endif /* SERVICECTL_H */
