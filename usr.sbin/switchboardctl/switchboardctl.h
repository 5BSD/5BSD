/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared prototypes for switchboardctl command modules.
 */

#ifndef SWITCHBOARDCTL_H
#define	SWITCHBOARDCTL_H

/* install.c and deps.c */
int	cmd_install(const char *bundle_path);
int cmd_recover_install(const char *, const char *);
int	cmd_deps(const char *program);

/* verify.c */
int	cmd_verify(int argc, char *argv[]);
int	cmd_bundles(void);

/* graph.c */
int	cmd_graph(int argc, char *argv[]);

struct sl_db;
int lifecycle_open_root(const char *, struct sl_db *);
void lifecycle_reference(const char *, char [64]);
int cmd_lifecycle(int, char **);

#endif /* SWITCHBOARDCTL_H */
