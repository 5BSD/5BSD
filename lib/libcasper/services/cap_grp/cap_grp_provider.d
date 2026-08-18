/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * USDT provider for the Casper cap_grp service.  Each probe exposes a
 * capability-mediated decision the service made on behalf of a sandboxed
 * process: which command was permitted (allow), which command/field/group
 * names a channel narrowed its limits to (limit-*), and the final result
 * of a dispatched command (command; error == 0 -> allowed).
 */
provider cap_grp {
	/* Command-permission predicate: command, allow/deny (1/0). */
	probe allow(const char *cmd, int allowed);
	/* A channel narrowed the set of allowed commands. */
	probe limit__cmds(const char *cmd);
	/* A channel narrowed the set of allowed fields. */
	probe limit__fields(const char *field);
	/* A channel narrowed the set of allowed groups (by name). */
	probe limit__groups(const char *group);
	/* Final result of a dispatched command (error == 0 -> allowed). */
	probe command(const char *cmd, int error);
};
