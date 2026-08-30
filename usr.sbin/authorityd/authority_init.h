/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Authority PID 1 personality.  Selected by main() when getpid() == 1.
 */

#ifndef AUTHORITY_INIT_H
#define AUTHORITY_INIT_H

void	authority_init_main(int argc, char *argv[]) __dead2;

/*
 * Install the ambient lookup channel client end (§21) that serviced forwards
 * over AUTHORITY_OP_SET_AMBIENT_LOOKUP.  authority-init dup2()s this descriptor into
 * SERVICE_LOOKUP_FIXED_FD when spawning gettys so interactive logins inherit
 * it.  Takes ownership of fd.  Best-effort: returns 0 on success, -1 (errno
 * set) on failure without disturbing any previously installed channel; the
 * caller logs and continues either way.
 */
int	authority_init_set_ambient_lookup(int fd);

/*
 * Apply a system lifecycle transition requested over the capability plane
 * (docs/lifecycle-capability-design.md, P4b).  op is a CTL_OP_* lifecycle
 * opcode.  Returns 0 when applied, EPERM when Authority is not PID 1.
 */
int	authority_init_lifecycle(int op);

#endif /* AUTHORITY_INIT_H */
