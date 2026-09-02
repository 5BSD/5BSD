/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Authority PID 1 personality.  Selected by main() when getpid() == 1.
 */

#ifndef CAPSULE_H
#define CAPSULE_H

void	capsule_main(int argc, char *argv[]) __dead2;

/*
 * Install the ambient lookup channel client end (§21) that serviced forwards
 * over AUTHORITY_OP_SET_AMBIENT_LOOKUP.  capsule dup2()s this descriptor into
 * SERVICE_LOOKUP_FIXED_FD when spawning gettys so interactive logins inherit
 * it.  Takes ownership of fd.  Best-effort: returns 0 on success, -1 (errno
 * set) on failure without disturbing any previously installed channel; the
 * caller logs and continues either way.
 */
int	capsule_set_ambient_lookup(int fd);

/*
 * Apply a system lifecycle transition requested over the capability plane
 * (docs/lifecycle-capability-design.md, P4b).  op is a CTL_OP_* lifecycle
 * opcode.  Returns 0 when applied, EPERM when Authority is not PID 1.
 */
int	capsule_lifecycle(int op);

#endif /* CAPSULE_H */
