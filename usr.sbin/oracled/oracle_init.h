/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Oracle PID 1 personality.  Selected by main() when getpid() == 1.
 */

#ifndef ORACLE_INIT_H
#define ORACLE_INIT_H

void	oracle_init_main(int argc, char *argv[]) __dead2;

/*
 * Install the ambient lookup channel client end (§21) that serviced forwards
 * over ORACLE_OP_SET_AMBIENT_LOOKUP.  oracle-init dup2()s this descriptor into
 * SERVICE_LOOKUP_FIXED_FD when spawning gettys so interactive logins inherit
 * it.  Takes ownership of fd.  Best-effort: returns 0 on success, -1 (errno
 * set) on failure without disturbing any previously installed channel; the
 * caller logs and continues either way.
 */
int	oracle_init_set_ambient_lookup(int fd);

#endif /* ORACLE_INIT_H */
