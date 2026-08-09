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

#endif /* ORACLE_INIT_H */
