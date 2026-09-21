/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */
#ifndef _BSDTIME_TEST_H_
#define	_BSDTIME_TEST_H_

struct timecmp_config;

/*
 * Test-only entrypoints, compiled into BSDTime.c only under -DBSDTIME_TESTING
 * (main() is guarded out).  They let the ATF suite drive the real per-session
 * channel worker -- policy enforcement, protocol validation, GET/SET/ADJUST
 * dispatch -- over an already-connected provider channel fd, and install a held
 * SYS_GATE_SETTIME token so the allow path can reach the gate.
 */
int	bsdtime_test_serve_session(int fd, const char *label,
	    const struct timecmp_config *config);
void	bsdtime_test_set_token(int fd);

#endif /* _BSDTIME_TEST_H_ */
