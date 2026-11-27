/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared by launch_authority_pins_test and the image it executes,
 * launch_authority_helper: one record, written whole to a pipe at each
 * step, so the test reads what the exec'd image observed.
 */

#ifndef _LAUNCH_AUTHORITY_H_
#define	_LAUNCH_AUTHORITY_H_

#include <sys/cap_authority.h>
#include <stdint.h>

#define	LA_NA		(-9999)	/* a field the step did not measure */
#define	LA_HELPER_BROKEN 250	/* the helper itself failed (exit status) */

struct la_report {
	struct cap_authority_info info;	/* CAP_AUTH_INFO of the reporter */
	int32_t	pid;
	int32_t	probe;		/* GETINFO on the channel end: 0 or errno */
	int32_t	child_probe;	/* the same from a fork child */
	int32_t	cleared_probe;	/* from a fork child that cleared its grant */
	int32_t	dq_open;	/* open("/dev/dq", O_RDWR): 0 or errno */
	int32_t	install;	/* CAP_AUTH_INSTALL: 0 or errno */
	int32_t	exec_errno;	/* an exec that returned: its errno */
};

#endif /* !_LAUNCH_AUTHORITY_H_ */
