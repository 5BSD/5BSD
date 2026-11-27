/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Shared by launch_authority_pins_test and the image it executes,
 * launch_authority_helper: records written whole to a pipe at each step,
 * so the test reads what the exec'd image observed.
 */

#ifndef _LAUNCH_AUTHORITY_H_
#define	_LAUNCH_AUTHORITY_H_

#include <sys/types.h>
#include <sys/cap_authority.h>
#include <sys/capsicum.h>
#include <stdint.h>

#define	LA_NA		(-9999)	/* a field the step did not measure */
#define	LA_HELPER_BROKEN 250	/* the helper itself failed (exit status) */

struct la_report {
	struct cap_authority_info info;	/* CAP_AUTH_INFO of the reporter */
	int32_t	pid;
	int32_t	issetugid;	/* issetugid(2) of the reporter */
	int32_t	pdeathsig;	/* PROC_PDEATHSIG_STATUS of the reporter */
	int32_t	probe;		/* GETINFO on the channel end: 0 or errno */
	int32_t	child_probe;	/* the same from a fork child */
	int32_t	cleared_probe;	/* from a fork child that cleared its grant */
	int32_t	send;		/* one message sent on the channel end */
	int32_t	dq_open;	/* open("/dev/dq", O_RDWR): 0 or errno */
	int32_t	install;	/* CAP_AUTH_INSTALL: 0 or errno */
	int32_t	exec_errno;	/* an exec that returned: its errno */
};

/* What CAP_AUTH_GET_LIBDIR gives the reporter (the libdir command). */
struct la_libdir_report {
	struct cap_authority_info info;
	int32_t	get0;		/* index 0: 0 or errno */
	int32_t	get1;		/* index 1: 0 or errno (past the count) */
	int32_t	get3;		/* index CAP_AUTH_LIBDIR_MAX: 0 or errno */
	int32_t	get_data;	/* index 0 with a data pointer: 0 or errno */
	int32_t	cloexec;	/* FD_CLOEXEC of the index 0 descriptor */
	int32_t	is_dir;		/* S_ISDIR of the index 0 descriptor */
	uint64_t dev;		/* its st_dev */
	uint64_t ino;		/* its st_ino */
	cap_rights_t rights;	/* its Capsicum rights */
};

#endif /* !_LAUNCH_AUTHORITY_H_ */
