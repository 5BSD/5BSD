/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * cap_rt_capprotect — wire protocol for Capability Protection.
 *
 * Shared between kernel and userspace.  Include this header
 * to construct CAP_RT_CALL requests for the "capprotect" service.
 */

#ifndef _DEV_CAP_RT_CAP_RT_CAPPROTECT_PROTO_H_
#define _DEV_CAP_RT_CAP_RT_CAPPROTECT_PROTO_H_

#include <sys/types.h>

#define	CP_OP_SHIELD		1	/* shield calling program (nonce-scoped) */
#define	CP_OP_MINT		2	/* create access token (returns reply fd) */
#define	CP_OP_AUTHORIZE		3	/* authorize caller (on token fd) */
#define	CP_OP_CAPMODE		4	/* enter Capsicum capability mode */
#define	CP_OP_CHROOT		5	/* change filesystem root (dir fd attached) */

/*
 * Shield flags — bitmask of desired protections.
 * Pass in cp_request.flags.  Zero means all protections.
 *
 * Flags are set once per fd (one-shot).  Protection is per-nonce:
 * the first shield call for a nonce sets the policy, additional
 * shield fds for the same nonce add a refcount hold but do not
 * change the active flags.  Protection drops only when all shield
 * fds for the nonce are closed.
 */
#define	CP_SF_PTRACE		0x01	/* block ptrace attach */
#define	CP_SF_SIGNAL		0x02	/* block signals (except SIGKILL/SIGCONT) */
#define	CP_SF_VISIBLE		0x04	/* hide from ps/top/procfs */
#define	CP_SF_WAIT		0x08	/* block wait4 from non-parent */
#define	CP_SF_SIGKILL		0x10	/* block SIGKILL (unkillable) */
#define	CP_SF_SIGCONT		0x20	/* block SIGCONT (unstoppable) */
#define	CP_SF_SCHED		0x40	/* block setpriority/cpuset manipulation */
#define	CP_SF_CORE		0x80	/* suppress core dumps (prevent secret leakage) */
#define	CP_SF_KTRACE		0x100	/* block ktrace (passive information disclosure) */
#define	CP_SF_NOPRIVS		0x200	/* strip all privileges (priv_check returns EPERM) */
#define	CP_SF_NOFORK		0x400	/* block fork/vfork/rfork */
#define	CP_SF_NOIPC		0x800	/* block SysV and POSIX IPC */
#define	CP_SF_NOFDRECV		0x1000	/* block incoming fd passing (SCM_RIGHTS) */
#define	CP_SF_ALL		0x1fff

struct cp_request {
	uint32_t	op;
	uint32_t	flags;		/* shield flags (0 = all) */
} __packed;

#endif /* _DEV_CAP_RT_CAP_RT_CAPPROTECT_PROTO_H_ */
