/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Userspace harness shadow of the kernel <sys/sysctl.h>.  The vmm device
 * models register read-only tunables at load time; in the rootless harness
 * those declarations must compile to nothing.
 */
#ifndef _KMOCK_SYS_SYSCTL_H_
#define	_KMOCK_SYS_SYSCTL_H_

#include <sys/types.h>

#define	CTLFLAG_RD	0
#define	CTLFLAG_RW	0
#define	CTLFLAG_RDTUN	0
#define	CTLFLAG_MPSAFE	0
#define	OID_AUTO	0

#define	SYSCTL_DECL(name)
#define	SYSCTL_NODE(parent, nbr, name, access, handler, descr)		\
	extern int sysctl_kmock_##name##_unused
#define	SYSCTL_INT(parent, nbr, name, access, ptr, val, descr)		\
	extern int sysctl_kmock_##name##_unused

#endif /* !_KMOCK_SYS_SYSCTL_H_ */
