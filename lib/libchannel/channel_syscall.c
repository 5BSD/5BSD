/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Userland resolver for the ungated, SYF_CAPENABLED channel-pair-create
 * syscall registered dynamically by the mac_capability_channel module.
 *
 * The syscall creates a fresh, self-owned pair of two connected
 * mac_capability channel endpoints — the socketpair(2)-equivalent
 * primitive with no service connection and no authority.  Because it is a
 * SYSCALL_MODULE its number is assigned dynamically at module load, so we
 * resolve it through a read-only sysctl, with modfind(2)/modstat(2)
 * as an older-kernel fallback, and memoize it atomically.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <unistd.h>

#include "channel.h"

/*
 * Memoized syscall number.
 *   INT_RESOLVE_PENDING  not yet resolved
 *   -1                   resolved: syscall unavailable (old kernel/module)
 *   >= 0                 resolved syscall number
 * Concurrent first use may resolve the same number more than once; atomic
 * publication avoids a data race.
 */
#define CHANNEL_SYSNO_PENDING (-2)
static _Atomic int channel_create_sysno = CHANNEL_SYSNO_PENDING;

static int
channel_resolve_sysno(void)
{
	struct module_stat stat;
	int modid, sysno;
	size_t len = sizeof(sysno);

	sysno = channel_create_sysno;
	if (sysno != CHANNEL_SYSNO_PENDING)
		return (sysno);

	/* modfind is forbidden after cap_enter; this read grants no authority.
	 */
	if (sysctlbyname("kern.mac_capability.channel_create_syscall", &sysno,
		&len, NULL, 0) == 0 &&
	    sysno >= 0) {
		channel_create_sysno = sysno;
		return (sysno);
	}
	modid = modfind("sys/mac_capability_channel_create");
	if (modid < 0) {
		channel_create_sysno = -1;
		return (-1);
	}
	stat.version = sizeof(stat);
	if (modstat(modid, &stat) != 0) {
		channel_create_sysno = -1;
		return (-1);
	}
	sysno = stat.data.intval;
	channel_create_sysno = sysno;
	return (sysno);
}

/*
 * Create a self-owned connected channel pair.  On success fds[0] and
 * fds[1] are two connected endpoints owned by the caller; a message sent
 * on either is delivered to the other, kernel-stamped with the sender's
 * cred nonce.  Grants no authority.
 *
 * Returns 0 on success, or -1 with errno set (ENOSYS if the kernel does
 * not provide the syscall). Discovery must fail rather than receive replies
 * from a shared inherited queue.
 */
int
mac_capability_channel_create(int fds[2])
{
	int sysno;

	sysno = channel_resolve_sysno();
	if (sysno < 0) {
		errno = ENOSYS;
		return (-1);
	}
	return (syscall(sysno, fds));
}
