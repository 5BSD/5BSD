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
 * resolve it once via modfind(2)/modstat(2) and memoize it.
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/syscall.h>

#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include "channel.h"

/*
 * Memoized syscall number.
 *   INT_RESOLVE_PENDING  not yet resolved
 *   -1                   resolved: syscall unavailable (old kernel/module)
 *   >= 0                 resolved syscall number
 * A benign race on concurrent first use just re-resolves; the result is
 * identical, so no lock is required.
 */
#define	CHANNEL_SYSNO_PENDING	(-2)
static int channel_create_sysno = CHANNEL_SYSNO_PENDING;

static int
channel_resolve_sysno(void)
{
	struct module_stat stat;
	int modid, sysno;

	sysno = channel_create_sysno;
	if (sysno != CHANNEL_SYSNO_PENDING)
		return (sysno);

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
 * not provide the syscall — callers should fail soft to the inherited
 * shared lookup channel).
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
