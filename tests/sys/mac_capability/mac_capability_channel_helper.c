/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * Helper for mac_capability_channel_test: exec'd with a fresh cred nonce,
 * it creates a self-owned channel pair via the dynamic SYF_CAPENABLED
 * syscall and exercises it.  Exit 0 on success.
 *
 * Modes (argv[1]):
 *   "pair"		(default) create a pair and exercise it bidirectionally.
 *   "capmode_roundtrip"	cap_enter(), then create a pair and exercise it
 *			bidirectionally entirely inside capability mode.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/syscall.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"

static int
chan_sysno(void)
{
	struct module_stat ms;
	int modid;

	modid = modfind("sys/mac_capability_channel_create");
	if (modid < 0)
		return (-1);
	ms.version = sizeof(ms);
	if (modstat(modid, &ms) != 0)
		return (-1);
	return (ms.data.intval);
}

/*
 * Create a pair, send msg on fds[from] and receive it on fds[to].
 * Returns 0 on success, or a small nonzero code identifying the failure.
 * Requires the received nonce to be nonzero (kernel-stamped).
 */
static int
roundtrip_once(int fds[2], int from, int to, int base)
{
	struct mac_capability_sendmsg_args sa;
	struct mac_capability_recvmsg_args ra;
	char buf[32];
	static const char msg[] = "child-fresh-nonce";

	memset(&sa, 0, sizeof(sa));
	sa.payload = msg;
	sa.payload_len = sizeof(msg);
	if (ioctl(fds[from], MAC_CAPABILITY_SENDMSG, &sa) != 0)
		return (base + 0);

	memset(&ra, 0, sizeof(ra));
	ra.payload = buf;
	ra.payload_len = sizeof(buf);
	if (ioctl(fds[to], MAC_CAPABILITY_RECVMSG, &ra) != 0)
		return (base + 1);
	if (ra.payload_len != sizeof(msg) || memcmp(buf, msg, sizeof(msg)) != 0)
		return (base + 2);
	/* The child has a real (nonzero) nonce, stamped by the kernel. */
	if (ra.trailer.nonce == 0)
		return (base + 3);
	return (0);
}

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "pair";
	int fds[2], no, rc;

	no = chan_sysno();
	if (no < 0)
		return (2);

	if (strcmp(mode, "capmode_roundtrip") == 0) {
		/* Resolve happened above (pre-capmode); now sandbox. */
		if (cap_enter() != 0 && errno != ENOSYS)
			return (20);
	}

	if (syscall(no, fds) != 0)
		return (3);
	if (fds[0] < 0 || fds[1] < 0 || fds[0] == fds[1])
		return (4);

	/* A -> B */
	rc = roundtrip_once(fds, 0, 1, 5);
	if (rc != 0)
		return (rc);
	/* B -> A */
	rc = roundtrip_once(fds, 1, 0, 9);
	if (rc != 0)
		return (rc);

	close(fds[0]);
	close(fds[1]);
	return (0);
}
