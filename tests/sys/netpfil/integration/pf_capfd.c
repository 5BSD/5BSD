/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 *
 * Open /dev/pf the way BSDNetwork's system.Network.PF service does
 * (usr.sbin/BSDNetwork/pf_session.c): read-only, rights limited to READ,
 * FSTAT and IOCTL, and ioctls limited to DIOCGETSTATES.  Enter capability
 * mode and report what pf answers:
 *
 *	getstates ok <number of states>
 *	getstatus <errno name>
 *	addrule <errno name>
 *	begin <errno name>
 *
 * Used by consumers.sh:pf_monitor_descriptor.
 */

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *
errname(int error)
{
	switch (error) {
	case 0:
		return ("ok");
	case ENOTCAPABLE:
		return ("ENOTCAPABLE");
	case EPERM:
		return ("EPERM");
	case EACCES:
		return ("EACCES");
	case EBADF:
		return ("EBADF");
	case EINVAL:
		return ("EINVAL");
	default:
		return ("other");
	}
}

static void
try_ioctl(int fd, const char *name, unsigned long cmd, void *arg)
{
	int error;

	error = ioctl(fd, cmd, arg) == -1 ? errno : 0;
	printf("%s %s\n", name, errname(error));
}

int
main(void)
{
	static const unsigned long cmds[] = { DIOCGETSTATES };
	struct pfioc_states ps;
	struct pf_status status;
	struct pfioc_rule pr;
	struct pfioc_trans trans;
	cap_rights_t rights;
	size_t len;
	void *buf;
	int fd;

	fd = open("/dev/pf", O_RDONLY);
	if (fd == -1)
		err(1, "open /dev/pf");
	cap_rights_init(&rights, CAP_READ, CAP_FSTAT, CAP_IOCTL);
	if (cap_rights_limit(fd, &rights) == -1)
		err(1, "cap_rights_limit");
	if (cap_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		err(1, "cap_ioctls_limit");
	if (cap_enter() == -1)
		err(1, "cap_enter");

	/* Size the export, then fetch it; retry while the table grows. */
	for (len = 0;;) {
		memset(&ps, 0, sizeof(ps));
		buf = NULL;
		if (len > 0 && (buf = malloc(len)) == NULL)
			err(1, "malloc");
		ps.ps_len = len;
		ps.ps_buf = buf;
		if (ioctl(fd, DIOCGETSTATES, &ps) == -1)
			err(1, "DIOCGETSTATES");
		if (len > 0 && ps.ps_len <= len)
			break;
		free(buf);
		if (ps.ps_len == 0)
			break;
		len = ps.ps_len + 16 * sizeof(struct pfsync_state);
	}
	printf("getstates ok %zu\n", ps.ps_len / sizeof(struct pfsync_state));
	free(buf);

	memset(&status, 0, sizeof(status));
	try_ioctl(fd, "getstatus", DIOCGETSTATUS, &status);
	memset(&pr, 0, sizeof(pr));
	try_ioctl(fd, "addrule", DIOCADDRULE, &pr);
	memset(&trans, 0, sizeof(trans));
	try_ioctl(fd, "begin", DIOCXBEGIN, &trans);

	return (0);
}
