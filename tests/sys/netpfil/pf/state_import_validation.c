/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in an empty disposable VNET. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct pfioc_state ps = {0};
	struct pf_status status = {0};
	int fd, result, saved_errno, valid;

	if (argc != 2)
	 errx(1, "usage: state_import_validation valid|direction|src|dst|name|timeout|creator");
	valid = strcmp(argv[1], "valid") == 0;
	ps.state.id = 1;
	ps.state.creatorid = htonl(1);
	strlcpy(ps.state.ifname, "lo0", sizeof(ps.state.ifname));
	ps.state.af = ps.state.key[0].af = ps.state.key[1].af = AF_INET;
	ps.state.proto = IPPROTO_ICMP;
	ps.state.direction = PF_OUT;
	ps.state.timeout = PFTM_ICMP_FIRST_PACKET;
	ps.state.expire = htonl(120);
	if (strcmp(argv[1], "direction") == 0)
	 ps.state.direction = 255;
	else if (strcmp(argv[1], "src") == 0)
	 ps.state.src.state = 255;
	else if (strcmp(argv[1], "dst") == 0)
	 ps.state.dst.state = 255;
	else if (strcmp(argv[1], "name") == 0)
	 memset(ps.state.ifname, 'A', sizeof(ps.state.ifname));
	else if (strcmp(argv[1], "timeout") == 0)
	 ps.state.timeout = 255;
	else if (strcmp(argv[1], "creator") == 0)
	 ps.state.creatorid = 0;
	else if (!valid)
	 errx(1, "unknown mode");
	fd = open("/dev/pf", O_RDWR);
	if (fd < 0)
	 err(1, "/dev/pf");
	if (ioctl(fd, DIOCGETSTATUS, &status) == -1)
	 err(1, "DIOCGETSTATUS");
	if (status.states != 0)
	 errx(1, "fixture is not empty");
	errno = 0;
	result = ioctl(fd, DIOCADDSTATE, &ps);
	saved_errno = errno;
	printf("IMPORT_RESULT=%d ERRNO=%d\n", result, saved_errno);
	if (valid ? result != 0 : (result != -1 || saved_errno != EINVAL))
	 errx(1, "unexpected import result for %s", argv[1]);
	if (ioctl(fd, DIOCGETSTATUS, &status) == -1)
	 err(1, "DIOCGETSTATUS after import");
	printf("ALLOCATED_STATES=%u\n", status.states);
	if (status.states != (unsigned)valid)
	 errx(1, "unexpected allocated state count");
	close(fd);
	puts("PASS");
	return (0);
}
