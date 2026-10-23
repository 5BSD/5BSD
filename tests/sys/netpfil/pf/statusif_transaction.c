/* SPDX-License-Identifier: BSD-2-Clause */
/* Run only in an empty disposable VNET: the helper commits an empty ruleset. */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <net/pfvar.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int fd;
static struct pfioc_trans_e entry = { .type = PF_TRANS_RULESET };
static struct pfioc_trans transaction = {
	.size = 1, .esize = sizeof(entry), .array = &entry
};

static void
request(unsigned long command, void *argument)
{
	if (ioctl(fd, command, argument) == -1)
		err(1, "ioctl %lu", command);
}

static void
check_status(const char *expected)
{
	struct pf_status status = {0};

	request(DIOCGETSTATUS, &status);
	if (strcmp(status.ifname, expected) != 0)
		errx(1, "active status interface: expected '%s', got '%s'",
		    expected, status.ifname);
}

static void
set_status(const char *name)
{
	struct pfioc_iface iface = {0};

	strlcpy(iface.pfiio_name, name, sizeof(iface.pfiio_name));
	request(DIOCSETSTATUSIF, &iface);
}

int
main(int argc, char **argv)
{
	if (argc != 2 || (strcmp(argv[1], "set") != 0 &&
	    strcmp(argv[1], "clear_commit") != 0 &&
	    strcmp(argv[1], "clear_rollback") != 0))
		errx(1, "usage: statusif_transaction set|clear_commit|clear_rollback");
	fd = open("/dev/pf", O_RDWR);
	if (fd < 0)
		err(1, "/dev/pf");

	check_status("");
	request(DIOCXBEGIN, &transaction);
	set_status("lo0");
	check_status("");
	request(DIOCXCOMMIT, &transaction);
	check_status("lo0");

	if (strcmp(argv[1], "set") != 0) {
		request(DIOCXBEGIN, &transaction);
		set_status("");
		check_status("lo0");
		if (strcmp(argv[1], "clear_rollback") == 0) {
			request(DIOCXROLLBACK, &transaction);
			check_status("lo0");
		} else {
			request(DIOCXCOMMIT, &transaction);
			check_status("");
		}
	}
	close(fd);
	puts("PASS");
	return (0);
}
