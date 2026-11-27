/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * launch_authority_probe FD: the image subset_unit's requester-exec
 * scenario executes (fexecve, in capability mode, so this program is
 * static) to see what a channel end SwitchBoard handed to the unit allows
 * after the receiving process has executed another image.  GETINFO on FD
 * passes through the end's binding check before anything else; the exit
 * status is its errno (0: admitted).  Exits 255 when FD is not a number.
 */

#include <sys/ioctl.h>

#include <dev/mac_capability/mac_capability_ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct mac_capability_info_args info;
	char *end;
	long fd;

	if (argc != 2)
		return (255);
	fd = strtol(argv[1], &end, 10);
	if (*argv[1] == '\0' || *end != '\0' || fd < 0 || fd > 65535)
		return (255);
	memset(&info, 0, sizeof(info));
	if (ioctl((int)fd, MAC_CAPABILITY_GETINFO, &info) == -1)
		return (errno);
	return (0);
}
