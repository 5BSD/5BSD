/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * self_events_test's new image after an exec: join the OES client open on
 * the descriptor named in argv[1] (OES_IOC_JOIN), then exit 0, or the
 * ioctl's errno.
 */

#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>

#include <security/oes/oes.h>

int
main(int argc, char *argv[])
{

	if (argc != 2)
		return (64);
	return (ioctl(atoi(argv[1]), OES_IOC_JOIN) == 0 ? 0 : errno);
}
