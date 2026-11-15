#!/usr/sbin/dtrace -s
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	failed = 0;
	printf("oes ioctl helper coverage\n");
}

fbt::oes_ioctl_*:entry
{
	helper++;
	@byioctl[probefunc] = count();
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (helper == 0)
		failed = 1;
	printa(@byioctl);
	exit(failed);
}
