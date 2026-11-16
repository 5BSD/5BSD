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
	printf("oes poll/kqueue workflow\n");
}

fbt::oes_poll:entry
{
	poll++;
}

fbt::oes_kqfilter:entry
{
	kqfilter++;
}

fbt::oes_kqdetach:entry
{
	kqdetach++;
}

fbt::oes_kqread:entry
{
	kqread++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (poll == 0 && kqfilter == 0)
		failed = 1;
	printf("poll=%d kqfilter=%d kqread=%d kqdetach=%d\n",
	    poll, kqfilter, kqread, kqdetach);
	exit(failed);
}
