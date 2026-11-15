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
	printf("oes path mute evaluation\n");
}

fbt::oes_event_is_path_muted:entry
{
	check++;
}

fbt::oes_event_path_muted_join:entry
{
	join++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (check == 0)
		failed = 1;
	printf("check=%d join=%d\n", check, join);
	exit(failed);
}
