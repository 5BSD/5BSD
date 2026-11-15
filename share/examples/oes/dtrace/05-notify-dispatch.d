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
	printf("oes notify dispatch workflow\n");
}

fbt::oes_generate_vnode_event:entry
/((arg0 & 0x1000) != 0)/
{
	notify_gen++;
	self->notify = 1;
}

fbt::oes_dispatch_event:entry
/self->notify/
{
	dispatch++;
}

fbt::oes_event_enqueue:entry
/self->notify/
{
	enqueue++;
}

fbt::oes_generate_vnode_event:return
/self->notify/
{
	self->notify = 0;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (notify_gen == 0 || dispatch == 0)
		failed = 1;
	printf("notify_gen=%d dispatch=%d enqueue=%d\n",
	    notify_gen, dispatch, enqueue);
	exit(failed);
}
