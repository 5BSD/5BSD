#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes fork/exit workflow\n");
}

fbt::oes_proc_event_fork:entry
{
	fork_evt++;
}

fbt::oes_proc_event_exit:entry
{
	exit_evt++;
}

fbt::oes_deliver_notify_nosleep:entry
{
	deliver++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (fork_evt == 0 || exit_evt == 0)
		failed = 1;
	printf("fork_evt=%d exit_evt=%d deliver=%d\n",
	    fork_evt, exit_evt, deliver);
	exit(failed);
}
