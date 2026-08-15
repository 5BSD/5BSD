#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes exec args workflow\n");
}

fbt::oes_generate_exec_event:entry
{
	exec_gen++;
}

fbt::oes_event_get_args:entry
{
	get_args++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (exec_gen == 0)
		failed = 1;
	printf("exec_gen=%d get_args=%d\n", exec_gen, get_args);
	exit(failed);
}
