#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes auth group workflow\n");
}

fbt::oes_auth_group_alloc:entry
{
	alloc++;
}

fbt::oes_auth_group_add_pending:entry
{
	add_pending++;
}

fbt::oes_auth_group_wait:entry
{
	wait++;
}

fbt::oes_auth_group_mark_response:entry
{
	mark++;
}

fbt::oes_auth_group_rele:entry
{
	rele++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (alloc == 0)
		failed = 1;
	printf("alloc=%d add_pending=%d wait=%d mark=%d rele=%d\n",
	    alloc, add_pending, wait, mark, rele);
	exit(failed);
}
