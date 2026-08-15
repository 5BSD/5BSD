#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes vnode hook coverage\n");
}

fbt::oes_mac_vnode_check_*:entry
{
	hooks++;
	@byhook[probefunc] = count();
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (hooks == 0)
		failed = 1;
	printa(@byhook);
	exit(failed);
}
