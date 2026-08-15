#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes load/unload workflow\n");
}

fbt::oes_dev_init:entry
{
	dev_init++;
}

fbt::oes_mac_init:entry
{
	mac_init++;
	if (dev_init == 0)
		failed = 1;
}

fbt::oes_mac_uninit:entry
{
	mac_uninit++;
}

fbt::oes_dev_uninit:entry
{
	dev_uninit++;
	if (mac_uninit == 0)
		failed = 1;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (dev_init == 0 || mac_init == 0)
		failed = 1;
	printf("dev_init=%d mac_init=%d mac_uninit=%d dev_uninit=%d\n",
	    dev_init, mac_init, mac_uninit, dev_uninit);
	exit(failed);
}
