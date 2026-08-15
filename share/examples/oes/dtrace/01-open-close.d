#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes open/close workflow\n");
}

fbt::oes_open:entry
{
	open++;
	self->open = 1;
}

fbt::oes_client_alloc:return
/self->open/
{
	alloc++;
	self->open = 0;
}

fbt::oes_client_dtor:entry
{
	dtor++;
	self->dtor = 1;
}

fbt::oes_client_free:entry
/self->dtor/
{
	free++;
	self->dtor = 0;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (open == 0 || alloc == 0 || dtor == 0 || free == 0)
		failed = 1;
	printf("open=%d alloc=%d dtor=%d free=%d\n",
	    open, alloc, dtor, free);
	exit(failed);
}
