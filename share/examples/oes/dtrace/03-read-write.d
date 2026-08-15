#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes read/write workflow\n");
}

fbt::oes_read:entry
{
	read++;
	self->read = 1;
}

fbt::oes_event_dequeue:entry
/self->read/
{
	dequeue++;
	self->read = 0;
}

fbt::oes_write:entry
{
	write++;
	self->write = 1;
}

fbt::oes_event_respond:entry
/self->write/
{
	respond++;
	self->write = 0;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (read == 0 || dequeue == 0 || write == 0 || respond == 0)
		failed = 1;
	printf("read=%d dequeue=%d write=%d respond=%d\n",
	    read, dequeue, write, respond);
	exit(failed);
}
