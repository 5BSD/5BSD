#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes mute workflow\n");
}

fbt::oes_client_mute:entry
{
	mute++;
}

fbt::oes_client_unmute:entry
{
	unmute++;
}

fbt::oes_client_mute_path:entry
{
	mute_path++;
}

fbt::oes_client_unmute_path:entry
{
	unmute_path++;
}

fbt::oes_client_is_muted:return
/retval == 1/
{
	muted_hit++;
}

fbt::oes_event_is_path_muted:return
/retval == 1/
{
	path_muted_hit++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (mute == 0 && mute_path == 0)
		failed = 1;
	printf("mute=%d unmute=%d mute_path=%d unmute_path=%d muted_hit=%d path_muted_hit=%d\n",
	    mute, unmute, mute_path, unmute_path, muted_hit, path_muted_hit);
	exit(failed);
}
