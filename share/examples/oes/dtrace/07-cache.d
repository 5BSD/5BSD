#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes decision cache workflow\n");
}

fbt::oes_client_cache_add:entry
{
	cache_add++;
}

fbt::oes_client_cache_lookup:entry
{
	cache_lookup++;
}

fbt::oes_client_cache_remove:entry
{
	cache_remove++;
}

fbt::oes_client_cache_clear:entry
{
	cache_clear++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (cache_add == 0 || cache_lookup == 0)
		failed = 1;
	printf("cache_add=%d cache_lookup=%d cache_remove=%d cache_clear=%d\n",
	    cache_add, cache_lookup, cache_remove, cache_clear);
	exit(failed);
}
