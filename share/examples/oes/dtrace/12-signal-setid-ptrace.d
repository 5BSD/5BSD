#!/usr/sbin/dtrace -s
#pragma D option quiet

#ifndef TIMEOUT
#define TIMEOUT 20
#endif

BEGIN {
	printf("oes signal/setid/ptrace workflow\n");
}

fbt::oes_mac_proc_check_signal:entry
{
	signal_evt++;
}

fbt::oes_mac_cred_check_setuid:entry
{
	setuid_evt++;
}

fbt::oes_mac_cred_check_setgid:entry
{
	setgid_evt++;
}

fbt::oes_mac_proc_check_debug:entry
{
	ptrace_evt++;
}

tick-TIMEOUTs
{
	printf("timeout\n");
	exit(failed);
}

END
{
	if (signal_evt == 0 && setuid_evt == 0 && setgid_evt == 0 && ptrace_evt == 0)
		failed = 1;
	printf("signal_evt=%d setuid_evt=%d setgid_evt=%d ptrace_evt=%d\n",
	    signal_evt, setuid_evt, setgid_evt, ptrace_evt);
	exit(failed);
}
