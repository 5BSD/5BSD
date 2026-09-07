/*
 * Live libshmring traffic, backpressure, and wake-coalescing summary.
 * Usage: bsdinstruments watch shmring-traffic
 * Stop with Ctrl-C to print cumulative totals.
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("Tracing libshmring traffic... Ctrl-C for summary.\n");
}

shmring*:::write
{
	@operations[execname, pid, "write", arg0] = count();
	@bytes[execname, pid, "write", arg0] = sum(arg2);
	@errors[execname, pid, "write", arg3] = count();
}

shmring*:::read
{
	@operations[execname, pid, "read", arg0] = count();
	@bytes[execname, pid, "read", arg0] = sum(arg2);
	@errors[execname, pid, "read", arg3] = count();
}

shmring*:::consumer-arm
{
	@arms[execname, pid, arg1] = count();
}

shmring*:::producer-wakeup
{
	@wake_decisions[execname, pid, arg1] = count();
}

shmring*:::corrupt
{
	@corruption[execname, pid] = count();
}

dtrace:::END
{
	printf("\noperations (process pid direction mode):\n");
	printa("%-16s %6d %-5s mode=%d %@d\n", @operations);
	printf("\nbytes (process pid direction mode):\n");
	printa("%-16s %6d %-5s mode=%d %@d\n", @bytes);
	printf("\nresults (process pid direction errno):\n");
	printa("%-16s %6d %-5s error=%d %@d\n", @errors);
	printf("\nconsumer arms (readable=0 slept, readable=1 raced):\n");
	printa("%-16s %6d readable=%d %@d\n", @arms);
	printf("\nproducer wake decisions (needed=1 means one signal):\n");
	printa("%-16s %6d needed=%d %@d\n", @wake_decisions);
	printa("\ncorruption %-16s %6d %@d\n", @corruption);
}
