/*
 * Cross-component IPC volume and error summary for capability daemons.
 * Usage: bsdinstruments watch component-ipc
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("Tracing capability IPC... Ctrl-C for summary.\n");
}

libchannel*:::queue
{
	@channel_queued[execname, pid] = count();
	@channel_bytes[execname, pid] = sum(arg1);
	@channel_depth[execname, pid] = max(arg3);
}

libchannel*:::send
{
	@channel_send[execname, pid, arg3] = count();
}

libchannel*:::complete
{
	@channel_complete[execname, pid, arg1] = count();
}

networkcmp*:::message-send
{
	@network_send[execname, pid, arg0, arg3] = count();
	@network_bytes[execname, pid] = sum(arg1);
}

tracecmp*:::send
{
	@trace_send[execname, pid, arg0, arg2] = count();
	@trace_bytes[execname, pid] = sum(arg1);
}

bsdaudit*:::submit
{
	@audit_submit[pid, arg3] = count();
}

dtrace:::END
{
	printf("\nlibchannel:\n");
	printa("%-16s %6d queued=%@d\n", @channel_queued);
	printa("%-16s %6d bytes=%@d\n", @channel_bytes);
	printa("%-16s %6d max-depth=%@d\n", @channel_depth);
	printa("%-16s %6d send-result=%d %@d\n", @channel_send);
	printa("%-16s %6d complete-result=%d %@d\n", @channel_complete);
	printf("\ntyped component clients:\n");
	printa("network %-16s %6d op=%d result=%d %@d\n", @network_send);
	printa("network-bytes %-16s %6d %@d\n", @network_bytes);
	printa("trace %-16s %6d op=%d result=%d %@d\n", @trace_send);
	printa("trace-bytes %-16s %6d %@d\n", @trace_bytes);
	printa("bsdaudit pid=%d result=%d %@d\n", @audit_submit);
}
