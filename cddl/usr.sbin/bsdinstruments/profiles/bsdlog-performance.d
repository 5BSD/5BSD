/*
 * Live system.Log batching, wakeup, persistence, and flush performance.
 * Usage: bsdinstruments watch bsdlog-performance
 */

#pragma D option quiet

dtrace:::BEGIN
{
	printf("Tracing system.Log... Ctrl-C for summary.\n");
}

logcmp*:::record-enqueue
{
	@client_records[execname, pid, arg2] = count();
	@client_bytes[execname, pid] = sum(arg1);
}

logcmp*:::wakeup-send
{
	@client_wakes[execname, pid, arg1] = count();
}

logcmp*:::flush-complete
{
	@client_flush_ns[execname, pid, arg1] = quantize(arg0);
}

bsdlog*:::batch-drain
{
	@batches[pid, arg4] = count();
	@batch_records[pid] = sum(arg3);
	@batch_size[pid] = quantize(arg3);
}

bsdlog*:::wakeup-receive
{
	@provider_wakes[pid, arg2] = count();
}

bsdlog*:::storage-persist
{
	@persist_records[pid, arg4] = count();
	@persist_bytes[pid] = sum(arg3);
}

bsdlog*:::flush-complete
{
	@provider_flush_ns[pid, arg4] = quantize(arg3);
}

bsdlog*:::record-drop
{
	@drops[pid, arg2] = count();
}

dtrace:::END
{
	printf("\nclient enqueue results:\n");
	printa("%-16s %6d result=%d %@d\n", @client_records);
	printa("client bytes %-16s %6d %@d\n", @client_bytes);
	printf("\nclient wake results:\n");
	printa("%-16s %6d result=%d %@d\n", @client_wakes);
	printa("\nclient flush latency %-16s pid=%d result=%d %@d\n",
	    @client_flush_ns);
	printf("\nprovider batches and wakes:\n");
	printa("pid=%d result=%d batches=%@d\n", @batches);
	printa("pid=%d records=%@d\n", @batch_records);
	printa("pid=%d batch-size %@d\n", @batch_size);
	printa("pid=%d wake-result=%d %@d\n", @provider_wakes);
	printf("\nstorage and drops:\n");
	printa("pid=%d result=%d records=%@d\n", @persist_records);
	printa("pid=%d bytes=%@d\n", @persist_bytes);
	printa("pid=%d error=%d drops=%@d\n", @drops);
	printa("\nprovider flush latency pid=%d result=%d %@d\n",
	    @provider_flush_ns);
}
