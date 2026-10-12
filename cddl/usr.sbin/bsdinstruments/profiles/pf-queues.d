/*
 * pf queueing and delay - packets delayed by "set delay" rules, by
 * queue id and requested delay, and their release on the interface
 * (dtrace_pf(4); queue statistics are reported by pfctl -s queue).
 */

pf:queue:packet:delay
/* @bsdinstruments-predicate */
{
	@delayed[arg0, arg1] = count();
}

fbt::pf_pktenqueue_delayed:entry
{
	@released = count();
}

dtrace:::END
{
	printf("\n--- delayed packets (queue id, delay ms) ---\n");
	printa("  qid %-6d %-6d ms %@d\n", @delayed);
	printa("\n  delayed packets released %@d\n", @released);
}
