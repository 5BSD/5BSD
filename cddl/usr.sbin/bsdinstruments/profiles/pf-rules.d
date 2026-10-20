/*
 * pf ruleset evaluation - pf_test_rule() latency, anchors entered and
 * logged rule hits by rule number (dtrace_pf(4)).
 */

pf:ip:rules:entry
/* @bsdinstruments-predicate */
{
	self->rts = timestamp;
}

fbt::pf_test_rule:return
/self->rts/
{
	@eval_ns[arg1] = quantize(timestamp - self->rts);
	self->rts = 0;
}

pf:ip:anchor:enter
{
	@anchors[stringof(args[1]->anchor != NULL ?
	    args[1]->anchor->path : "main")] = count();
}

pf:log:pflog:packet
{
	@logged[args[2]->nr, arg1] = count();
}

dtrace:::END
{
	printf("\n--- pf_test_rule() latency (ns) by action ---\n");
	printa(@eval_ns);
	printf("\n--- rulesets/anchors evaluated ---\n");
	printa("  %-40s %@d\n", @anchors);
	printf("\n--- logged packets (rule number, reason) ---\n");
	printa("  rule %-6d reason %-3d %@d\n", @logged);
}
