/*
 * pf address translation - nat-to/rdr-to/binat-to address selection
 * and af-to translations (dtrace_pf(4)), with selection latency.
 */

pf:nat:transaddr:entry
/* @bsdinstruments-predicate */
{
	@rules[args[0]->nr] = count();
}

pf:nat:af_to:translate
{
	@afto = count();
}

fbt::pf_get_transaddr:entry { self->ts = timestamp; }
fbt::pf_get_transaddr:return
/self->ts/
{
	@lat_ns = quantize(timestamp - self->ts);
	@result[arg1] = count();
	self->ts = 0;
}

dtrace:::END
{
	printf("\n--- translations by rule number ---\n");
	printa("  rule %-6d %@d\n", @rules);
	printa("\n  af-to translations %@d\n", @afto);
	printf("\n--- pf_get_transaddr() result (0 ok) ---\n");
	printa("  %d %@d\n", @result);
	printf("\n--- selection latency (ns) ---\n");
	printa(@lat_ns);
}
