/*
 * pf firewall evaluation latency - per-packet timing.
 *
 * Measures time spent in pf_test() per packet using the pf SDT
 * provider (dtrace_pf(4)).  Slow evaluation indicates complex
 * rulesets or table lookups.  Requires pf loaded.
 */

pf:ip:test:entry
/* @bsdinstruments-predicate */
{
	self->pf_ts = timestamp;
}

pf:ip:test:finish
/self->pf_ts/
{
	this->us = (timestamp - self->pf_ts) / 1000;
	@latency = quantize(this->us);
	@by_if[stringof(args[2]->if_xname)] = quantize(this->us);
	self->pf_ts = 0;
}

dtrace:::END
{
	printf("\n--- pf_test latency (us) ---\n");
	printa(@latency);
	printf("\n--- pf_test latency by interface (us) ---\n");
	printa(@by_if);
}
