/*
 * pf firewall evaluation latency — per-packet timing.
 *
 * Measures time spent in pf_test per packet. Slow evaluation
 * indicates complex rulesets or table lookups. Histogram
 * shows the latency distribution. Requires pf loaded.
 */

fbt::pf_test:entry
/* @bsdinstruments-predicate */
{
    self->pf_ts = timestamp;
}

fbt::pf_test:return
/self->pf_ts/
{
    this->us = (timestamp - self->pf_ts) / 1000;
    @latency = quantize(this->us);
    @by_proc[execname] = quantize(this->us);
    self->pf_ts = 0;
}

dtrace:::END
{
    printf("\n--- pf_test latency (us) ---\n");
    printa(@latency);
    printf("\n--- pf_test latency by process (us) ---\n");
    printa(@by_proc);
}
