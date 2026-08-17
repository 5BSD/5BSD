/*
 * CPU time distribution — on-CPU duration histogram per process.
 *
 * Measures how long each process runs before yielding the CPU.
 * Short runs indicate high context-switch rates or preemption.
 * Long runs indicate CPU-bound workloads. Histogram in us.
 */

sched:::on-cpu
/* @bsdinstruments-predicate */
{
    self->on_ts = timestamp;
}

sched:::off-cpu
/self->on_ts/
{
    this->us = (timestamp - self->on_ts) / 1000;
    @dist[execname] = quantize(this->us);
    self->on_ts = 0;
}

dtrace:::END
{
    printf("\n--- On-CPU time distribution (us) by process ---\n");
    printa(@dist);
}
