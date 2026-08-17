/*
 * Off-CPU profiler — blocked/waiting stack analysis.
 *
 * Two complementary views:
 * 1. Blocking site frequency: captures the kernel stack at
 *    sched:::off-cpu to show WHERE threads block.
 * 2. Blocked duration: measures elapsed time between off-cpu
 *    and on-cpu, aggregated by process. The on-cpu stack shows
 *    the resume path, not the blocking site (DTrace limitation).
 *
 * For blocking-site + duration correlation, use the frequency
 * view to find hot sites, then examine the duration histogram.
 */

sched:::off-cpu
/* @bsdinstruments-predicate */
{
    /* Blocking site — captured at the point of going off-CPU. */
    @block_sites[execname, stack()] = count();
    self->offcpu_ts = timestamp;
}

sched:::on-cpu
/self->offcpu_ts/
{
    this->blocked_us = (timestamp - self->offcpu_ts) / 1000;
    @blocked_time[execname] = quantize(this->blocked_us);
    @total_blocked[execname] = sum(this->blocked_us);
    self->offcpu_ts = 0;
}

dtrace:::END
{
    printf("\n--- Blocking site frequency (off-cpu stacks) ---\n");
    printa(@block_sites);
    printf("\n--- Off-CPU duration distribution (us) by process ---\n");
    printa(@blocked_time);
    printf("\n--- Total off-CPU time (us) by process ---\n");
    printa("%-30s %@d\n", @total_blocked);
}
