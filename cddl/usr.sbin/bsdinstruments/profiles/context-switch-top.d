/*
 * Context switch frequency — off-cpu and preempt counts by process.
 *
 * Counts sched:::off-cpu events (thread went off CPU for any
 * reason — sleep, block, yield, or preemption) and separately
 * counts sched:::preempt events (involuntary preemption only).
 * The off-cpu count includes preemptions, so preempt is a
 * subset of off-cpu.
 */

sched:::off-cpu
/* @bsdinstruments-predicate */
{
    @off_cpu[execname] = count();
}

sched:::preempt
/* @bsdinstruments-predicate */
{
    @preempt[execname] = count();
}

dtrace:::END
{
    printf("\n--- Off-CPU events (all reasons) by process ---\n");
    printa("%-30s %@d\n", @off_cpu);
    printf("\n--- Preemption events (involuntary only) by process ---\n");
    printa("%-30s %@d\n", @preempt);
}
