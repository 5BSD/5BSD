/*
 * SX lock (shared-exclusive) contention by process.
 *
 * Aggregates sx lock block and spin wait times. SX locks are
 * widely used in the FreeBSD kernel for reader-writer patterns.
 * High contention here indicates VFS, VM, or network bottlenecks.
 */

lockstat:::sx-block
/* @bsdinstruments-predicate */
{
    @sx_block_time[execname] = quantize(arg1);
    @sx_block_count[execname] = count();
}

lockstat:::sx-spin
/* @bsdinstruments-predicate */
{
    @sx_spin_time[execname] = quantize(arg1);
    @sx_spin_count[execname] = count();
}

dtrace:::END
{
    printf("\n=== sx lock block time (ns) ===\n");
    printa(@sx_block_time);
    printf("\n=== sx lock block count ===\n");
    printa("%-30s %@d\n", @sx_block_count);
    printf("\n=== sx lock spin time (ns) ===\n");
    printa(@sx_spin_time);
    printf("\n=== sx lock spin count ===\n");
    printa("%-30s %@d\n", @sx_spin_count);
}
