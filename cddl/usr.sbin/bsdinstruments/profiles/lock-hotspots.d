/*
 * Lock hotspots by stack — most contended locks with context.
 *
 * Aggregates lockstat contention events by kernel stack to
 * show exactly where lock contention originates. More
 * diagnostic than lock-contention which only aggregates by
 * execname.
 */

lockstat:::adaptive-block
/* @bsdinstruments-predicate */
{
    @block_time[execname, stack()] = sum(arg1);
    @block_count[execname, stack()] = count();
}

lockstat:::adaptive-spin
/* @bsdinstruments-predicate */
{
    @spin_time[execname, stack()] = sum(arg1);
    @spin_count[execname, stack()] = count();
}

dtrace:::END
{
    printf("\n--- Adaptive mutex block time (ns) by stack ---\n");
    printa(@block_time);
    printf("\n--- Adaptive mutex block count by stack ---\n");
    printa(@block_count);
    printf("\n--- Adaptive mutex spin time (ns) by stack ---\n");
    printa(@spin_time);
    printf("\n--- Adaptive mutex spin count by stack ---\n");
    printa(@spin_count);
}
