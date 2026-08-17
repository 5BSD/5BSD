/*
 * ZFS ARC activity — cache reads, completions, and evictions.
 *
 * Traces the ZFS Adaptive Replacement Cache to show read volume
 * and eviction pressure. arc_read counts all ARC read requests;
 * arc_read_done counts all completions (both hits and misses);
 * arc_evict counts evictions. Requires zfs.ko loaded.
 */

fbt:zfs:arc_read:entry
/* @bsdinstruments-predicate */
{
    @arc_reads[execname] = count();
}

fbt:zfs:arc_read_done:entry
/* @bsdinstruments-predicate */
{
    @arc_completions[execname] = count();
}

fbt:zfs:arc_evict:entry
/* @bsdinstruments-predicate */
{
    @arc_evictions = count();
}

dtrace:::END
{
    printf("\n--- ARC reads by process ---\n");
    printa("%-30s %@d\n", @arc_reads);
    printf("\n--- ARC completions by process ---\n");
    printa("%-30s %@d\n", @arc_completions);
    printf("\n--- ARC evictions ---\n");
    printa("%@d\n", @arc_evictions);
}
