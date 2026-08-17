/*
 * Sleep site hotspots — where threads block most often.
 *
 * Aggregates sched:::sleep events by kernel stack to show
 * the most common blocking points. High counts at a single
 * sleep site indicate a bottleneck (lock, I/O, condition var).
 */

sched:::sleep
/* @bsdinstruments-predicate */
{
    @sites[execname, stack()] = count();
    @by_process[execname] = count();
}

dtrace:::END
{
    printf("\n--- Sleep count by process ---\n");
    printa("%-30s %@d\n", @by_process);
    printf("\n--- Sleep sites by stack ---\n");
    printa(@sites);
}
