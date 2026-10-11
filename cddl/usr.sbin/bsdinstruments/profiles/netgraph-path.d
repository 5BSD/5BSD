/*
 * Netgraph queued items, dispatch types/depths, results and hook disconnections.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

netgraph:::queue
/* @bsdinstruments-predicate */
{
    @queued[arg0, arg2] = count();
}

netgraph:::dispatch
/* @bsdinstruments-predicate */
{
    @dispatched[arg0, arg2, arg3] = count();
}

netgraph:::dispatch-done
/* @bsdinstruments-predicate */
{
    @results[arg0, arg2] = count();
}

netgraph:::disconnect
/* @bsdinstruments-predicate */
{
    @disconnected[arg0] = count();
}
