/*
 * Epoch grace-period waits (preemptible=1) and callback drain duration.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

epoch:::wait-start
/* @bsdinstruments-predicate */
{
    wait_start[tid, arg0, arg1] = timestamp;
}

epoch:::wait-done
/wait_start[tid, arg0, arg1] != 0/
{
    @wait_us[arg0, arg1] = quantize((timestamp - wait_start[tid, arg0, arg1]) / 1000);
    wait_start[tid, arg0, arg1] = 0;
}

epoch:::drain-start
/* @bsdinstruments-predicate */
{
    drain_start[tid, arg0] = timestamp;
}

epoch:::drain-done
/drain_start[tid, arg0] != 0/
{
    @drain_us[arg0] = quantize((timestamp - drain_start[tid, arg0]) / 1000);
    drain_start[tid, arg0] = 0;
}
