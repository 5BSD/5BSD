/*
 * UMA zone limit waits, direct-item allocation failures and reclaim duration.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

uma:::limit-wait
/* @bsdinstruments-predicate */
{
    limit_start[tid, arg0] = timestamp;
    @limit_sleeps[stringof(arg1)] = count();
}

uma:::limit-resume
/limit_start[tid, arg0] != 0/
{
    @limit_us[arg0] = quantize((timestamp - limit_start[tid, arg0]) / 1000);
    limit_start[tid, arg0] = 0;
}

uma:::alloc-fail
/* @bsdinstruments-predicate */
{
    @failures[stringof(arg1), arg2, arg3] = count();
}

uma:::reclaim-start
/* @bsdinstruments-predicate */
{
    reclaim_start[tid, arg0] = timestamp;
}

uma:::reclaim-done
/reclaim_start[tid, arg0] != 0/
{
    @reclaim_us[arg0] = quantize((timestamp - reclaim_start[tid, arg0]) / 1000);
    reclaim_start[tid, arg0] = 0;
}
