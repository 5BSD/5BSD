/*
 * gtaskqueue execution/drain latency; execution pairs use queue, task and sequence.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

gtaskqueue:::execute-start
/* @bsdinstruments-predicate */
{
    execute_start[arg0, arg1, arg2] = timestamp;
}

gtaskqueue:::execute-done
/execute_start[arg0, arg1, arg2] != 0/
{
    @execute_us[arg0] = quantize((timestamp - execute_start[arg0, arg1, arg2]) / 1000);
    execute_start[arg0, arg1, arg2] = 0;
}

gtaskqueue:::drain-start
/* @bsdinstruments-predicate */
{
    drain_start[tid, arg0, arg1] = timestamp;
}

gtaskqueue:::drain-done
/drain_start[tid, arg0, arg1] != 0/
{
    @drain_us[arg0] = quantize((timestamp - drain_start[tid, arg0, arg1]) / 1000);
    drain_start[tid, arg0, arg1] = 0;
}

gtaskqueue:::coalesce
/* @bsdinstruments-predicate */
{
    @coalesced[arg0] = count();
}

gtaskqueue:::enqueue
/* @bsdinstruments-predicate */
{
    queue_start[arg0, arg1] = timestamp;
}

gtaskqueue:::execute-start
/queue_start[arg0, arg1] != 0/
{
    @queue_us[arg0] = quantize((timestamp - queue_start[arg0, arg1]) / 1000);
    queue_start[arg0, arg1] = 0;
}

gtaskqueue:::reject
/* @bsdinstruments-predicate */
{
    @rejected[arg0, arg2] = count();
}

gtaskqueue:::cancel
{
    queue_start[arg0, arg1] = 0;
}
