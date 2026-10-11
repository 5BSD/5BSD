/*
 * taskqueue execution/drain latency; execution pairs use queue, task and sequence.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

taskqueue:::execute-start
/* @bsdinstruments-predicate */
{
    execute_start[arg0, arg1, arg2] = timestamp;
}

taskqueue:::execute-done
/execute_start[arg0, arg1, arg2] != 0/
{
    @execute_us[arg0] = quantize((timestamp - execute_start[arg0, arg1, arg2]) / 1000);
    execute_start[arg0, arg1, arg2] = 0;
}

taskqueue:::drain-start
/* @bsdinstruments-predicate */
{
    drain_start[tid, arg0, arg1] = timestamp;
}

taskqueue:::drain-done
/drain_start[tid, arg0, arg1] != 0/
{
    @drain_us[arg0] = quantize((timestamp - drain_start[tid, arg0, arg1]) / 1000);
    drain_start[tid, arg0, arg1] = 0;
}

taskqueue:::coalesce
/* @bsdinstruments-predicate */
{
    @coalesced[arg0] = count();
}
