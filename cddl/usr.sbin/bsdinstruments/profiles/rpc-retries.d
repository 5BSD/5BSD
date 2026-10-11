/*
 * Kernel RPC datagram retries, connect attempts and duplicate request cache hits.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

krpc:::dg-retry
/* @bsdinstruments-predicate */
{
    @retries[arg0] = count();
}

krpc:::dg-retry
/* @bsdinstruments-predicate */
{
    @retry_ordinal[arg0] = quantize(arg2);
    @backoff_ticks[arg0] = quantize(arg3);
}

krpc:::dg-done
/* @bsdinstruments-predicate */
{
    @status[arg0, arg2] = count();
}

krpc:::connect-start
/* @bsdinstruments-predicate */
{
    connect_start[tid, arg0] = timestamp;
}

krpc:::connect-done
/connect_start[tid, arg0] != 0/
{
    @connect_us[arg0, arg1] = quantize((timestamp - connect_start[tid, arg0]) / 1000);
    connect_start[tid, arg0] = 0;
}

krpc:::replay-hit
/* @bsdinstruments-predicate */
{
    @duplicates[arg0, arg2] = count();
}
