/*
 * KTLS committed mode changes, software queue latency, async crypto results and drops.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

ktls:::mode-change
/* @bsdinstruments-predicate */
{
    @mode_changes[arg1, arg2] = count();
}

ktls:::enqueue
/* @bsdinstruments-predicate */
{
    queue_start[arg0] = timestamp;
}

ktls:::dispatch
/queue_start[arg0] != 0/
{
    @queue_us["software TX"] = quantize((timestamp - queue_start[arg0]) / 1000);
    queue_start[arg0] = 0;
}

ktls:::crypto-done
/* @bsdinstruments-predicate */
{
    @async_crypto_status[arg2] = count();
}

ktls:::drop
/* @bsdinstruments-predicate */
{
    @drops[arg1] = count();
}

ktls:::tx-fallback
/* @bsdinstruments-predicate */
{
    @tx_fallback[arg1] = count();
}

ktls:::mode-failed
/* @bsdinstruments-predicate */
{
    @mode_failed[arg1, arg2, arg3] = count();
}

ktls:::disable-done
/* @bsdinstruments-predicate */
{
    @disable_done[arg1] = count();
}
