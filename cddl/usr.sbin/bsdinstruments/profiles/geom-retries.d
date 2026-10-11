/*
 * GEOM resource retries and completion results; direct=1 bypasses the up queue.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

geom:::io-retry
/* @bsdinstruments-predicate */
{
    @retries[arg1, arg2, arg3] = count();
}

geom:::io-complete
/* @bsdinstruments-predicate */
{
    @completions[arg1, arg2, arg3] = count();
}
