/*
 * DMA bounce shortages and time from deferral to resource readiness and callback.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

busdma:::defer
/* @bsdinstruments-predicate */
{
    deferred[arg1] = timestamp;
    @pages_needed[arg0] = quantize(arg2);
}

busdma:::ready
/deferred[arg1] != 0/
{
    @resource_wait_us[arg0] = quantize((timestamp - deferred[arg1]) / 1000);
}

busdma:::callback
/deferred[arg1] != 0/
{
    @callback_wait_us[arg0] = quantize((timestamp - deferred[arg1]) / 1000);
    deferred[arg1] = 0;
}

busdma:::reserve-fail
/* @bsdinstruments-predicate */
{
    @nowait_failures[arg0] = count();
}
