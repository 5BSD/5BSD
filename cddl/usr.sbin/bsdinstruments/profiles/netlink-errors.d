/*
 * Netlink handler outcomes, malformed lengths and dropped reply/notification batches.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

netlink:::request
/* @bsdinstruments-predicate */
{
    request_start[tid, arg0, arg1] = timestamp;
}

netlink:::result
/request_start[tid, arg0, arg1] != 0/
{
    @request_us[arg2, arg3] = quantize((timestamp - request_start[tid, arg0, arg1]) / 1000);
    request_start[tid, arg0, arg1] = 0;
}

netlink:::result
/* @bsdinstruments-predicate */
{
    @results[arg0, arg2, arg3, arg4] = count();
}

netlink:::malformed
/* @bsdinstruments-predicate */
{
    @malformed[arg0, arg2, arg3] = count();
}

netlink:::rx-drop
/* @bsdinstruments-predicate */
{
    @dropped_messages[arg0] = sum(arg1);
    @dropped_bytes[arg0] = sum(arg2);
}
