/*
 * Bluetooth RFCOMM flow control, credits, drop reasons and closure outcomes.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

bluetooth:::rfcomm-flow
/* @bsdinstruments-predicate */
{
    @flow[arg1, arg2, arg3] = count();
}

bluetooth:::rfcomm-credit
/* @bsdinstruments-predicate */
{
    @tx_credits[arg1] = quantize(arg2);
    @rx_credits[arg1] = quantize(arg3);
}

bluetooth:::rfcomm-drop
/* @bsdinstruments-predicate */
{
    @drops[arg1, arg2, arg4] = count();
}

bluetooth:::rfcomm-close
/* @bsdinstruments-predicate */
{
    @closures[arg1, arg2, arg3] = count();
}
