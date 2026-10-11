/*
 * Wireless transition results, association outcomes and driver scan completion.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

wlan:::state-result
/* @bsdinstruments-predicate */
{
    @transitions[arg0, arg1, arg2, arg3, arg4] = count();
}

wlan:::assoc-fail
/* @bsdinstruments-predicate */
{
    @association_failures[arg0, arg1] = count();
}

wlan:::assoc-success
/* @bsdinstruments-predicate */
{
    @association_successes[arg0] = count();
}

wlan:::scan-done
/* @bsdinstruments-predicate */
{
    @driver_scan_done[arg0, arg1, arg2] = count();
}
