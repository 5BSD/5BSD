/*
 * Linuxulator futex wait duration and outcomes, keyed by process and address.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

linuxulator*:futex::wait-start
/* @bsdinstruments-predicate */
{
    wait_start[tid, arg0] = timestamp;
}

linuxulator*:futex::wait-done
/wait_start[tid, arg0] != 0/
{
    @wait_us[pid, arg1] = quantize((timestamp - wait_start[tid, arg0]) / 1000);
    wait_start[tid, arg0] = 0;
}

linuxulator*:futex::wake-done
/* @bsdinstruments-predicate */
{
    @wakes[pid, arg1, arg2, arg3] = count();
}

linuxulator*:futex::owner-death
/* @bsdinstruments-predicate */
{
    @owner_death[pid, arg1, arg2] = count();
}
