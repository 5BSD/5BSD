/*
 * Linuxulator epoll wait duration, returned event counts and control errors.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

linuxulator*:epoll::wait-start
/* @bsdinstruments-predicate */
{
    wait_start[tid, arg0] = timestamp;
}

linuxulator*:epoll::wait-done
/wait_start[tid, arg0] != 0/
{
    @wait_us[pid, arg0, arg2] = quantize((timestamp - wait_start[tid, arg0]) / 1000);
    wait_start[tid, arg0] = 0;
}

linuxulator*:epoll::wait-done
/* @bsdinstruments-predicate */
{
    @returned_events[pid, arg2] = quantize(arg1);
}

linuxulator*:epoll::ctl-done
/* @bsdinstruments-predicate */
{
    @ctl_results[pid, arg2, arg3] = count();
}
