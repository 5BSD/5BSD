/*
 * Linuxulator socket option results and ancillary-data rejection/truncation.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

linuxulator*:socket::setopt-done,
linuxulator*:socket::getopt-done
/* @bsdinstruments-predicate */
{
    @options[probename, pid, arg1, arg2, arg3] = count();
}

linuxulator*:socket::cmsg-reject
/* @bsdinstruments-predicate */
{
    @rejected[pid, arg0, arg1, arg2] = count();
}

linuxulator*:socket::cmsg-truncate
/* @bsdinstruments-predicate */
{
    @truncated[pid, arg0] = count();
}
