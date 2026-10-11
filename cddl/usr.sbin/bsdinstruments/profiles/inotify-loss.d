/*
 * Inotify queue outcomes: 0 enqueue, 1 allocation shortage, 2 coalesce, 3 limit.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

inotify:::queue
/* @bsdinstruments-predicate */
{
    @outcomes[arg0, arg5] = count();
}

inotify:::queue
/* @bsdinstruments-predicate */
{
    @depth[arg0, arg5] = quantize(arg4);
}

inotify:::watch-remove
/* @bsdinstruments-predicate */
{
    @removed[arg0] = count();
}
