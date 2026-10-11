/*
 * PCM xrun detections: direction 0 playback, 1 recording; channel trigger outcomes.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

pcm:::xrun
/* @bsdinstruments-predicate */
{
    @xruns[arg0, arg1] = count();
}

pcm:::xrun
/* @bsdinstruments-predicate */
{
    @ready_bytes[arg0, arg1] = quantize(arg2);
    @wanted_or_free_bytes[arg0, arg1] = quantize(arg3);
}

pcm:::trigger
/* @bsdinstruments-predicate */
{
    @triggers[arg0, arg1, arg2] = count();
}
