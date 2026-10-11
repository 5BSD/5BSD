/*
 * Buffer-cache space waits, first-pass flush duration and buffer I/O waits.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

bufcache:::space-wait
/* @bsdinstruments-predicate */
{
    space_start[tid, arg0] = timestamp;
}

bufcache:::space-resume
/space_start[tid, arg0] != 0/
{
    @space_us[arg0, arg1] = quantize((timestamp - space_start[tid, arg0]) / 1000);
    space_start[tid, arg0] = 0;
}

bufcache:::flush-start
/* @bsdinstruments-predicate */
{
    flush_start[tid, arg0, arg1] = timestamp;
}

bufcache:::flush-done
/flush_start[tid, arg0, arg1] != 0/
{
    @flush_us[arg1] = quantize((timestamp - flush_start[tid, arg0, arg1]) / 1000);
    flush_start[tid, arg0, arg1] = 0;
}

bufcache:::io-wait
/* @bsdinstruments-predicate */
{
    io_start[tid, arg0] = timestamp;
}

bufcache:::io-done
/io_start[tid, arg0] != 0/
{
    @io_us[arg1] = quantize((timestamp - io_start[tid, arg0]) / 1000);
    io_start[tid, arg0] = 0;
}
