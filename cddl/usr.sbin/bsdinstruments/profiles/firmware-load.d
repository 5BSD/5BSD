/*
 * Firmware registry hits, module-load errno and binary-load success (1)/failure (0).
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

firmware:::lookup
/* @bsdinstruments-predicate */
{
    @lookup[stringof(arg0), arg1] = count();
}

firmware:::module-start
/* @bsdinstruments-predicate */
{
    module_start[tid, stringof(arg0)] = timestamp;
}

firmware:::module-done
/module_start[tid, stringof(arg0)] != 0/
{
    @module_us[stringof(arg0), arg1] = quantize((timestamp - module_start[tid, stringof(arg0)]) / 1000);
    module_start[tid, stringof(arg0)] = 0;
}

firmware:::binary-start
/* @bsdinstruments-predicate */
{
    binary_start[tid, stringof(arg0)] = timestamp;
}

firmware:::binary-done
/binary_start[tid, stringof(arg0)] != 0/
{
    @binary_us[stringof(arg0), arg1] = quantize((timestamp - binary_start[tid, stringof(arg0)]) / 1000);
    binary_start[tid, stringof(arg0)] = 0;
}
