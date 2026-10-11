/*
 * FFS allocation retries, softdep worklist/journal duration and cleanup pressure.
 *
 * Requires the corresponding 5BSD SDT probes; see tools/test/system-tracing/
 * KERNEL-PROBES-NEXT for argument contracts and coverage limits.
 * Histogram durations are microseconds. Pointer values are identities only.
 * Aggregations print on exit. Start an interval before reproducing the issue.
 */

ffs:::alloc-retry
/* @bsdinstruments-predicate */
{
    @allocation_retries[arg1] = count();
}

ffs:::slowdown
/* @bsdinstruments-predicate */
{
    @cleanup_pressure[arg0, arg1] = count();
}

ffs:::worklist-start
/* @bsdinstruments-predicate */
{
    worklist_start[tid, arg0] = timestamp;
}

ffs:::worklist-done
/worklist_start[tid, arg0] != 0/
{
    @worklist_us[arg0] = quantize((timestamp - worklist_start[tid, arg0]) / 1000);
    worklist_start[tid, arg0] = 0;
}

ffs:::worklist-done
/* @bsdinstruments-predicate */
{
    @remaining_work[arg0] = quantize(arg2);
}

ffs:::journal-start
/* @bsdinstruments-predicate */
{
    journal_start[tid, arg0] = timestamp;
}

ffs:::journal-done
/journal_start[tid, arg0] != 0/
{
    @journal_us[arg0] = quantize((timestamp - journal_start[tid, arg0]) / 1000);
    journal_start[tid, arg0] = 0;
}
