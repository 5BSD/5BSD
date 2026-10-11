/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

fat:::alloc-start
/* @bsdinstruments-predicate */
{
    alloc_depth[pid, tid]++;
    alloc_start[pid, tid, alloc_depth[pid, tid]] = timestamp;
}

fat:::alloc-done
/alloc_start[pid, tid, alloc_depth[pid, tid]] != 0/
{
    @alloc_us[(int)arg3] = quantize((timestamp - alloc_start[pid, tid, alloc_depth[pid, tid]]) / 1000);
    alloc_start[pid, tid, alloc_depth[pid, tid]] = 0;
    alloc_depth[pid, tid]--;
}

fat:::entry-start
/* @bsdinstruments-predicate */
{
    entry_depth[pid, tid]++;
    entry_start[pid, tid, entry_depth[pid, tid]] = timestamp;
}

fat:::entry-done
/entry_start[pid, tid, entry_depth[pid, tid]] != 0/
{
    @entry_us[(int)arg2] = quantize((timestamp - entry_start[pid, tid, entry_depth[pid, tid]]) / 1000);
    entry_start[pid, tid, entry_depth[pid, tid]] = 0;
    entry_depth[pid, tid]--;
}

fat:::remount-start
/* @bsdinstruments-predicate */
{
    remount_depth[pid, tid]++;
    remount_start[pid, tid, remount_depth[pid, tid]] = timestamp;
}

fat:::remount-done
/remount_start[pid, tid, remount_depth[pid, tid]] != 0/
{
    @remount_us[(int)arg1] = quantize((timestamp - remount_start[pid, tid, remount_depth[pid, tid]]) / 1000);
    remount_start[pid, tid, remount_depth[pid, tid]] = 0;
    remount_depth[pid, tid]--;
}

fat:::integrity
/* @bsdinstruments-predicate */
{
    @integrity[arg0] = count();
}
