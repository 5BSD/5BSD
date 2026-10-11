/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

ffscheck*:::phase-start
/* @bsdinstruments-predicate */
{
    ffs_depth[pid, tid]++;
    ffs_start[pid, tid, ffs_depth[pid, tid]] = timestamp;
}

ffscheck*:::phase-done
/ffs_start[pid, tid, ffs_depth[pid, tid]] != 0/
{
    @ffs_us[(int)arg0] = quantize((timestamp - ffs_start[pid, tid, ffs_depth[pid, tid]]) / 1000);
    ffs_start[pid, tid, ffs_depth[pid, tid]] = 0;
    ffs_depth[pid, tid]--;
}

fatcheck*:::check-start
/* @bsdinstruments-predicate */
{
    fat_depth[pid, tid]++;
    fat_start[pid, tid, fat_depth[pid, tid]] = timestamp;
}

fatcheck*:::check-done
/fat_start[pid, tid, fat_depth[pid, tid]] != 0/
{
    @fat_us[(int)arg1] = quantize((timestamp - fat_start[pid, tid, fat_depth[pid, tid]]) / 1000);
    fat_start[pid, tid, fat_depth[pid, tid]] = 0;
    fat_depth[pid, tid]--;
}
