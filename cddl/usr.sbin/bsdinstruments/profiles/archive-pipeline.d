/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

archiveio*:::operation-start
/* @bsdinstruments-predicate */
{
    archive_depth[pid, tid]++;
    archive_start[pid, tid, archive_depth[pid, tid]] = timestamp;
}

archiveio*:::operation-done
/archive_start[pid, tid, archive_depth[pid, tid]] != 0/
{
    @archive_us[(int)arg1] = quantize((timestamp - archive_start[pid, tid, archive_depth[pid, tid]]) / 1000);
    archive_start[pid, tid, archive_depth[pid, tid]] = 0;
    archive_depth[pid, tid]--;
}

archiveio*:::operation-done
/* @bsdinstruments-predicate */
{
    @operation_results[arg1, (int64_t)arg2] = count();
}
