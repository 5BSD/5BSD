/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

logrotate*:::rotate-start
/* @bsdinstruments-predicate */
{
    rotate_depth[pid, tid]++;
    rotate_start[pid, tid, rotate_depth[pid, tid]] = timestamp;
}

logrotate*:::rotate-done
/rotate_start[pid, tid, rotate_depth[pid, tid]] != 0/
{
    @rotate_us[(int)arg1] = quantize((timestamp - rotate_start[pid, tid, rotate_depth[pid, tid]]) / 1000);
    rotate_start[pid, tid, rotate_depth[pid, tid]] = 0;
    rotate_depth[pid, tid]--;
}

logrotate*:::compress-start
/* @bsdinstruments-predicate */
{
    compress_depth[pid, tid]++;
    compress_start[pid, tid, compress_depth[pid, tid]] = timestamp;
}

logrotate*:::compress-done
/compress_start[pid, tid, compress_depth[pid, tid]] != 0/
{
    @compress_us[(int)arg3] = quantize((timestamp - compress_start[pid, tid, compress_depth[pid, tid]]) / 1000);
    compress_start[pid, tid, compress_depth[pid, tid]] = 0;
    compress_depth[pid, tid]--;
}

logrotate*:::notify
/* @bsdinstruments-predicate */
{
    @notifications[arg1, (int)arg2] = count();
}
