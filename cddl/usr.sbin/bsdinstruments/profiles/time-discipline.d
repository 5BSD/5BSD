/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

timediscipline*:::select-start
/* @bsdinstruments-predicate */
{
    select_depth[pid, tid]++;
    select_start[pid, tid, select_depth[pid, tid]] = timestamp;
}

timediscipline*:::select-done
/select_start[pid, tid, select_depth[pid, tid]] != 0/
{
    @select_us[(int)arg1] = quantize((timestamp - select_start[pid, tid, select_depth[pid, tid]]) / 1000);
    select_start[pid, tid, select_depth[pid, tid]] = 0;
    select_depth[pid, tid]--;
}

timediscipline*:::adjust-start
/* @bsdinstruments-predicate */
{
    adjust_depth[pid, tid]++;
    adjust_start[pid, tid, adjust_depth[pid, tid]] = timestamp;
}

timediscipline*:::adjust-done
/adjust_start[pid, tid, adjust_depth[pid, tid]] != 0/
{
    @adjust_us[(int)arg1] = quantize((timestamp - adjust_start[pid, tid, adjust_depth[pid, tid]]) / 1000);
    adjust_start[pid, tid, adjust_depth[pid, tid]] = 0;
    adjust_depth[pid, tid]--;
}
