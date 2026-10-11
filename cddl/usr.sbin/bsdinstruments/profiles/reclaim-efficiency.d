/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

swap:::io-start
/* @bsdinstruments-predicate */
{
    swap_io_start[arg0] = timestamp;
}

swap:::io-done
/swap_io_start[arg0] != 0/
{
    @swap_io_us[(int)arg3] = quantize((timestamp - swap_io_start[arg0]) / 1000);
    swap_io_start[arg0] = 0;
}

vm:::inactive-start
/* @bsdinstruments-predicate */
{
    inactive_depth[pid, tid]++;
    inactive_start[pid, tid, inactive_depth[pid, tid]] = timestamp;
}

vm:::inactive-done
/inactive_start[pid, tid, inactive_depth[pid, tid]] != 0/
{
    @inactive_us[0] = quantize((timestamp - inactive_start[pid, tid, inactive_depth[pid, tid]]) / 1000);
    inactive_start[pid, tid, inactive_depth[pid, tid]] = 0;
    inactive_depth[pid, tid]--;
}

vm:::inactive-done
/* @bsdinstruments-predicate */
{
    @shortages[(int)arg1, (int)arg2] = count();
}
