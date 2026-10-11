/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

dhcplife*:::state
/* @bsdinstruments-predicate */
{
    @states[arg1] = count();
}

dhcplife*:::script-start
/* @bsdinstruments-predicate */
{
    script_depth[pid, tid]++;
    script_start[pid, tid, script_depth[pid, tid]] = timestamp;
}

dhcplife*:::script-done
/script_start[pid, tid, script_depth[pid, tid]] != 0/
{
    @script_us[(int)arg1] = quantize((timestamp - script_start[pid, tid, script_depth[pid, tid]]) / 1000);
    script_start[pid, tid, script_depth[pid, tid]] = 0;
    script_depth[pid, tid]--;
}
