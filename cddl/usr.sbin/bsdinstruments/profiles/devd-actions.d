/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

devd*:::event-start
/* @bsdinstruments-predicate */
{
    event_depth[pid, tid]++;
    event_start[pid, tid, event_depth[pid, tid]] = timestamp;
}

devd*:::event-done
/event_start[pid, tid, event_depth[pid, tid]] != 0/
{
    @event_us[0] = quantize((timestamp - event_start[pid, tid, event_depth[pid, tid]]) / 1000);
    event_start[pid, tid, event_depth[pid, tid]] = 0;
    event_depth[pid, tid]--;
}

devd*:::action-start
/* @bsdinstruments-predicate */
{
    action_depth[pid, tid]++;
    action_start[pid, tid, action_depth[pid, tid]] = timestamp;
}

devd*:::action-done
/action_start[pid, tid, action_depth[pid, tid]] != 0/
{
    @action_us[(int)arg1] = quantize((timestamp - action_start[pid, tid, action_depth[pid, tid]]) / 1000);
    action_start[pid, tid, action_depth[pid, tid]] = 0;
    action_depth[pid, tid]--;
}

devd*:::rule
/* @bsdinstruments-predicate */
{
    @rules[arg1] = count();
}
