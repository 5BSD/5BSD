/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

threadwait*:::mutex-start
/* @bsdinstruments-predicate */
{
    mutex_depth[pid, tid]++;
    mutex_start[pid, tid, mutex_depth[pid, tid]] = timestamp;
}

threadwait*:::mutex-done
/mutex_start[pid, tid, mutex_depth[pid, tid]] != 0/
{
    @mutex_us[(int)arg1] = quantize((timestamp - mutex_start[pid, tid, mutex_depth[pid, tid]]) / 1000);
    mutex_start[pid, tid, mutex_depth[pid, tid]] = 0;
    mutex_depth[pid, tid]--;
}

threadwait*:::condition-start
/* @bsdinstruments-predicate */
{
    condition_depth[pid, tid]++;
    condition_start[pid, tid, condition_depth[pid, tid]] = timestamp;
}

threadwait*:::condition-done
/condition_start[pid, tid, condition_depth[pid, tid]] != 0/
{
    @condition_us[(int)arg1] = quantize((timestamp - condition_start[pid, tid, condition_depth[pid, tid]]) / 1000);
    condition_start[pid, tid, condition_depth[pid, tid]] = 0;
    condition_depth[pid, tid]--;
}

threadwait*:::join-start
/* @bsdinstruments-predicate */
{
    join_depth[pid, tid]++;
    join_start[pid, tid, join_depth[pid, tid]] = timestamp;
}

threadwait*:::join-done
/join_start[pid, tid, join_depth[pid, tid]] != 0/
{
    @join_us[(int)arg1] = quantize((timestamp - join_start[pid, tid, join_depth[pid, tid]]) / 1000);
    join_start[pid, tid, join_depth[pid, tid]] = 0;
    join_depth[pid, tid]--;
}
