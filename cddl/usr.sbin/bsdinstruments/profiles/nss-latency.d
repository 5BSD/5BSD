/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

nameres*:::dispatch-start
/* @bsdinstruments-predicate */
{
    dispatch_depth[pid, tid]++;
    dispatch_start[pid, tid, dispatch_depth[pid, tid]] = timestamp;
}

nameres*:::dispatch-done
/dispatch_start[pid, tid, dispatch_depth[pid, tid]] != 0/
{
    @dispatch_us[(int)arg1] = quantize((timestamp - dispatch_start[pid, tid, dispatch_depth[pid, tid]]) / 1000);
    dispatch_start[pid, tid, dispatch_depth[pid, tid]] = 0;
    dispatch_depth[pid, tid]--;
}

nameres*:::backend-start
/* @bsdinstruments-predicate */
{
    backend_depth[pid, tid]++;
    backend_start[pid, tid, backend_depth[pid, tid]] = timestamp;
}

nameres*:::backend-done
/backend_start[pid, tid, backend_depth[pid, tid]] != 0/
{
    @backend_us[(int)arg2] = quantize((timestamp - backend_start[pid, tid, backend_depth[pid, tid]]) / 1000);
    backend_start[pid, tid, backend_depth[pid, tid]] = 0;
    backend_depth[pid, tid]--;
}
