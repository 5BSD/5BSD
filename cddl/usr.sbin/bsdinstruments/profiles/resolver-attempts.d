/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

nameres*:::query-start
/* @bsdinstruments-predicate */
{
    query_depth[pid, tid]++;
    query_start[pid, tid, query_depth[pid, tid]] = timestamp;
}

nameres*:::query-done
/query_start[pid, tid, query_depth[pid, tid]] != 0/
{
    @query_us[(int)arg2] = quantize((timestamp - query_start[pid, tid, query_depth[pid, tid]]) / 1000);
    query_start[pid, tid, query_depth[pid, tid]] = 0;
    query_depth[pid, tid]--;
}

nameres*:::server-start
/* @bsdinstruments-predicate */
{
    server_depth[pid, tid]++;
    server_start[pid, tid, server_depth[pid, tid]] = timestamp;
}

nameres*:::server-done
/server_start[pid, tid, server_depth[pid, tid]] != 0/
{
    @server_us[(int)arg3] = quantize((timestamp - server_start[pid, tid, server_depth[pid, tid]]) / 1000);
    server_start[pid, tid, server_depth[pid, tid]] = 0;
    server_depth[pid, tid]--;
}
