/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

nfsserver:::compound-start
/* @bsdinstruments-predicate */
{
    compound_depth[pid, tid]++;
    compound_start[pid, tid, compound_depth[pid, tid]] = timestamp;
}

nfsserver:::compound-done
/compound_start[pid, tid, compound_depth[pid, tid]] != 0/
{
    @compound_us[(int)arg2] = quantize((timestamp - compound_start[pid, tid, compound_depth[pid, tid]]) / 1000);
    compound_start[pid, tid, compound_depth[pid, tid]] = 0;
    compound_depth[pid, tid]--;
}

nfsserver:::operation-start
/* @bsdinstruments-predicate */
{
    operation_depth[pid, tid]++;
    operation_start[pid, tid, operation_depth[pid, tid]] = timestamp;
}

nfsserver:::operation-done
/operation_start[pid, tid, operation_depth[pid, tid]] != 0/
{
    @operation_us[(int)arg2] = quantize((timestamp - operation_start[pid, tid, operation_depth[pid, tid]]) / 1000);
    operation_start[pid, tid, operation_depth[pid, tid]] = 0;
    operation_depth[pid, tid]--;
}

nfsserver:::client-start
/* @bsdinstruments-predicate */
{
    client_depth[pid, tid]++;
    client_start[pid, tid, client_depth[pid, tid]] = timestamp;
}

nfsserver:::client-done
/client_start[pid, tid, client_depth[pid, tid]] != 0/
{
    @client_us[(int)arg1] = quantize((timestamp - client_start[pid, tid, client_depth[pid, tid]]) / 1000);
    client_start[pid, tid, client_depth[pid, tid]] = 0;
    client_depth[pid, tid]--;
}

nfsserver:::session-replay
/* @bsdinstruments-predicate */
{
    @session_replays[arg0] = count();
}
