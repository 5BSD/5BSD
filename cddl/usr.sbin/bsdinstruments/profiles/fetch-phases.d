/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

fetchio*:::request-start
/* @bsdinstruments-predicate */
{
    request_depth[pid, tid]++;
    request_start[pid, tid, request_depth[pid, tid]] = timestamp;
}

fetchio*:::request-done
/request_start[pid, tid, request_depth[pid, tid]] != 0/
{
    @request_us[(int)arg2] = quantize((timestamp - request_start[pid, tid, request_depth[pid, tid]]) / 1000);
    request_start[pid, tid, request_depth[pid, tid]] = 0;
    request_depth[pid, tid]--;
}

fetchio*:::connect-start
/* @bsdinstruments-predicate */
{
    connect_depth[pid, tid]++;
    connect_start[pid, tid, connect_depth[pid, tid]] = timestamp;
}

fetchio*:::connect-done
/connect_start[pid, tid, connect_depth[pid, tid]] != 0/
{
    @connect_us[(int)arg1] = quantize((timestamp - connect_start[pid, tid, connect_depth[pid, tid]]) / 1000);
    connect_start[pid, tid, connect_depth[pid, tid]] = 0;
    connect_depth[pid, tid]--;
}

fetchio*:::tls-start
/* @bsdinstruments-predicate */
{
    tls_depth[pid, tid]++;
    tls_start[pid, tid, tls_depth[pid, tid]] = timestamp;
}

fetchio*:::tls-done
/tls_start[pid, tid, tls_depth[pid, tid]] != 0/
{
    @tls_us[(int)arg1] = quantize((timestamp - tls_start[pid, tid, tls_depth[pid, tid]]) / 1000);
    tls_start[pid, tid, tls_depth[pid, tid]] = 0;
    tls_depth[pid, tid]--;
}
