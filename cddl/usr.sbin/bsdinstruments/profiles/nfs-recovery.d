/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

nfsclient:::recover-start
/* @bsdinstruments-predicate */
{
    recover_depth[pid, tid]++;
    recover_start[pid, tid, recover_depth[pid, tid]] = timestamp;
}

nfsclient:::recover-done
/recover_start[pid, tid, recover_depth[pid, tid]] != 0/
{
    @recover_us[(int)arg1] = quantize((timestamp - recover_start[pid, tid, recover_depth[pid, tid]]) / 1000);
    recover_start[pid, tid, recover_depth[pid, tid]] = 0;
    recover_depth[pid, tid]--;
}

nfsclient:::renew-start
/* @bsdinstruments-predicate */
{
    renew_depth[pid, tid]++;
    renew_start[pid, tid, renew_depth[pid, tid]] = timestamp;
}

nfsclient:::renew-done
/renew_start[pid, tid, renew_depth[pid, tid]] != 0/
{
    @renew_us[(int)arg1] = quantize((timestamp - renew_start[pid, tid, renew_depth[pid, tid]]) / 1000);
    renew_start[pid, tid, renew_depth[pid, tid]] = 0;
    renew_depth[pid, tid]--;
}

nfsclient:::open-start
/* @bsdinstruments-predicate */
{
    open_depth[pid, tid]++;
    open_start[pid, tid, open_depth[pid, tid]] = timestamp;
}

nfsclient:::open-done
/open_start[pid, tid, open_depth[pid, tid]] != 0/
{
    @open_us[(int)arg1] = quantize((timestamp - open_start[pid, tid, open_depth[pid, tid]]) / 1000);
    open_start[pid, tid, open_depth[pid, tid]] = 0;
    open_depth[pid, tid]--;
}

nfsclient:::setclient-result
/* @bsdinstruments-predicate */
{
    @setclient_results[(int)arg1, arg2] = count();
}
