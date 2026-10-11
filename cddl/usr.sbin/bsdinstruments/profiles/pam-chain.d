/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

pamchain*:::chain-start
/* @bsdinstruments-predicate */
{
    chain_depth[pid, tid]++;
    chain_start[pid, tid, chain_depth[pid, tid]] = timestamp;
}

pamchain*:::chain-done
/chain_start[pid, tid, chain_depth[pid, tid]] != 0/
{
    @chain_us[(int)arg1] = quantize((timestamp - chain_start[pid, tid, chain_depth[pid, tid]]) / 1000);
    chain_start[pid, tid, chain_depth[pid, tid]] = 0;
    chain_depth[pid, tid]--;
}

pamchain*:::module-start
/* @bsdinstruments-predicate */
{
    module_depth[pid, tid]++;
    module_start[pid, tid, module_depth[pid, tid]] = timestamp;
}

pamchain*:::module-done
/module_start[pid, tid, module_depth[pid, tid]] != 0/
{
    @module_us[(int)arg2] = quantize((timestamp - module_start[pid, tid, module_depth[pid, tid]]) / 1000);
    module_start[pid, tid, module_depth[pid, tid]] = 0;
    module_depth[pid, tid]--;
}
