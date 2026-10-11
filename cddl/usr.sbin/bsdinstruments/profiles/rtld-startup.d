/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

rtldtrace*:::load-start
/* @bsdinstruments-predicate */
{
    load_depth[pid, tid]++;
    load_start[pid, tid, load_depth[pid, tid]] = timestamp;
}

rtldtrace*:::load-done
/load_start[pid, tid, load_depth[pid, tid]] != 0/
{
    @load_us[0] = quantize((timestamp - load_start[pid, tid, load_depth[pid, tid]]) / 1000);
    load_start[pid, tid, load_depth[pid, tid]] = 0;
    load_depth[pid, tid]--;
}

rtldtrace*:::relocate-start
/* @bsdinstruments-predicate */
{
    relocate_depth[pid, tid]++;
    relocate_start[pid, tid, relocate_depth[pid, tid]] = timestamp;
}

rtldtrace*:::relocate-done
/relocate_start[pid, tid, relocate_depth[pid, tid]] != 0/
{
    @relocate_us[(int)arg1] = quantize((timestamp - relocate_start[pid, tid, relocate_depth[pid, tid]]) / 1000);
    relocate_start[pid, tid, relocate_depth[pid, tid]] = 0;
    relocate_depth[pid, tid]--;
}

rtldtrace*:::init-start
/* @bsdinstruments-predicate */
{
    init_depth[pid, tid]++;
    init_start[pid, tid, init_depth[pid, tid]] = timestamp;
}

rtldtrace*:::init-done
/init_start[pid, tid, init_depth[pid, tid]] != 0/
{
    @init_us[0] = quantize((timestamp - init_start[pid, tid, init_depth[pid, tid]]) / 1000);
    init_start[pid, tid, init_depth[pid, tid]] = 0;
    init_depth[pid, tid]--;
}
