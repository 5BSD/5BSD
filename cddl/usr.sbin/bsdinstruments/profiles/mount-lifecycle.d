/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

mountop*:::operation-start
/* @bsdinstruments-predicate */
{
    mountop_depth[pid, tid]++;
    mountop_start[pid, tid, mountop_depth[pid, tid]] = timestamp;
}

mountop*:::operation-done
/mountop_start[pid, tid, mountop_depth[pid, tid]] != 0/
{
    @mountop_us[(int)arg1] = quantize((timestamp - mountop_start[pid, tid, mountop_depth[pid, tid]]) / 1000);
    mountop_start[pid, tid, mountop_depth[pid, tid]] = 0;
    mountop_depth[pid, tid]--;
}

umountop*:::operation-start
/* @bsdinstruments-predicate */
{
    umountop_depth[pid, tid]++;
    umountop_start[pid, tid, umountop_depth[pid, tid]] = timestamp;
}

umountop*:::operation-done
/umountop_start[pid, tid, umountop_depth[pid, tid]] != 0/
{
    @umountop_us[(int)arg1] = quantize((timestamp - umountop_start[pid, tid, umountop_depth[pid, tid]]) / 1000);
    umountop_start[pid, tid, umountop_depth[pid, tid]] = 0;
    umountop_depth[pid, tid]--;
}

exports*:::reload-start
/* @bsdinstruments-predicate */
{
    exports_depth[pid, tid]++;
    exports_start[pid, tid, exports_depth[pid, tid]] = timestamp;
}

exports*:::reload-done
/exports_start[pid, tid, exports_depth[pid, tid]] != 0/
{
    @exports_us[(int)arg0] = quantize((timestamp - exports_start[pid, tid, exports_depth[pid, tid]]) / 1000);
    exports_start[pid, tid, exports_depth[pid, tid]] = 0;
    exports_depth[pid, tid]--;
}
