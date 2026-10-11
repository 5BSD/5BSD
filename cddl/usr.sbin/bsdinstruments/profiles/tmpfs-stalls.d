/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

tmpfs:::vnode-start
/* @bsdinstruments-predicate */
{
    vnode_depth[pid, tid]++;
    vnode_start[pid, tid, vnode_depth[pid, tid]] = timestamp;
}

tmpfs:::vnode-done
/vnode_start[pid, tid, vnode_depth[pid, tid]] != 0/
{
    @vnode_us[(int)arg2] = quantize((timestamp - vnode_start[pid, tid, vnode_depth[pid, tid]]) / 1000);
    vnode_start[pid, tid, vnode_depth[pid, tid]] = 0;
    vnode_depth[pid, tid]--;
}

tmpfs:::reclaim-wait
/* @bsdinstruments-predicate */
{
    reclaim_depth[pid, tid]++;
    reclaim_start[pid, tid, reclaim_depth[pid, tid]] = timestamp;
}

tmpfs:::reclaim-resume
/reclaim_start[pid, tid, reclaim_depth[pid, tid]] != 0/
{
    @reclaim_us[0] = quantize((timestamp - reclaim_start[pid, tid, reclaim_depth[pid, tid]]) / 1000);
    reclaim_start[pid, tid, reclaim_depth[pid, tid]] = 0;
    reclaim_depth[pid, tid]--;
}

tmpfs:::resize-start
/* @bsdinstruments-predicate */
{
    resize_depth[pid, tid]++;
    resize_start[pid, tid, resize_depth[pid, tid]] = timestamp;
}

tmpfs:::resize-done
/resize_start[pid, tid, resize_depth[pid, tid]] != 0/
{
    @resize_us[(int)arg1] = quantize((timestamp - resize_start[pid, tid, resize_depth[pid, tid]]) / 1000);
    resize_start[pid, tid, resize_depth[pid, tid]] = 0;
    resize_depth[pid, tid]--;
}

tmpfs:::node-start
/* @bsdinstruments-predicate */
{
    node_depth[pid, tid]++;
    node_start[pid, tid, node_depth[pid, tid]] = timestamp;
}

tmpfs:::node-done
/node_start[pid, tid, node_depth[pid, tid]] != 0/
{
    @node_us[(int)arg1] = quantize((timestamp - node_start[pid, tid, node_depth[pid, tid]]) / 1000);
    node_start[pid, tid, node_depth[pid, tid]] = 0;
    node_depth[pid, tid]--;
}

tmpfs:::rename-start
/* @bsdinstruments-predicate */
{
    rename_depth[pid, tid]++;
    rename_start[pid, tid, rename_depth[pid, tid]] = timestamp;
}

tmpfs:::rename-done
/rename_start[pid, tid, rename_depth[pid, tid]] != 0/
{
    @rename_us[(int)arg2] = quantize((timestamp - rename_start[pid, tid, rename_depth[pid, tid]]) / 1000);
    rename_start[pid, tid, rename_depth[pid, tid]] = 0;
    rename_depth[pid, tid]--;
}

tmpfs:::capacity
/* @bsdinstruments-predicate */
{
    @capacity_refusals[arg1] = count();
}
