/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

iommu:::map-start
/* @bsdinstruments-predicate */
{
    map_depth[pid, tid]++;
    map_start[pid, tid, map_depth[pid, tid]] = timestamp;
}

iommu:::map-done
/map_start[pid, tid, map_depth[pid, tid]] != 0/
{
    @map_us[(int)arg1] = quantize((timestamp - map_start[pid, tid, map_depth[pid, tid]]) / 1000);
    map_start[pid, tid, map_depth[pid, tid]] = 0;
    map_depth[pid, tid]--;
}

iommu:::unload-start
/* @bsdinstruments-predicate */
{
    unload_depth[pid, tid]++;
    unload_start[pid, tid, unload_depth[pid, tid]] = timestamp;
}

iommu:::unload-done
/unload_start[pid, tid, unload_depth[pid, tid]] != 0/
{
    @unload_us[0] = quantize((timestamp - unload_start[pid, tid, unload_depth[pid, tid]]) / 1000);
    unload_start[pid, tid, unload_depth[pid, tid]] = 0;
    unload_depth[pid, tid]--;
}

iommu:::load-complete
/* @bsdinstruments-predicate */
{
    @load_results[(int)arg2] = count();
}
