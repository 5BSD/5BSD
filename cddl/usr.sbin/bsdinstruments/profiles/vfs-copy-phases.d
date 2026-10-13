/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

vfs:::copy-range-start
/* @bsdinstruments-predicate */
{
    vfs_copy_range_depth[pid, tid]++;
    vfs_copy_range_time[pid, tid, vfs_copy_range_depth[pid, tid]] = timestamp;
}

vfs:::copy-range-done
/vfs_copy_range_time[pid, tid, vfs_copy_range_depth[pid, tid]] != 0/
{
    @vfs_copy_range_us[(int)arg3] = quantize((timestamp - vfs_copy_range_time[pid, tid, vfs_copy_range_depth[pid, tid]]) / 1000);
    @vfs_copy_range_count[(int)arg3] = count();
    vfs_copy_range_time[pid, tid, vfs_copy_range_depth[pid, tid]] = 0;
    vfs_copy_range_depth[pid, tid]--;
}
