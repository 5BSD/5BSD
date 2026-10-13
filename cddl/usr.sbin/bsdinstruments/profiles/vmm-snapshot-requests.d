/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

vmm:::snapshot-start
/* @bsdinstruments-predicate */
{
    vmm_snapshot_depth[pid, tid]++;
    vmm_snapshot_start[pid, tid, vmm_snapshot_depth[pid, tid]] = timestamp;
}

vmm:::snapshot-done
/vmm_snapshot_start[pid, tid, vmm_snapshot_depth[pid, tid]] != 0/
{
    @vmm_snapshot_us[(int)arg1, (int)arg2, (int)arg3] = quantize((timestamp - vmm_snapshot_start[pid, tid, vmm_snapshot_depth[pid, tid]]) / 1000);
    vmm_snapshot_start[pid, tid, vmm_snapshot_depth[pid, tid]] = 0;
    vmm_snapshot_depth[pid, tid]--;
}
