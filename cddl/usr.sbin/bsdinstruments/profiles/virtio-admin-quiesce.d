/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

virtio*:::admin-quiesce-start
/* @bsdinstruments-predicate */
{
    admin_quiesce_depth[pid, tid]++;
    admin_quiesce_start[pid, tid, admin_quiesce_depth[pid, tid]] = timestamp;
}

virtio*:::admin-quiesce-done
/admin_quiesce_start[pid, tid, admin_quiesce_depth[pid, tid]] != 0/
{
    @admin_quiesce_us[arg1] = quantize((timestamp - admin_quiesce_start[pid, tid, admin_quiesce_depth[pid, tid]]) / 1000);
    admin_quiesce_start[pid, tid, admin_quiesce_depth[pid, tid]] = 0;
    admin_quiesce_depth[pid, tid]--;
}
