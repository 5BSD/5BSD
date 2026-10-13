/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

bhyve*:::checkpoint-phase-start
/* @bsdinstruments-predicate */
{
    checkpoint_depth[pid, tid]++;
    checkpoint_start[pid, tid, checkpoint_depth[pid, tid]] = timestamp;
}

bhyve*:::checkpoint-phase-done
/checkpoint_start[pid, tid, checkpoint_depth[pid, tid]] != 0/
{
    @checkpoint_us[copyinstr(arg0), copyinstr(arg1), (int)arg2, (int)arg3] = quantize((timestamp - checkpoint_start[pid, tid, checkpoint_depth[pid, tid]]) / 1000);
    checkpoint_start[pid, tid, checkpoint_depth[pid, tid]] = 0;
    checkpoint_depth[pid, tid]--;
}

bhyve*:::checkpoint-publish
/* @bsdinstruments-predicate */
{
    @published[(int)arg0, (int)arg1] = count();
}

bhyve*:::checkpoint-result
/* @bsdinstruments-predicate */
{
    @result[(int)arg0, (int)arg1, (int)arg2] = count();
}

bhyve*:::checkpoint-begin
/* @bsdinstruments-predicate */
{
    checkpoint_total_depth[pid, tid]++;
    checkpoint_total_start[pid, tid, checkpoint_total_depth[pid, tid]] = timestamp;
}

bhyve*:::checkpoint-result
/checkpoint_total_start[pid, tid, checkpoint_total_depth[pid, tid]] != 0/
{
    @checkpoint_total_us[(int)arg1, (int)arg2] = quantize((timestamp - checkpoint_total_start[pid, tid, checkpoint_total_depth[pid, tid]]) / 1000);
    checkpoint_total_start[pid, tid, checkpoint_total_depth[pid, tid]] = 0;
    checkpoint_total_depth[pid, tid]--;
}

bhyve*:::restore-begin
/* @bsdinstruments-predicate */
{
    restore_total_depth[pid, tid]++;
    restore_total_start[pid, tid, restore_total_depth[pid, tid]] = timestamp;
}

bhyve*:::restore-result
/restore_total_start[pid, tid, restore_total_depth[pid, tid]] != 0/
{
    @restore_total_us[(int)arg0] = quantize((timestamp - restore_total_start[pid, tid, restore_total_depth[pid, tid]]) / 1000);
    restore_total_start[pid, tid, restore_total_depth[pid, tid]] = 0;
    restore_total_depth[pid, tid]--;
}
