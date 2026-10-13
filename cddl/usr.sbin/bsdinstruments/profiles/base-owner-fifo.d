/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

fileowner*:::operation-start
/* @bsdinstruments-predicate */
{
    fileowner_operation_depth[pid, tid]++;
    fileowner_operation_time[pid, tid, fileowner_operation_depth[pid, tid]] = timestamp;
}

fileowner*:::operation-done
/fileowner_operation_time[pid, tid, fileowner_operation_depth[pid, tid]] != 0/
{
    @fileowner_operation_us[arg0, (int)arg2] = quantize((timestamp - fileowner_operation_time[pid, tid, fileowner_operation_depth[pid, tid]]) / 1000);
    @fileowner_operation_count[arg0, (int)arg2] = count();
    fileowner_operation_time[pid, tid, fileowner_operation_depth[pid, tid]] = 0;
    fileowner_operation_depth[pid, tid]--;
}

fifocreate*:::operation-start
/* @bsdinstruments-predicate */
{
    fifocreate_operation_depth[pid, tid]++;
    fifocreate_operation_time[pid, tid, fifocreate_operation_depth[pid, tid]] = timestamp;
}

fifocreate*:::operation-done
/fifocreate_operation_time[pid, tid, fifocreate_operation_depth[pid, tid]] != 0/
{
    @fifocreate_operation_us[arg0, (int)arg2] = quantize((timestamp - fifocreate_operation_time[pid, tid, fifocreate_operation_depth[pid, tid]]) / 1000);
    @fifocreate_operation_count[arg0, (int)arg2] = count();
    fifocreate_operation_time[pid, tid, fifocreate_operation_depth[pid, tid]] = 0;
    fifocreate_operation_depth[pid, tid]--;
}
