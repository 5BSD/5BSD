/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

diskspace*:::operation-start
/* @bsdinstruments-predicate */
{
    diskspace_operation_depth[pid, tid]++;
    diskspace_operation_time[pid, tid, diskspace_operation_depth[pid, tid]] = timestamp;
}

diskspace*:::operation-done
/diskspace_operation_time[pid, tid, diskspace_operation_depth[pid, tid]] != 0/
{
    @diskspace_operation_us[arg0, (int)arg2] = quantize((timestamp - diskspace_operation_time[pid, tid, diskspace_operation_depth[pid, tid]]) / 1000);
    @diskspace_operation_count[arg0, (int)arg2] = count();
    diskspace_operation_time[pid, tid, diskspace_operation_depth[pid, tid]] = 0;
    diskspace_operation_depth[pid, tid]--;
}

sysctltool*:::operation-start
/* @bsdinstruments-predicate */
{
    sysctltool_operation_depth[pid, tid]++;
    sysctltool_operation_time[pid, tid, sysctltool_operation_depth[pid, tid]] = timestamp;
}

sysctltool*:::operation-done
/sysctltool_operation_time[pid, tid, sysctltool_operation_depth[pid, tid]] != 0/
{
    @sysctltool_operation_us[arg0, (int)arg3] = quantize((timestamp - sysctltool_operation_time[pid, tid, sysctltool_operation_depth[pid, tid]]) / 1000);
    @sysctltool_operation_count[arg0, (int)arg3] = count();
    sysctltool_operation_time[pid, tid, sysctltool_operation_depth[pid, tid]] = 0;
    sysctltool_operation_depth[pid, tid]--;
}
