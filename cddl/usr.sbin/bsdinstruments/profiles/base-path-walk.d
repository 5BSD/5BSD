/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

pathcheck*:::operation-start
/* @bsdinstruments-predicate */
{
    pathcheck_operation_depth[pid, tid]++;
    pathcheck_operation_time[pid, tid, pathcheck_operation_depth[pid, tid]] = timestamp;
}

pathcheck*:::operation-done
/pathcheck_operation_time[pid, tid, pathcheck_operation_depth[pid, tid]] != 0/
{
    @pathcheck_operation_us[arg0, (int)arg2] = quantize((timestamp - pathcheck_operation_time[pid, tid, pathcheck_operation_depth[pid, tid]]) / 1000);
    @pathcheck_operation_count[arg0, (int)arg2] = count();
    pathcheck_operation_time[pid, tid, pathcheck_operation_depth[pid, tid]] = 0;
    pathcheck_operation_depth[pid, tid]--;
}

diskwalk*:::operation-start
/* @bsdinstruments-predicate */
{
    diskwalk_operation_depth[pid, tid]++;
    diskwalk_operation_time[pid, tid, diskwalk_operation_depth[pid, tid]] = timestamp;
}

diskwalk*:::operation-done
/diskwalk_operation_time[pid, tid, diskwalk_operation_depth[pid, tid]] != 0/
{
    @diskwalk_operation_us[arg0, (int)arg2] = quantize((timestamp - diskwalk_operation_time[pid, tid, diskwalk_operation_depth[pid, tid]]) / 1000);
    @diskwalk_operation_count[arg0, (int)arg2] = count();
    diskwalk_operation_time[pid, tid, diskwalk_operation_depth[pid, tid]] = 0;
    diskwalk_operation_depth[pid, tid]--;
}
