/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

configquery*:::operation-start
/* @bsdinstruments-predicate */
{
    configquery_operation_depth[pid, tid]++;
    configquery_operation_time[pid, tid, configquery_operation_depth[pid, tid]] = timestamp;
}

configquery*:::operation-done
/configquery_operation_time[pid, tid, configquery_operation_depth[pid, tid]] != 0/
{
    @configquery_operation_us[arg0, (int)arg2] = quantize((timestamp - configquery_operation_time[pid, tid, configquery_operation_depth[pid, tid]]) / 1000);
    @configquery_operation_count[arg0, (int)arg2] = count();
    configquery_operation_time[pid, tid, configquery_operation_depth[pid, tid]] = 0;
    configquery_operation_depth[pid, tid]--;
}

cpusettool*:::operation-start
/* @bsdinstruments-predicate */
{
    cpusettool_operation_depth[pid, tid]++;
    cpusettool_operation_time[pid, tid, cpusettool_operation_depth[pid, tid]] = timestamp;
}

cpusettool*:::operation-done
/cpusettool_operation_time[pid, tid, cpusettool_operation_depth[pid, tid]] != 0/
{
    @cpusettool_operation_us[arg0, (int)arg4] = quantize((timestamp - cpusettool_operation_time[pid, tid, cpusettool_operation_depth[pid, tid]]) / 1000);
    @cpusettool_operation_count[arg0, (int)arg4] = count();
    cpusettool_operation_time[pid, tid, cpusettool_operation_depth[pid, tid]] = 0;
    cpusettool_operation_depth[pid, tid]--;
}
