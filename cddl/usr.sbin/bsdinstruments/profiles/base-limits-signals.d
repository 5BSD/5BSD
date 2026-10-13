/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

limittool*:::operation-start
/* @bsdinstruments-predicate */
{
    limittool_operation_depth[pid, tid]++;
    limittool_operation_time[pid, tid, limittool_operation_depth[pid, tid]] = timestamp;
}

limittool*:::operation-done
/limittool_operation_time[pid, tid, limittool_operation_depth[pid, tid]] != 0/
{
    @limittool_operation_us[arg0, (int)arg2] = quantize((timestamp - limittool_operation_time[pid, tid, limittool_operation_depth[pid, tid]]) / 1000);
    @limittool_operation_count[arg0, (int)arg2] = count();
    limittool_operation_time[pid, tid, limittool_operation_depth[pid, tid]] = 0;
    limittool_operation_depth[pid, tid]--;
}

signalall*:::operation-start
/* @bsdinstruments-predicate */
{
    signalall_operation_depth[pid, tid]++;
    signalall_operation_time[pid, tid, signalall_operation_depth[pid, tid]] = timestamp;
}

signalall*:::operation-done
/signalall_operation_time[pid, tid, signalall_operation_depth[pid, tid]] != 0/
{
    @signalall_operation_us[arg0, (int)arg3] = quantize((timestamp - signalall_operation_time[pid, tid, signalall_operation_depth[pid, tid]]) / 1000);
    @signalall_operation_count[arg0, (int)arg3] = count();
    signalall_operation_time[pid, tid, signalall_operation_depth[pid, tid]] = 0;
    signalall_operation_depth[pid, tid]--;
}
