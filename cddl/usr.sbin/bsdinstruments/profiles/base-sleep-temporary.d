/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

sleepwait*:::operation-start
/* @bsdinstruments-predicate */
{
    sleepwait_operation_depth[pid, tid]++;
    sleepwait_operation_time[pid, tid, sleepwait_operation_depth[pid, tid]] = timestamp;
}

sleepwait*:::operation-done
/sleepwait_operation_time[pid, tid, sleepwait_operation_depth[pid, tid]] != 0/
{
    @sleepwait_operation_us[arg0, (int)arg2] = quantize((timestamp - sleepwait_operation_time[pid, tid, sleepwait_operation_depth[pid, tid]]) / 1000);
    @sleepwait_operation_count[arg0, (int)arg2] = count();
    sleepwait_operation_time[pid, tid, sleepwait_operation_depth[pid, tid]] = 0;
    sleepwait_operation_depth[pid, tid]--;
}

tempcreate*:::operation-start
/* @bsdinstruments-predicate */
{
    tempcreate_operation_depth[pid, tid]++;
    tempcreate_operation_time[pid, tid, tempcreate_operation_depth[pid, tid]] = timestamp;
}

tempcreate*:::operation-done
/tempcreate_operation_time[pid, tid, tempcreate_operation_depth[pid, tid]] != 0/
{
    @tempcreate_operation_us[arg0, (int)arg2] = quantize((timestamp - tempcreate_operation_time[pid, tid, tempcreate_operation_depth[pid, tid]]) / 1000);
    @tempcreate_operation_count[arg0, (int)arg2] = count();
    tempcreate_operation_time[pid, tid, tempcreate_operation_depth[pid, tid]] = 0;
    tempcreate_operation_depth[pid, tid]--;
}
