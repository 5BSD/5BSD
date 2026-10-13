/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

signaltool*:::operation-start
/* @bsdinstruments-predicate */
{
    signaltool_operation_depth[pid, tid]++;
    signaltool_operation_time[pid, tid, signaltool_operation_depth[pid, tid]] = timestamp;
}

signaltool*:::operation-done
/signaltool_operation_time[pid, tid, signaltool_operation_depth[pid, tid]] != 0/
{
    @signaltool_operation_us[arg0, (int)arg3] = quantize((timestamp - signaltool_operation_time[pid, tid, signaltool_operation_depth[pid, tid]]) / 1000);
    @signaltool_operation_count[arg0, (int)arg3] = count();
    signaltool_operation_time[pid, tid, signaltool_operation_depth[pid, tid]] = 0;
    signaltool_operation_depth[pid, tid]--;
}

logsend*:::operation-start
/* @bsdinstruments-predicate */
{
    logsend_operation_depth[pid, tid]++;
    logsend_operation_time[pid, tid, logsend_operation_depth[pid, tid]] = timestamp;
}

logsend*:::operation-done
/logsend_operation_time[pid, tid, logsend_operation_depth[pid, tid]] != 0/
{
    @logsend_operation_us[arg0, (int)arg2] = quantize((timestamp - logsend_operation_time[pid, tid, logsend_operation_depth[pid, tid]]) / 1000);
    @logsend_operation_count[arg0, (int)arg2] = count();
    logsend_operation_time[pid, tid, logsend_operation_depth[pid, tid]] = 0;
    logsend_operation_depth[pid, tid]--;
}

logsend*:::local-start
/* @bsdinstruments-predicate */
{
    logsend_local_depth[pid, tid]++;
    logsend_local_time[pid, tid, logsend_local_depth[pid, tid]] = timestamp;
}

logsend*:::local-done
/logsend_local_time[pid, tid, logsend_local_depth[pid, tid]] != 0/
{
    @logsend_local_us[arg0] = quantize((timestamp - logsend_local_time[pid, tid, logsend_local_depth[pid, tid]]) / 1000);
    @logsend_local_count[arg0] = count();
    logsend_local_time[pid, tid, logsend_local_depth[pid, tid]] = 0;
    logsend_local_depth[pid, tid]--;
}
