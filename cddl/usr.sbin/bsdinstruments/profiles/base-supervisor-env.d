/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

daemonwait*:::operation-start
/* @bsdinstruments-predicate */
{
    daemonwait_operation_depth[pid, tid]++;
    daemonwait_operation_time[pid, tid, daemonwait_operation_depth[pid, tid]] = timestamp;
}

daemonwait*:::operation-done
/daemonwait_operation_time[pid, tid, daemonwait_operation_depth[pid, tid]] != 0/
{
    @daemonwait_operation_us[arg0, (int)arg3] = quantize((timestamp - daemonwait_operation_time[pid, tid, daemonwait_operation_depth[pid, tid]]) / 1000);
    @daemonwait_operation_count[arg0, (int)arg3] = count();
    daemonwait_operation_time[pid, tid, daemonwait_operation_depth[pid, tid]] = 0;
    daemonwait_operation_depth[pid, tid]--;
}

envdir*:::operation-start
/* @bsdinstruments-predicate */
{
    envdir_operation_depth[pid, tid]++;
    envdir_operation_time[pid, tid, envdir_operation_depth[pid, tid]] = timestamp;
}

envdir*:::operation-done
/envdir_operation_time[pid, tid, envdir_operation_depth[pid, tid]] != 0/
{
    @envdir_operation_us[arg0, (int)arg2] = quantize((timestamp - envdir_operation_time[pid, tid, envdir_operation_depth[pid, tid]]) / 1000);
    @envdir_operation_count[arg0, (int)arg2] = count();
    envdir_operation_time[pid, tid, envdir_operation_depth[pid, tid]] = 0;
    envdir_operation_depth[pid, tid]--;
}
