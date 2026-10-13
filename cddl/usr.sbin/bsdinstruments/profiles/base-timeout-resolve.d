/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

timeoutsig*:::operation-start
/* @bsdinstruments-predicate */
{
    timeoutsig_operation_depth[pid, tid]++;
    timeoutsig_operation_time[pid, tid, timeoutsig_operation_depth[pid, tid]] = timestamp;
}

timeoutsig*:::operation-done
/timeoutsig_operation_time[pid, tid, timeoutsig_operation_depth[pid, tid]] != 0/
{
    @timeoutsig_operation_us[arg0, (int)arg3] = quantize((timestamp - timeoutsig_operation_time[pid, tid, timeoutsig_operation_depth[pid, tid]]) / 1000);
    @timeoutsig_operation_count[arg0, (int)arg3] = count();
    timeoutsig_operation_time[pid, tid, timeoutsig_operation_depth[pid, tid]] = 0;
    timeoutsig_operation_depth[pid, tid]--;
}

timeoutsig*:::reaper-start
/* @bsdinstruments-predicate */
{
    timeoutsig_reaper_depth[pid, tid]++;
    timeoutsig_reaper_time[pid, tid, timeoutsig_reaper_depth[pid, tid]] = timestamp;
}

timeoutsig*:::reaper-done
/timeoutsig_reaper_time[pid, tid, timeoutsig_reaper_depth[pid, tid]] != 0/
{
    @timeoutsig_reaper_us[arg0, (int)arg2] = quantize((timestamp - timeoutsig_reaper_time[pid, tid, timeoutsig_reaper_depth[pid, tid]]) / 1000);
    @timeoutsig_reaper_count[arg0, (int)arg2] = count();
    timeoutsig_reaper_time[pid, tid, timeoutsig_reaper_depth[pid, tid]] = 0;
    timeoutsig_reaper_depth[pid, tid]--;
}

pathresolve*:::operation-start
/* @bsdinstruments-predicate */
{
    pathresolve_operation_depth[pid, tid]++;
    pathresolve_operation_time[pid, tid, pathresolve_operation_depth[pid, tid]] = timestamp;
}

pathresolve*:::operation-done
/pathresolve_operation_time[pid, tid, pathresolve_operation_depth[pid, tid]] != 0/
{
    @pathresolve_operation_us[arg0, (int)arg2] = quantize((timestamp - pathresolve_operation_time[pid, tid, pathresolve_operation_depth[pid, tid]]) / 1000);
    @pathresolve_operation_count[arg0, (int)arg2] = count();
    pathresolve_operation_time[pid, tid, pathresolve_operation_depth[pid, tid]] = 0;
    pathresolve_operation_depth[pid, tid]--;
}
