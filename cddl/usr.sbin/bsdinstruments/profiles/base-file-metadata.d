/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TENTH.
 * Synchronous per-thread pairs; elapsed times include preemption.
 * Start before workload; lost events invalidate pairing. No string/pointer reads.
 */

filetime*:::operation-start
/* @bsdinstruments-predicate */
{
    filetime_operation_depth[pid, tid]++;
    filetime_operation_time[pid, tid, filetime_operation_depth[pid, tid]] = timestamp;
}

filetime*:::operation-done
/filetime_operation_time[pid, tid, filetime_operation_depth[pid, tid]] != 0/
{
    @filetime_operation_us[arg0, (int)arg2] = quantize((timestamp - filetime_operation_time[pid, tid, filetime_operation_depth[pid, tid]]) / 1000);
    @filetime_operation_count[arg0, (int)arg2] = count();
    filetime_operation_time[pid, tid, filetime_operation_depth[pid, tid]] = 0;
    filetime_operation_depth[pid, tid]--;
}

filestat*:::operation-start
/* @bsdinstruments-predicate */
{
    filestat_operation_depth[pid, tid]++;
    filestat_operation_time[pid, tid, filestat_operation_depth[pid, tid]] = timestamp;
}

filestat*:::operation-done
/filestat_operation_time[pid, tid, filestat_operation_depth[pid, tid]] != 0/
{
    @filestat_operation_us[arg0, (int)arg2] = quantize((timestamp - filestat_operation_time[pid, tid, filestat_operation_depth[pid, tid]]) / 1000);
    @filestat_operation_count[arg0, (int)arg2] = count();
    filestat_operation_time[pid, tid, filestat_operation_depth[pid, tid]] = 0;
    filestat_operation_depth[pid, tid]--;
}
