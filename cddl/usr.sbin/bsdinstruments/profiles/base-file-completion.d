/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

filesync*:::operation-start
/* @bsdinstruments-predicate */
{
    filesync_operation_depth[pid, tid]++;
    filesync_operation_time[pid, tid, filesync_operation_depth[pid, tid]] = timestamp;
}

filesync*:::operation-done
/filesync_operation_time[pid, tid, filesync_operation_depth[pid, tid]] != 0/
{
    @filesync_operation_us[(int)arg2] = quantize((timestamp - filesync_operation_time[pid, tid, filesync_operation_depth[pid, tid]]) / 1000);
    @filesync_operation_count[(int)arg2] = count();
    filesync_operation_time[pid, tid, filesync_operation_depth[pid, tid]] = 0;
    filesync_operation_depth[pid, tid]--;
}

checksumtool*:::file-start
/* @bsdinstruments-predicate */
{
    checksumtool_file_depth[pid, tid]++;
    checksumtool_file_time[pid, tid, checksumtool_file_depth[pid, tid]] = timestamp;
}

checksumtool*:::file-done
/checksumtool_file_time[pid, tid, checksumtool_file_depth[pid, tid]] != 0/
{
    @checksumtool_file_us[(int)arg3] = quantize((timestamp - checksumtool_file_time[pid, tid, checksumtool_file_depth[pid, tid]]) / 1000);
    @checksumtool_file_count[(int)arg3] = count();
    checksumtool_file_time[pid, tid, checksumtool_file_depth[pid, tid]] = 0;
    checksumtool_file_depth[pid, tid]--;
}
