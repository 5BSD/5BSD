/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

archiveop*:::operation-start
/* @bsdinstruments-predicate */
{
    archive_op_depth[pid, tid]++;
    archive_op_time[pid, tid, archive_op_depth[pid, tid]] = timestamp;
}

archiveop*:::operation-done
/archive_op_time[pid, tid, archive_op_depth[pid, tid]] != 0/
{
    @archive_op_us = quantize((timestamp - archive_op_time[pid, tid, archive_op_depth[pid, tid]]) / 1000);
    @operation_status[(int)arg0, (int)arg1] = count();
    archive_op_time[pid, tid, archive_op_depth[pid, tid]] = 0;
    archive_op_depth[pid, tid]--;
}
