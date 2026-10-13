/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

aclread*:::operation-start
/* @bsdinstruments-predicate */
{
    aclread_operation_depth[pid, tid]++;
    aclread_operation_time[pid, tid, aclread_operation_depth[pid, tid]] = timestamp;
}

aclread*:::operation-done
/aclread_operation_time[pid, tid, aclread_operation_depth[pid, tid]] != 0/
{
    @aclread_operation_us[(int)arg3] = quantize((timestamp - aclread_operation_time[pid, tid, aclread_operation_depth[pid, tid]]) / 1000);
    @aclread_operation_count[(int)arg3] = count();
    aclread_operation_time[pid, tid, aclread_operation_depth[pid, tid]] = 0;
    aclread_operation_depth[pid, tid]--;
}

aclwrite*:::operation-start
/* @bsdinstruments-predicate */
{
    aclwrite_operation_depth[pid, tid]++;
    aclwrite_operation_time[pid, tid, aclwrite_operation_depth[pid, tid]] = timestamp;
}

aclwrite*:::operation-done
/aclwrite_operation_time[pid, tid, aclwrite_operation_depth[pid, tid]] != 0/
{
    @aclwrite_operation_us[(int)arg3] = quantize((timestamp - aclwrite_operation_time[pid, tid, aclwrite_operation_depth[pid, tid]]) / 1000);
    @aclwrite_operation_count[(int)arg3] = count();
    aclwrite_operation_time[pid, tid, aclwrite_operation_depth[pid, tid]] = 0;
    aclwrite_operation_depth[pid, tid]--;
}
