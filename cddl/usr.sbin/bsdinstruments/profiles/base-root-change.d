/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

rootchange*:::operation-start
/* @bsdinstruments-predicate */
{
    rootchange_operation_depth[pid, tid]++;
    rootchange_operation_time[pid, tid, rootchange_operation_depth[pid, tid]] = timestamp;
}

rootchange*:::operation-done
/rootchange_operation_time[pid, tid, rootchange_operation_depth[pid, tid]] != 0/
{
    @rootchange_operation_us[(int)arg2] = quantize((timestamp - rootchange_operation_time[pid, tid, rootchange_operation_depth[pid, tid]]) / 1000);
    @rootchange_operation_count[(int)arg2] = count();
    rootchange_operation_time[pid, tid, rootchange_operation_depth[pid, tid]] = 0;
    rootchange_operation_depth[pid, tid]--;
}
