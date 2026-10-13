/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

tailwait*:::operation-start
/* @bsdinstruments-predicate */
{
    tailwait_operation_depth[pid, tid]++;
    tailwait_operation_time[pid, tid, tailwait_operation_depth[pid, tid]] = timestamp;
}

tailwait*:::operation-done
/tailwait_operation_time[pid, tid, tailwait_operation_depth[pid, tid]] != 0/
{
    @tailwait_operation_us[(int)arg3] = quantize((timestamp - tailwait_operation_time[pid, tid, tailwait_operation_depth[pid, tid]]) / 1000);
    @tailwait_operation_count[(int)arg3] = count();
    tailwait_operation_time[pid, tid, tailwait_operation_depth[pid, tid]] = 0;
    tailwait_operation_depth[pid, tid]--;
}

processwait*:::operation-start
/* @bsdinstruments-predicate */
{
    processwait_operation_depth[pid, tid]++;
    processwait_operation_time[pid, tid, processwait_operation_depth[pid, tid]] = timestamp;
}

processwait*:::operation-done
/processwait_operation_time[pid, tid, processwait_operation_depth[pid, tid]] != 0/
{
    @processwait_operation_us[(int)arg3] = quantize((timestamp - processwait_operation_time[pid, tid, processwait_operation_depth[pid, tid]]) / 1000);
    @processwait_operation_count[(int)arg3] = count();
    processwait_operation_time[pid, tid, processwait_operation_depth[pid, tid]] = 0;
    processwait_operation_depth[pid, tid]--;
}
