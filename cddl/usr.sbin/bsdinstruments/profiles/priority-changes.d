/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

priorityop*:::operation-start
/* @bsdinstruments-predicate */
{
    priorityop_depth[pid, tid]++;
    priorityop_time[pid, tid, priorityop_depth[pid, tid]] = timestamp;
}

priorityop*:::operation-done
/priorityop_time[pid, tid, priorityop_depth[pid, tid]] != 0/
{
    @priorityop_us[(int)arg0, (int)arg2, (int)arg4] = quantize((timestamp - priorityop_time[pid, tid, priorityop_depth[pid, tid]]) / 1000);
    @priorityop_count[(int)arg0, (int)arg2, (int)arg4] = count();
    priorityop_time[pid, tid, priorityop_depth[pid, tid]] = 0;
    priorityop_depth[pid, tid]--;
}
