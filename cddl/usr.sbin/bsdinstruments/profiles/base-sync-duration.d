/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

flushall*:::operation-start
/* @bsdinstruments-predicate */
{
    flushall_depth[pid, tid]++;
    flushall_time[pid, tid, flushall_depth[pid, tid]] = timestamp;
}

flushall*:::operation-done
/flushall_time[pid, tid, flushall_depth[pid, tid]] != 0/
{
    @flushall_us[0] = quantize((timestamp - flushall_time[pid, tid, flushall_depth[pid, tid]]) / 1000);
    @flushall_count[0] = count();
    flushall_time[pid, tid, flushall_depth[pid, tid]] = 0;
    flushall_depth[pid, tid]--;
}
