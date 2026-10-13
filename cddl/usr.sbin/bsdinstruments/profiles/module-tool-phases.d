/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

moduleload*:::operation-start
/* @bsdinstruments-predicate */
{
    modload_depth[pid, tid]++;
    modload_time[pid, tid, modload_depth[pid, tid]] = timestamp;
}

moduleload*:::operation-done
/modload_time[pid, tid, modload_depth[pid, tid]] != 0/
{
    @modload_us[(int)arg2] = quantize((timestamp - modload_time[pid, tid, modload_depth[pid, tid]]) / 1000);
    @modload_count[(int)arg2] = count();
    modload_time[pid, tid, modload_depth[pid, tid]] = 0;
    modload_depth[pid, tid]--;
}

moduleunload*:::operation-start
/* @bsdinstruments-predicate */
{
    modunload_depth[pid, tid]++;
    modunload_time[pid, tid, modunload_depth[pid, tid]] = timestamp;
}

moduleunload*:::operation-done
/modunload_time[pid, tid, modunload_depth[pid, tid]] != 0/
{
    @modunload_us[(int)arg1, (int)arg3] = quantize((timestamp - modunload_time[pid, tid, modunload_depth[pid, tid]]) / 1000);
    @modunload_count[(int)arg1, (int)arg3] = count();
    modunload_time[pid, tid, modunload_depth[pid, tid]] = 0;
    modunload_depth[pid, tid]--;
}
