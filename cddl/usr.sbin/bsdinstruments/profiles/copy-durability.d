/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

ddio*:::sync-start
/* @bsdinstruments-predicate */
{
    ddsync_depth[pid, tid]++;
    ddsync_time[pid, tid, ddsync_depth[pid, tid]] = timestamp;
}

ddio*:::sync-done
/ddsync_time[pid, tid, ddsync_depth[pid, tid]] != 0/
{
    @ddsync_us[(int)arg1, (int)arg3] = quantize((timestamp - ddsync_time[pid, tid, ddsync_depth[pid, tid]]) / 1000);
    @ddsync_count[(int)arg1, (int)arg3] = count();
    ddsync_time[pid, tid, ddsync_depth[pid, tid]] = 0;
    ddsync_depth[pid, tid]--;
}

cpcopy*:::retry
/* @bsdinstruments-predicate */
{
    @copy_retries[(int)arg2] = count();
}
