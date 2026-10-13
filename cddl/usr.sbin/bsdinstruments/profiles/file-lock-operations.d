/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

lockfile*:::operation-start
/* @bsdinstruments-predicate */
{
    lockfile_depth[pid, tid]++;
    lockfile_time[pid, tid, lockfile_depth[pid, tid]] = timestamp;
}

lockfile*:::operation-done
/lockfile_time[pid, tid, lockfile_depth[pid, tid]] != 0/
{
    @lockfile_us[(int)arg0, (int)arg1, (int)arg3] = quantize((timestamp - lockfile_time[pid, tid, lockfile_depth[pid, tid]]) / 1000);
    @lockfile_count[(int)arg0, (int)arg1, (int)arg3] = count();
    lockfile_time[pid, tid, lockfile_depth[pid, tid]] = 0;
    lockfile_depth[pid, tid]--;
}
