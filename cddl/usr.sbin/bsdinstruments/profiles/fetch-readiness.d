/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

fetchio*:::poll-start
/* @bsdinstruments-predicate */
{
    fetchpoll_depth[pid, tid]++;
    fetchpoll_time[pid, tid, fetchpoll_depth[pid, tid]] = timestamp;
}

fetchio*:::poll-done
/fetchpoll_time[pid, tid, fetchpoll_depth[pid, tid]] != 0/
{
    @fetchpoll_us[(int)arg2, (int)arg3] = quantize((timestamp - fetchpoll_time[pid, tid, fetchpoll_depth[pid, tid]]) / 1000);
    @fetchpoll_count[(int)arg2, (int)arg3] = count();
    fetchpoll_time[pid, tid, fetchpoll_depth[pid, tid]] = 0;
    fetchpoll_depth[pid, tid]--;
}
