/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

unpcb:::send-wait-start
/* @bsdinstruments-predicate */
{
    unixsend_depth[pid, tid]++;
    unixsend_time[pid, tid, unixsend_depth[pid, tid]] = timestamp;
}

unpcb:::send-wait-done
/unixsend_time[pid, tid, unixsend_depth[pid, tid]] != 0/
{
    @unixsend_us[(int)arg1] = quantize((timestamp - unixsend_time[pid, tid, unixsend_depth[pid, tid]]) / 1000);
    @unixsend_count[(int)arg1] = count();
    unixsend_time[pid, tid, unixsend_depth[pid, tid]] = 0;
    unixsend_depth[pid, tid]--;
}
