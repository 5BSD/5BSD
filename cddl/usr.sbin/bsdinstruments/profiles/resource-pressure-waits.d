/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

swap:::buffer-wait-start
/* @bsdinstruments-predicate */
{
    swapbuffer_depth[pid, tid]++;
    swapbuffer_time[pid, tid, swapbuffer_depth[pid, tid]] = timestamp;
}

swap:::buffer-wait-done
/swapbuffer_time[pid, tid, swapbuffer_depth[pid, tid]] != 0/
{
    @swapbuffer_us[(int)arg0] = quantize((timestamp - swapbuffer_time[pid, tid, swapbuffer_depth[pid, tid]]) / 1000);
    @swapbuffer_count[(int)arg0] = count();
    swapbuffer_time[pid, tid, swapbuffer_depth[pid, tid]] = 0;
    swapbuffer_depth[pid, tid]--;
}

racct:::throttle-start
/* @bsdinstruments-predicate */
{
    throttle_depth[pid, tid]++;
    throttle_time[pid, tid, throttle_depth[pid, tid]] = timestamp;
}

racct:::throttle-done
/throttle_time[pid, tid, throttle_depth[pid, tid]] != 0/
{
    @throttle_us[(int)arg1] = quantize((timestamp - throttle_time[pid, tid, throttle_depth[pid, tid]]) / 1000);
    @throttle_count[(int)arg1] = count();
    throttle_time[pid, tid, throttle_depth[pid, tid]] = 0;
    throttle_depth[pid, tid]--;
}
