/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

moveio*:::child-start
/* @bsdinstruments-predicate */
{
    mvchild_depth[pid, tid]++;
    mvchild_time[pid, tid, mvchild_depth[pid, tid]] = timestamp;
}

moveio*:::child-done
/mvchild_time[pid, tid, mvchild_depth[pid, tid]] != 0/
{
    @mvchild_us[(int)arg2, (int)arg3] = quantize((timestamp - mvchild_time[pid, tid, mvchild_depth[pid, tid]]) / 1000);
    @mvchild_count[(int)arg2, (int)arg3] = count();
    mvchild_time[pid, tid, mvchild_depth[pid, tid]] = 0;
    mvchild_depth[pid, tid]--;
}
