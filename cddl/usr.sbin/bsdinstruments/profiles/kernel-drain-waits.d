/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

pipe:::lock-wait-start
/* @bsdinstruments-predicate */
{
    pipelk_depth[pid, tid]++;
    pipelk_time[pid, tid, pipelk_depth[pid, tid]] = timestamp;
}

pipe:::lock-wait-done
/pipelk_time[pid, tid, pipelk_depth[pid, tid]] != 0/
{
    @pipelk_us[(int)arg1] = quantize((timestamp - pipelk_time[pid, tid, pipelk_depth[pid, tid]]) / 1000);
    @pipelk_count[(int)arg1] = count();
    pipelk_time[pid, tid, pipelk_depth[pid, tid]] = 0;
    pipelk_depth[pid, tid]--;
}

aio:::suspend-wait-start
/* @bsdinstruments-predicate */
{
    aiowait_depth[pid, tid]++;
    aiowait_time[pid, tid, aiowait_depth[pid, tid]] = timestamp;
}

aio:::suspend-wait-done
/aiowait_time[pid, tid, aiowait_depth[pid, tid]] != 0/
{
    @aiowait_us[(int)arg1] = quantize((timestamp - aiowait_time[pid, tid, aiowait_depth[pid, tid]]) / 1000);
    @aiowait_count[(int)arg1] = count();
    aiowait_time[pid, tid, aiowait_depth[pid, tid]] = 0;
    aiowait_depth[pid, tid]--;
}

mount:::drain-start
/* @bsdinstruments-predicate */
{
    mountdrain_depth[pid, tid]++;
    mountdrain_time[pid, tid, mountdrain_depth[pid, tid]] = timestamp;
}

mount:::drain-done
/mountdrain_time[pid, tid, mountdrain_depth[pid, tid]] != 0/
{
    @mountdrain_us[(int)arg1] = quantize((timestamp - mountdrain_time[pid, tid, mountdrain_depth[pid, tid]]) / 1000);
    @mountdrain_count[(int)arg1] = count();
    mountdrain_time[pid, tid, mountdrain_depth[pid, tid]] = 0;
    mountdrain_depth[pid, tid]--;
}

kqueue:::drain-start
/* @bsdinstruments-predicate */
{
    kqdrain_depth[pid, tid]++;
    kqdrain_time[pid, tid, kqdrain_depth[pid, tid]] = timestamp;
}

kqueue:::drain-done
/kqdrain_time[pid, tid, kqdrain_depth[pid, tid]] != 0/
{
    @kqdrain_us[(int)arg1] = quantize((timestamp - kqdrain_time[pid, tid, kqdrain_depth[pid, tid]]) / 1000);
    @kqdrain_count[(int)arg1] = count();
    kqdrain_time[pid, tid, kqdrain_depth[pid, tid]] = 0;
    kqdrain_depth[pid, tid]--;
}
