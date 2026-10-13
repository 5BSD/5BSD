/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

unionfs:::copyup-start
/* @bsdinstruments-predicate */
{
    unioncopy_depth[pid, tid]++;
    unioncopy_time[pid, tid, unioncopy_depth[pid, tid]] = timestamp;
}

unionfs:::copyup-done
/unioncopy_time[pid, tid, unioncopy_depth[pid, tid]] != 0/
{
    @unioncopy_us[(int)arg2] = quantize((timestamp - unioncopy_time[pid, tid, unioncopy_depth[pid, tid]]) / 1000);
    @unioncopy_count[(int)arg2] = count();
    unioncopy_time[pid, tid, unioncopy_depth[pid, tid]] = 0;
    unioncopy_depth[pid, tid]--;
}

nullfs:::node-start
/* @bsdinstruments-predicate */
{
    nullnode_depth[pid, tid]++;
    nullnode_time[pid, tid, nullnode_depth[pid, tid]] = timestamp;
}

nullfs:::node-done
/nullnode_time[pid, tid, nullnode_depth[pid, tid]] != 0/
{
    @nullnode_us[(int)arg1] = quantize((timestamp - nullnode_time[pid, tid, nullnode_depth[pid, tid]]) / 1000);
    @nullnode_count[(int)arg1] = count();
    nullnode_time[pid, tid, nullnode_depth[pid, tid]] = 0;
    nullnode_depth[pid, tid]--;
}

nullfs:::cache-hit,
nullfs:::cache-miss
/* @bsdinstruments-predicate */
{
    @null_cache[probename] = count();
}
