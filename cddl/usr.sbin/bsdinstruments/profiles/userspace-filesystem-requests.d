/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

autofs:::request-start
/* @bsdinstruments-predicate */
{
    autofsrequest_depth[pid, tid]++;
    autofsrequest_time[pid, tid, autofsrequest_depth[pid, tid]] = timestamp;
}

autofs:::request-done
/autofsrequest_time[pid, tid, autofsrequest_depth[pid, tid]] != 0/
{
    @autofsrequest_us[(int)arg1, (int)arg2] = quantize((timestamp - autofsrequest_time[pid, tid, autofsrequest_depth[pid, tid]]) / 1000);
    @autofsrequest_count[(int)arg1, (int)arg2] = count();
    autofsrequest_time[pid, tid, autofsrequest_depth[pid, tid]] = 0;
    autofsrequest_depth[pid, tid]--;
}

cuse:::command-start
/* @bsdinstruments-predicate */
{
    cusecommand_depth[pid, tid]++;
    cusecommand_time[pid, tid, cusecommand_depth[pid, tid]] = timestamp;
}

cuse:::command-done
/cusecommand_time[pid, tid, cusecommand_depth[pid, tid]] != 0/
{
    @cusecommand_us[(int)arg1] = quantize((timestamp - cusecommand_time[pid, tid, cusecommand_depth[pid, tid]]) / 1000);
    @cusecommand_count[(int)arg1] = count();
    cusecommand_time[pid, tid, cusecommand_depth[pid, tid]] = 0;
    cusecommand_depth[pid, tid]--;
}

p9fs:::request-start
/* @bsdinstruments-predicate */
{
    p9request_depth[pid, tid]++;
    p9request_time[pid, tid, p9request_depth[pid, tid]] = timestamp;
}

p9fs:::request-done
/p9request_time[pid, tid, p9request_depth[pid, tid]] != 0/
{
    @p9request_us[(int)arg1, (int)arg2] = quantize((timestamp - p9request_time[pid, tid, p9request_depth[pid, tid]]) / 1000);
    @p9request_count[(int)arg1, (int)arg2] = count();
    p9request_time[pid, tid, p9request_depth[pid, tid]] = 0;
    p9request_depth[pid, tid]--;
}

p9fs:::tag-exhausted
/* @bsdinstruments-predicate */
{
    @p9_tag_exhausted = count();
}
