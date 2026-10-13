/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

meshd*:::persist-write-start
/* @bsdinstruments-predicate */
{
    mesh_persist_depth[pid, tid]++;
    mesh_persist_start[pid, tid, mesh_persist_depth[pid, tid]] = timestamp;
}

meshd*:::persist-write-done
/mesh_persist_start[pid, tid, mesh_persist_depth[pid, tid]] != 0/
{
    @mesh_persist_us[(int)arg1] = quantize((timestamp - mesh_persist_start[pid, tid, mesh_persist_depth[pid, tid]]) / 1000);
    mesh_persist_start[pid, tid, mesh_persist_depth[pid, tid]] = 0;
    mesh_persist_depth[pid, tid]--;
}

meshd*:::bearer-full
/* @bsdinstruments-predicate */
{
    @bearer_full = count();
    @pending_bytes = quantize(arg2);
}

meshd*:::bearer-queue
/* @bsdinstruments-predicate */
{
    @queued[(uint16_t)arg1] = count();
}

meshd*:::bearer-failed
/* @bsdinstruments-predicate */
{
    @failed[(int)arg1] = count();
}
