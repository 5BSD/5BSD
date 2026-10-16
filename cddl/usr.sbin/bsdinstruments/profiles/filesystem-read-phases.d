/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

tarfs:::read-start
/* @bsdinstruments-predicate */
{
    tarread_depth[pid, tid]++;
    tarread_time[pid, tid, tarread_depth[pid, tid]] = timestamp;
}

tarfs:::read-done
/tarread_time[pid, tid, tarread_depth[pid, tid]] != 0/
{
    @tarread_us[(int)arg2] = quantize((timestamp - tarread_time[pid, tid, tarread_depth[pid, tid]]) / 1000);
    @tarread_count[(int)arg2] = count();
    tarread_time[pid, tid, tarread_depth[pid, tid]] = 0;
    tarread_depth[pid, tid]--;
}

isofs:::block-start
/* @bsdinstruments-predicate */
{
    cd9660block_depth[pid, tid]++;
    cd9660block_time[pid, tid, cd9660block_depth[pid, tid]] = timestamp;
}

isofs:::block-done
/cd9660block_time[pid, tid, cd9660block_depth[pid, tid]] != 0/
{
    @cd9660block_us[(int)arg3] = quantize((timestamp - cd9660block_time[pid, tid, cd9660block_depth[pid, tid]]) / 1000);
    @cd9660block_count[(int)arg3] = count();
    cd9660block_time[pid, tid, cd9660block_depth[pid, tid]] = 0;
    cd9660block_depth[pid, tid]--;
}
