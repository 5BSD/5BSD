/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::memory-contig-start
/* @bsdinstruments-predicate */
{
    contig_depth[pid, tid]++;
    contig_time[pid, tid, contig_depth[pid, tid]] = timestamp;
}

sdt:::memory-contig-done
/contig_time[pid, tid, contig_depth[pid, tid]] != 0/
{
    @contig_us = quantize((timestamp - contig_time[pid, tid, contig_depth[pid, tid]]) / 1000);
    @reclaim_status[(int)arg0, (int)arg1] = count();
    contig_time[pid, tid, contig_depth[pid, tid]] = 0;
    contig_depth[pid, tid]--;
}

sdt:::memory-reservation-reclaim
/* @bsdinstruments-predicate */
{
    @reservation_reclaim[(int)arg0, (int)arg1] = count();
}
