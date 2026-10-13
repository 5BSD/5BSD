/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

gzipstream*:::inflate-start
/* @bsdinstruments-predicate */
{
    inflate_depth[pid, tid]++;
    inflate_time[pid, tid, inflate_depth[pid, tid]] = timestamp;
}

gzipstream*:::inflate-done
/inflate_time[pid, tid, inflate_depth[pid, tid]] != 0/
{
    @inflate_us = quantize((timestamp - inflate_time[pid, tid, inflate_depth[pid, tid]]) / 1000);
    @zlib_status[(int)arg0] = count();
    inflate_time[pid, tid, inflate_depth[pid, tid]] = 0;
    inflate_depth[pid, tid]--;
}

gzipstream*:::decode-error
/* @bsdinstruments-predicate */
{ @decode_error_phase[(int)arg0] = count(); }
