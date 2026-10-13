/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::rebuild-wait-start
/* @bsdinstruments-predicate */
{
    rebuild_wait_depth[pid, tid]++;
    rebuild_wait_time[pid, tid, rebuild_wait_depth[pid, tid]] = timestamp;
}

sdt:::rebuild-wait-done
/rebuild_wait_time[pid, tid, rebuild_wait_depth[pid, tid]] != 0/
{
    @rebuild_wait_us = quantize((timestamp - rebuild_wait_time[pid, tid, rebuild_wait_depth[pid, tid]]) / 1000);
    @wait_kind[(int)arg1] = count();
    rebuild_wait_time[pid, tid, rebuild_wait_depth[pid, tid]] = 0;
    rebuild_wait_depth[pid, tid]--;
}

sdt:::rebuild-state
/* @bsdinstruments-predicate */
{ @states[(uint64_t)arg1] = count(); }
