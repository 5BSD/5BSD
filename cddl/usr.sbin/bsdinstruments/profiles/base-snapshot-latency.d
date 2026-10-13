/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

socketsnapshot*:::query-start
/* @bsdinstruments-predicate */
{
    socketsnapshot_depth[pid, tid]++;
    socketsnapshot_time[pid, tid, socketsnapshot_depth[pid, tid]] = timestamp;
}

socketsnapshot*:::query-done
/socketsnapshot_time[pid, tid, socketsnapshot_depth[pid, tid]] != 0/
{
    @socketsnapshot_us = quantize((timestamp - socketsnapshot_time[pid, tid, socketsnapshot_depth[pid, tid]]) / 1000);
    @socketsnapshot_errors[(int)arg1] = count();
    socketsnapshot_time[pid, tid, socketsnapshot_depth[pid, tid]] = 0;
    socketsnapshot_depth[pid, tid]--;
}

ipcsnapshot*:::query-start
/* @bsdinstruments-predicate */
{
    ipcsnapshot_depth[pid, tid]++;
    ipcsnapshot_time[pid, tid, ipcsnapshot_depth[pid, tid]] = timestamp;
}

ipcsnapshot*:::query-done
/ipcsnapshot_time[pid, tid, ipcsnapshot_depth[pid, tid]] != 0/
{
    @ipcsnapshot_us = quantize((timestamp - ipcsnapshot_time[pid, tid, ipcsnapshot_depth[pid, tid]]) / 1000);
    @ipcsnapshot_errors[(int)arg1] = count();
    ipcsnapshot_time[pid, tid, ipcsnapshot_depth[pid, tid]] = 0;
    ipcsnapshot_depth[pid, tid]--;
}
