/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-EIGHTEENTH for argument semantics.
 * Scalar arguments only, no payloads, addresses or credentials.
 * Start before the workload; dropped events invalidate latency pairing.
 * Elapsed times include scheduling and reacquiring existing locks.
 */

sdt:::socket-accept-wait-start
/* @bsdinstruments-predicate */
{
    accept_depth[pid, tid]++;
    accept_time[pid, tid, accept_depth[pid, tid]] = timestamp;
}

sdt:::socket-accept-wait-done
/accept_time[pid, tid, accept_depth[pid, tid]] != 0/
{
    @accept_us = quantize((timestamp - accept_time[pid, tid, accept_depth[pid, tid]]) / 1000);
    @wake_results[(int)arg1] = count();
    accept_time[pid, tid, accept_depth[pid, tid]] = 0;
    accept_depth[pid, tid]--;
}
