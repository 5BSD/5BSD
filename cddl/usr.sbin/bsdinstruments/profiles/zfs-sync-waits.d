/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

sdt:::txg-wait-start
/* @bsdinstruments-predicate */
{
    txg_wait_depth[pid, tid]++;
    txg_wait_time[pid, tid, txg_wait_depth[pid, tid]] = timestamp;
}

sdt:::txg-wait-done
/txg_wait_time[pid, tid, txg_wait_depth[pid, tid]] != 0/
{
    @txg_wait_us[(int)arg3] = quantize((timestamp - txg_wait_time[pid, tid, txg_wait_depth[pid, tid]]) / 1000);
    @txg_wait_count[(int)arg3] = count();
    txg_wait_time[pid, tid, txg_wait_depth[pid, tid]] = 0;
    txg_wait_depth[pid, tid]--;
}
