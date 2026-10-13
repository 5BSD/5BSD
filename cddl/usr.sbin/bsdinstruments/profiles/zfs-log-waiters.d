/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

sdt:::zil-wait-start
/* @bsdinstruments-predicate */
{
    zil_wait_depth[pid, tid]++;
    zil_wait_time[pid, tid, zil_wait_depth[pid, tid]] = timestamp;
}

sdt:::zil-wait-done
/zil_wait_time[pid, tid, zil_wait_depth[pid, tid]] != 0/
{
    @zil_wait_us[(int)arg2] = quantize((timestamp - zil_wait_time[pid, tid, zil_wait_depth[pid, tid]]) / 1000);
    @zil_wait_count[(int)arg2] = count();
    zil_wait_time[pid, tid, zil_wait_depth[pid, tid]] = 0;
    zil_wait_depth[pid, tid]--;
}

sdt:::zil-wait-timeout
/* @bsdinstruments-predicate */
{
    @issue_timeouts = count();
}

sdt:::zil-waiter-allocate
/* @bsdinstruments-predicate */
{
    @allocated = count();
}

sdt:::zil-waiter-release
/* @bsdinstruments-predicate */
{
    @released = count();
}
