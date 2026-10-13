/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

sdt:::dmu-assign-start
/* @bsdinstruments-predicate */
{
    dmu_assign_depth[pid, tid]++;
    dmu_assign_time[pid, tid, dmu_assign_depth[pid, tid]] = timestamp;
}

sdt:::dmu-assign-done
/dmu_assign_time[pid, tid, dmu_assign_depth[pid, tid]] != 0/
{
    @dmu_assign_us[(int)arg2] = quantize((timestamp - dmu_assign_time[pid, tid, dmu_assign_depth[pid, tid]]) / 1000);
    @dmu_assign_count[(int)arg2] = count();
    dmu_assign_time[pid, tid, dmu_assign_depth[pid, tid]] = 0;
    dmu_assign_depth[pid, tid]--;
}

sdt:::dmu-assign-retry
/* @bsdinstruments-predicate */
{
    @attempt_errors[(int)arg1] = count();
}
