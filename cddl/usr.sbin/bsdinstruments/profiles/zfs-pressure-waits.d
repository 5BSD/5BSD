/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-TWELFTH.
 * Start before workload. Event loss invalidates pairing; latency includes preemption.
 * No pointer or payload reads. PF limiter eligibility is not packet admission.
 */

sdt:::dmu-dirty-wait-start
/* @bsdinstruments-predicate */
{
    dmu_dirty_wait_depth[pid, tid]++;
    dmu_dirty_wait_time[pid, tid, dmu_dirty_wait_depth[pid, tid]] = timestamp;
}

sdt:::dmu-dirty-wait-done
/dmu_dirty_wait_time[pid, tid, dmu_dirty_wait_depth[pid, tid]] != 0/
{
    @dmu_dirty_wait_us = quantize((timestamp - dmu_dirty_wait_time[pid, tid, dmu_dirty_wait_depth[pid, tid]]) / 1000);
    @dmu_dirty_wait_count = count();
    dmu_dirty_wait_time[pid, tid, dmu_dirty_wait_depth[pid, tid]] = 0;
    dmu_dirty_wait_depth[pid, tid]--;
}

sdt:::dmu-dnode-wait-start
/* @bsdinstruments-predicate */
{
    dmu_dnode_wait_depth[pid, tid]++;
    dmu_dnode_wait_time[pid, tid, dmu_dnode_wait_depth[pid, tid]] = timestamp;
}

sdt:::dmu-dnode-wait-done
/dmu_dnode_wait_time[pid, tid, dmu_dnode_wait_depth[pid, tid]] != 0/
{
    @dmu_dnode_wait_us = quantize((timestamp - dmu_dnode_wait_time[pid, tid, dmu_dnode_wait_depth[pid, tid]]) / 1000);
    @dmu_dnode_wait_count = count();
    dmu_dnode_wait_time[pid, tid, dmu_dnode_wait_depth[pid, tid]] = 0;
    dmu_dnode_wait_depth[pid, tid]--;
}
