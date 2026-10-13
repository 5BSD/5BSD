/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

geomdev:::flush-start
/* @bsdinstruments-predicate */
{
    geomdev_flush_depth[pid, tid]++;
    geomdev_flush_time[pid, tid, geomdev_flush_depth[pid, tid]] = timestamp;
}

geomdev:::flush-done
/geomdev_flush_time[pid, tid, geomdev_flush_depth[pid, tid]] != 0/
{
    @geomdev_flush_us[(int)arg1] = quantize((timestamp - geomdev_flush_time[pid, tid, geomdev_flush_depth[pid, tid]]) / 1000);
    @geomdev_flush_count[(int)arg1] = count();
    geomdev_flush_time[pid, tid, geomdev_flush_depth[pid, tid]] = 0;
    geomdev_flush_depth[pid, tid]--;
}

geomdev:::delete-start
/* @bsdinstruments-predicate */
{
    geomdev_delete_depth[pid, tid]++;
    geomdev_delete_time[pid, tid, geomdev_delete_depth[pid, tid]] = timestamp;
}

geomdev:::delete-done
/geomdev_delete_time[pid, tid, geomdev_delete_depth[pid, tid]] != 0/
{
    @geomdev_delete_us[(int)arg1] = quantize((timestamp - geomdev_delete_time[pid, tid, geomdev_delete_depth[pid, tid]]) / 1000);
    @geomdev_delete_count[(int)arg1] = count();
    geomdev_delete_time[pid, tid, geomdev_delete_depth[pid, tid]] = 0;
    geomdev_delete_depth[pid, tid]--;
}

geomdev:::close-wait-start
/* @bsdinstruments-predicate */
{
    geomdev_close_wait_depth[pid, tid]++;
    geomdev_close_wait_time[pid, tid, geomdev_close_wait_depth[pid, tid]] = timestamp;
}

geomdev:::close-wait-done
/geomdev_close_wait_time[pid, tid, geomdev_close_wait_depth[pid, tid]] != 0/
{
    @geomdev_close_wait_us = quantize((timestamp - geomdev_close_wait_time[pid, tid, geomdev_close_wait_depth[pid, tid]]) / 1000);
    @geomdev_close_wait_count = count();
    geomdev_close_wait_time[pid, tid, geomdev_close_wait_depth[pid, tid]] = 0;
    geomdev_close_wait_depth[pid, tid]--;
}
