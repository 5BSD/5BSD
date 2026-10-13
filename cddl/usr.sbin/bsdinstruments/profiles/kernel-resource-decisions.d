/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

procresource:::nice-start
/* @bsdinstruments-predicate */
{
    procresource_nice_depth[pid, tid]++;
    procresource_nice_time[pid, tid, procresource_nice_depth[pid, tid]] = timestamp;
}

procresource:::nice-done
/procresource_nice_time[pid, tid, procresource_nice_depth[pid, tid]] != 0/
{
    @procresource_nice_us[(int)arg2] = quantize((timestamp - procresource_nice_time[pid, tid, procresource_nice_depth[pid, tid]]) / 1000);
    @procresource_nice_count[(int)arg2] = count();
    procresource_nice_time[pid, tid, procresource_nice_depth[pid, tid]] = 0;
    procresource_nice_depth[pid, tid]--;
}

procresource:::limit-start
/* @bsdinstruments-predicate */
{
    procresource_limit_depth[pid, tid]++;
    procresource_limit_time[pid, tid, procresource_limit_depth[pid, tid]] = timestamp;
}

procresource:::limit-done
/procresource_limit_time[pid, tid, procresource_limit_depth[pid, tid]] != 0/
{
    @procresource_limit_us[(int)arg1] = quantize((timestamp - procresource_limit_time[pid, tid, procresource_limit_depth[pid, tid]]) / 1000);
    @procresource_limit_count[(int)arg1] = count();
    procresource_limit_time[pid, tid, procresource_limit_depth[pid, tid]] = 0;
    procresource_limit_depth[pid, tid]--;
}
