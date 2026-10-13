/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

procdescriptor:::open-start
/* @bsdinstruments-predicate */
{
    procdescriptor_open_depth[pid, tid]++;
    procdescriptor_open_time[pid, tid, procdescriptor_open_depth[pid, tid]] = timestamp;
}

procdescriptor:::open-done
/procdescriptor_open_time[pid, tid, procdescriptor_open_depth[pid, tid]] != 0/
{
    @procdescriptor_open_us[(int)arg2] = quantize((timestamp - procdescriptor_open_time[pid, tid, procdescriptor_open_depth[pid, tid]]) / 1000);
    @procdescriptor_open_count[(int)arg2] = count();
    procdescriptor_open_time[pid, tid, procdescriptor_open_depth[pid, tid]] = 0;
    procdescriptor_open_depth[pid, tid]--;
}

procdescriptor:::transfer-start
/* @bsdinstruments-predicate */
{
    procdescriptor_transfer_depth[pid, tid]++;
    procdescriptor_transfer_time[pid, tid, procdescriptor_transfer_depth[pid, tid]] = timestamp;
}

procdescriptor:::transfer-done
/procdescriptor_transfer_time[pid, tid, procdescriptor_transfer_depth[pid, tid]] != 0/
{
    @procdescriptor_transfer_us[(int)arg2] = quantize((timestamp - procdescriptor_transfer_time[pid, tid, procdescriptor_transfer_depth[pid, tid]]) / 1000);
    @procdescriptor_transfer_count[(int)arg2] = count();
    procdescriptor_transfer_time[pid, tid, procdescriptor_transfer_depth[pid, tid]] = 0;
    procdescriptor_transfer_depth[pid, tid]--;
}
