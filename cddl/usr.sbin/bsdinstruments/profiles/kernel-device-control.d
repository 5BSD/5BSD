/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

socketctl:::protocol-start
/* @bsdinstruments-predicate */
{
    socketctl_protocol_depth[pid, tid]++;
    socketctl_protocol_time[pid, tid, socketctl_protocol_depth[pid, tid]] = timestamp;
}

socketctl:::protocol-done
/socketctl_protocol_time[pid, tid, socketctl_protocol_depth[pid, tid]] != 0/
{
    @socketctl_protocol_us[(int)arg2] = quantize((timestamp - socketctl_protocol_time[pid, tid, socketctl_protocol_depth[pid, tid]]) / 1000);
    @socketctl_protocol_count[(int)arg2] = count();
    socketctl_protocol_time[pid, tid, socketctl_protocol_depth[pid, tid]] = 0;
    socketctl_protocol_depth[pid, tid]--;
}

firmware:::load-wait-start
/* @bsdinstruments-predicate */
{
    firmware_load_wait_depth[pid, tid]++;
    firmware_load_wait_time[pid, tid, firmware_load_wait_depth[pid, tid]] = timestamp;
}

firmware:::load-wait-done
/firmware_load_wait_time[pid, tid, firmware_load_wait_depth[pid, tid]] != 0/
{
    @firmware_load_wait_us = quantize((timestamp - firmware_load_wait_time[pid, tid, firmware_load_wait_depth[pid, tid]]) / 1000);
    @firmware_load_wait_count = count();
    firmware_load_wait_time[pid, tid, firmware_load_wait_depth[pid, tid]] = 0;
    firmware_load_wait_depth[pid, tid]--;
}

epair:::enqueue
/* @bsdinstruments-predicate */
{
    @epair_outcomes[(int)arg3] = count();
    @epair_queue_depth[arg0] = quantize(arg2);
    @epair_packet_bytes[(int)arg3] = quantize(arg1);
}
