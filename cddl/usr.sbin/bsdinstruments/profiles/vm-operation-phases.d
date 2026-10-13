/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and exclusions: tools/test/system-tracing/COVERAGE-THIRTEENTH.
 * Start before the workload. Event loss invalidates pairing. Latency includes
 * preemption. PID filtering selects executing context, not a target process.
 * No pointer dereferences or payload reads. VM results are KERN_* codes.
 */

vm:::sync-map-start
/* @bsdinstruments-predicate */
{
    vm_sync_map_depth[pid, tid]++;
    vm_sync_map_time[pid, tid, vm_sync_map_depth[pid, tid]] = timestamp;
}

vm:::sync-map-done
/vm_sync_map_time[pid, tid, vm_sync_map_depth[pid, tid]] != 0/
{
    @vm_sync_map_us[(int)arg0] = quantize((timestamp - vm_sync_map_time[pid, tid, vm_sync_map_depth[pid, tid]]) / 1000);
    @vm_sync_map_count[(int)arg0] = count();
    vm_sync_map_time[pid, tid, vm_sync_map_depth[pid, tid]] = 0;
    vm_sync_map_depth[pid, tid]--;
}

vm:::wire-map-start
/* @bsdinstruments-predicate */
{
    vm_wire_map_depth[pid, tid]++;
    vm_wire_map_time[pid, tid, vm_wire_map_depth[pid, tid]] = timestamp;
}

vm:::wire-map-done
/vm_wire_map_time[pid, tid, vm_wire_map_depth[pid, tid]] != 0/
{
    @vm_wire_map_us[(int)arg0] = quantize((timestamp - vm_wire_map_time[pid, tid, vm_wire_map_depth[pid, tid]]) / 1000);
    @vm_wire_map_count[(int)arg0] = count();
    vm_wire_map_time[pid, tid, vm_wire_map_depth[pid, tid]] = 0;
    vm_wire_map_depth[pid, tid]--;
}
