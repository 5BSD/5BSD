/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::pci-hotplug-start
/* @bsdinstruments-predicate */
{
    pci_hotplug_depth[pid, tid]++;
    pci_hotplug_time[pid, tid, pci_hotplug_depth[pid, tid]] = timestamp;
}

sdt:::pci-hotplug-done
/pci_hotplug_time[pid, tid, pci_hotplug_depth[pid, tid]] != 0/
{
    @pci_hotplug_us = quantize((timestamp - pci_hotplug_time[pid, tid, pci_hotplug_depth[pid, tid]]) / 1000);
    @child_present[(int)arg1] = count();
    pci_hotplug_time[pid, tid, pci_hotplug_depth[pid, tid]] = 0;
    pci_hotplug_depth[pid, tid]--;
}

sdt:::pci-hotplug-watchdog
/* @bsdinstruments-predicate */
{ @watchdog_status[(int)arg1, (int)arg2] = count(); }
