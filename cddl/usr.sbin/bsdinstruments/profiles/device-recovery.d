/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

nvme:::reset-start
/* @bsdinstruments-predicate */
{
    nvme_reset_depth[pid, tid]++;
    nvme_reset_start[pid, tid, nvme_reset_depth[pid, tid]] = timestamp;
}

nvme:::reset-done
/nvme_reset_start[pid, tid, nvme_reset_depth[pid, tid]] != 0/
{
    @nvme_reset_us[(int)arg1] = quantize((timestamp - nvme_reset_start[pid, tid, nvme_reset_depth[pid, tid]]) / 1000);
    nvme_reset_start[pid, tid, nvme_reset_depth[pid, tid]] = 0;
    nvme_reset_depth[pid, tid]--;
}

pci:::power-start
/* @bsdinstruments-predicate */
{
    pci_power_depth[pid, tid]++;
    pci_power_start[pid, tid, pci_power_depth[pid, tid]] = timestamp;
}

pci:::power-done
/pci_power_start[pid, tid, pci_power_depth[pid, tid]] != 0/
{
    @pci_power_us[(int)arg2] = quantize((timestamp - pci_power_start[pid, tid, pci_power_depth[pid, tid]]) / 1000);
    pci_power_start[pid, tid, pci_power_depth[pid, tid]] = 0;
    pci_power_depth[pid, tid]--;
}
