/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

mdio:::control-start
/* @bsdinstruments-predicate */
{
    mdcontrol_depth[pid, tid]++;
    mdcontrol_time[pid, tid, mdcontrol_depth[pid, tid]] = timestamp;
}

mdio:::control-done
/mdcontrol_time[pid, tid, mdcontrol_depth[pid, tid]] != 0/
{
    @mdcontrol_us[arg0, (int)arg1] = quantize((timestamp - mdcontrol_time[pid, tid, mdcontrol_depth[pid, tid]]) / 1000);
    @mdcontrol_count[arg0, (int)arg1] = count();
    mdcontrol_time[pid, tid, mdcontrol_depth[pid, tid]] = 0;
    mdcontrol_depth[pid, tid]--;
}
