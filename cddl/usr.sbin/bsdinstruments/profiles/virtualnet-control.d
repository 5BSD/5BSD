/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

ifclone:::create-start
/* @bsdinstruments-predicate */
{
    ifclone_depth[pid, tid]++;
    ifclone_time[pid, tid, ifclone_depth[pid, tid]] = timestamp;
}

ifclone:::create-done
/ifclone_time[pid, tid, ifclone_depth[pid, tid]] != 0/
{
    @ifclone_us[(int)arg1] = quantize((timestamp - ifclone_time[pid, tid, ifclone_depth[pid, tid]]) / 1000);
    @ifclone_count[(int)arg1] = count();
    ifclone_time[pid, tid, ifclone_depth[pid, tid]] = 0;
    ifclone_depth[pid, tid]--;
}

bridge:::control-start
/* @bsdinstruments-predicate */
{
    bridgectl_depth[pid, tid]++;
    bridgectl_time[pid, tid, bridgectl_depth[pid, tid]] = timestamp;
}

bridge:::control-done
/bridgectl_time[pid, tid, bridgectl_depth[pid, tid]] != 0/
{
    @bridgectl_us[(int)arg2] = quantize((timestamp - bridgectl_time[pid, tid, bridgectl_depth[pid, tid]]) / 1000);
    @bridgectl_count[(int)arg2] = count();
    bridgectl_time[pid, tid, bridgectl_depth[pid, tid]] = 0;
    bridgectl_depth[pid, tid]--;
}

lagg:::port-start
/* @bsdinstruments-predicate */
{
    laggport_depth[pid, tid]++;
    laggport_time[pid, tid, laggport_depth[pid, tid]] = timestamp;
}

lagg:::port-done
/laggport_time[pid, tid, laggport_depth[pid, tid]] != 0/
{
    @laggport_us[(int)arg3] = quantize((timestamp - laggport_time[pid, tid, laggport_depth[pid, tid]]) / 1000);
    @laggport_count[(int)arg3] = count();
    laggport_time[pid, tid, laggport_depth[pid, tid]] = 0;
    laggport_depth[pid, tid]--;
}

vlan:::configure-start
/* @bsdinstruments-predicate */
{
    vlanconfig_depth[pid, tid]++;
    vlanconfig_time[pid, tid, vlanconfig_depth[pid, tid]] = timestamp;
}

vlan:::configure-done
/vlanconfig_time[pid, tid, vlanconfig_depth[pid, tid]] != 0/
{
    @vlanconfig_us[(int)arg3] = quantize((timestamp - vlanconfig_time[pid, tid, vlanconfig_depth[pid, tid]]) / 1000);
    @vlanconfig_count[(int)arg3] = count();
    vlanconfig_time[pid, tid, vlanconfig_depth[pid, tid]] = 0;
    vlanconfig_depth[pid, tid]--;
}
