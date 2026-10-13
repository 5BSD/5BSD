/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

tuntap:::read-wait-start
/* @bsdinstruments-predicate */
{
    tunread_depth[pid, tid]++;
    tunread_time[pid, tid, tunread_depth[pid, tid]] = timestamp;
}

tuntap:::read-wait-done
/tunread_time[pid, tid, tunread_depth[pid, tid]] != 0/
{
    @tunread_us[(int)arg1] = quantize((timestamp - tunread_time[pid, tid, tunread_depth[pid, tid]]) / 1000);
    @tunread_count[(int)arg1] = count();
    tunread_time[pid, tid, tunread_depth[pid, tid]] = 0;
    tunread_depth[pid, tid]--;
}

tty:::control-start
/* @bsdinstruments-predicate */
{
    ttyctl_depth[pid, tid]++;
    ttyctl_time[pid, tid, ttyctl_depth[pid, tid]] = timestamp;
}

tty:::control-done
/ttyctl_time[pid, tid, ttyctl_depth[pid, tid]] != 0/
{
    @ttyctl_us[arg1, (int)arg2] = quantize((timestamp - ttyctl_time[pid, tid, ttyctl_depth[pid, tid]]) / 1000);
    @ttyctl_count[arg1, (int)arg2] = count();
    ttyctl_time[pid, tid, ttyctl_depth[pid, tid]] = 0;
    ttyctl_depth[pid, tid]--;
}
