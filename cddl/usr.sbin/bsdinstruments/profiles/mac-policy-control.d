/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

mac_framework:::syscall-start
/* @bsdinstruments-predicate */
{
    mac_syscall_depth[pid, tid]++;
    mac_syscall_start[pid, tid, mac_syscall_depth[pid, tid]] = timestamp;
}

mac_framework:::syscall-done
/mac_syscall_start[pid, tid, mac_syscall_depth[pid, tid]] != 0/
{
    @mac_syscall_us[stringof(arg0), (int)arg1, (int)arg2] = quantize((timestamp - mac_syscall_start[pid, tid, mac_syscall_depth[pid, tid]]) / 1000);
    mac_syscall_start[pid, tid, mac_syscall_depth[pid, tid]] = 0;
    mac_syscall_depth[pid, tid]--;
}

mac_do:::configuration
/* @bsdinstruments-predicate */
{
    @configuration[(int)arg0, (int)arg3] = count();
}

mac_do:::rule-grant
/* @bsdinstruments-predicate */
{
    @grant[(u_int)arg2, (int)arg3] = count();
}
