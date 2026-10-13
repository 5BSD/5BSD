/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

vm:::fault-trap-start
/* @bsdinstruments-predicate */
{
    fault_trap_depth[pid, tid]++;
    fault_trap_start[pid, tid, fault_trap_depth[pid, tid]] = timestamp;
}

vm:::fault-trap-done
/fault_trap_start[pid, tid, fault_trap_depth[pid, tid]] != 0/
{
    @fault_trap_us[(int)arg1] = quantize((timestamp - fault_trap_start[pid, tid, fault_trap_depth[pid, tid]]) / 1000);
    fault_trap_start[pid, tid, fault_trap_depth[pid, tid]] = 0;
    fault_trap_depth[pid, tid]--;
}
