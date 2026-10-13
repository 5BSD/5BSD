/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

veriexec:::fingerprint-start
/* @bsdinstruments-predicate */
{
    fingerprint_depth[pid, tid]++;
    fingerprint_start[pid, tid, fingerprint_depth[pid, tid]] = timestamp;
}

veriexec:::fingerprint-done
/fingerprint_start[pid, tid, fingerprint_depth[pid, tid]] != 0/
{
    @fingerprint_us[(int)arg2] = quantize((timestamp - fingerprint_start[pid, tid, fingerprint_depth[pid, tid]]) / 1000);
    fingerprint_start[pid, tid, fingerprint_depth[pid, tid]] = 0;
    fingerprint_depth[pid, tid]--;
}

veriexec:::fingerprint-status
/* @bsdinstruments-predicate */
{
    @cached_status[(int)arg1] = count();
}
