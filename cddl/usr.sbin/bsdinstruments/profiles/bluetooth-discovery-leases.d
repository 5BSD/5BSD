/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

blued*:::discovery-lease-start
/* @bsdinstruments-predicate */
{
    lease_start[pid, arg0, arg1, arg2] = timestamp;
}

blued*:::discovery-lease-done
/lease_start[pid, arg0, arg1, arg2] != 0/
{
    @lease_us[(uint16_t)arg3, (int)arg4] = quantize((timestamp - lease_start[pid, arg0, arg1, arg2]) / 1000);
    lease_start[pid, arg0, arg1, arg2] = 0;
}

blued*:::discovery-deliver
/* @bsdinstruments-predicate */
{
    @delivered[(int)arg2] = count();
    @rssi[(int)arg2] = quantize((int)arg3);
}
