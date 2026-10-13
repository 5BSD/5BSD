/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

mac_capability_coalition:::cleanup-status
/* @bsdinstruments-predicate */
{
    @cleanup[(uint32_t)arg1, (int)arg2] = count();
}

mac_capability_coalition:::waiter-create, mac_capability_coalition:::waiter-revoke
/* @bsdinstruments-predicate */
{
    @waiters[probename] = count();
}

mac_capability_coalition:::waiter-notify
/* @bsdinstruments-predicate */
{
    @notified[(uint32_t)arg2] = count();
}
