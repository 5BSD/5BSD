/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

blued*:::iso-stream-alloc, blued*:::iso-stream-unlink
/* @bsdinstruments-predicate */
{
    @lifecycle[probename] = count();
}

blued*:::iso-handoff
/* @bsdinstruments-predicate */
{
    @handoff[(uint16_t)arg1, (int)arg2 < 0] = count();
}

bluetooth:hci:connection:timeout
/* @bsdinstruments-predicate */
{
    @hci_timeout[(int)arg2, (int)arg3] = count();
}
