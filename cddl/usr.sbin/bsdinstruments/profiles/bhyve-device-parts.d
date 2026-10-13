/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

bhyve*:::device-part
/* @bsdinstruments-predicate */
{
    @accepted_parts[(uint16_t)arg0, (int)arg3] = count();
    @length[(uint16_t)arg0] = quantize(arg2);
}
