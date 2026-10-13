/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-SEVENTH.
 * Pointers are opaque. Elapsed time includes blocking and preemption.
 * Start before the workload; drops or nonlocal exits invalidate pairing.
 * PID filters select executing context, not the initiating workload.
 */

bhyve*:::migration-progress
/* @bsdinstruments-predicate */
{
    @rounds[(uint32_t)arg0, (int)arg4] = count();
    @bytes[(uint32_t)arg0] = quantize(arg2);
    @dirty_pages[(uint32_t)arg0] = quantize(arg3);
}

bhyve*:::migration-send
/* @bsdinstruments-predicate */
{
    @send_result[(uint16_t)arg0, (int)arg3] = count();
}
