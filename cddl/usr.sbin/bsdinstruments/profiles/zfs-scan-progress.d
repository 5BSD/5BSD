/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::scan-checkpoint
/* @bsdinstruments-predicate */
{
    @events[probename] = count();
}

sdt:::scan-state
/* @bsdinstruments-predicate */
{
    @scan_states[(uint64_t)arg1] = count();
}

sdt:::scan-done
/* @bsdinstruments-predicate */
{
    @scan_done_states[(uint64_t)arg1] = count();
    @scan_errors = quantize((uint64_t)arg2);
}

sdt:::scan-paused
/* @bsdinstruments-predicate */
{
    @scan_paused[(int)arg1] = count();
}
