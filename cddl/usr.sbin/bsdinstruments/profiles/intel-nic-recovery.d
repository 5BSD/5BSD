/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::ixgbe-admin-batch
/* @bsdinstruments-predicate */
{
    @admin_requests[(uint32_t)arg1] = count();
    @admin_pass = quantize((u_int)arg2);
}

sdt:::ixgbe-reset-request
/* @bsdinstruments-predicate */
{
    @ix_resets = count();
}

sdt:::igc-fatal-error
/* @bsdinstruments-predicate */
{
    @fatal_status[(uint32_t)arg1, (uint32_t)arg2] = count();
}

sdt:::igc-reset-request
/* @bsdinstruments-predicate */
{
    @igc_resets = count();
}

sdt:::igc-reset-result
/* @bsdinstruments-predicate */
{
    @igc_reset_status[(int)arg1, (int)arg2] = count();
}
