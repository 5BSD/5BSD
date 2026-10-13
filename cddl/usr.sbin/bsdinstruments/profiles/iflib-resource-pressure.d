/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::iflib-dma-failure
/* @bsdinstruments-predicate */
{
    @dma_errors[(int)arg1, (int)arg2] = count();
}

sdt:::iflib-rx-pressure
/* @bsdinstruments-predicate */
{
    @rx_errors[(int)arg1, (int)arg2] = count();
}

sdt:::iflib-tx-pressure
/* @bsdinstruments-predicate */
{
    @tx_backpressure[(int)arg1] = count();
}
