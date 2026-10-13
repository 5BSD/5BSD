/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::wg-handshake-retry
/* @bsdinstruments-predicate */
{
    @handshake_retry = quantize((int)arg1);
}

sdt:::wg-handshake-exhausted
/* @bsdinstruments-predicate */
{
    @handshake_exhausted = count();
}

sdt:::wg-queue-pressure
/* @bsdinstruments-predicate */
{
    @queue_pressure[(int)arg1] = quantize((int)arg2);
}
