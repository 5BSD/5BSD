/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SEVENTEENTH for argument meanings.
 * Scalar arguments only; no payloads, paths or credential data.
 * Start before the workload. Lost events invalidate latency pairing.
 */

sdt:::pipe-buffer-pressure
/* @bsdinstruments-predicate */
{
    @failures[(int)arg1] = count();
    @requested_bytes[(int)arg1] = quantize((int)arg2);
}

sdt:::pipe-buffer-retry
/* @bsdinstruments-predicate */
{
    @fallback_sizes[(int)arg1, (int)arg2] = count();
}
