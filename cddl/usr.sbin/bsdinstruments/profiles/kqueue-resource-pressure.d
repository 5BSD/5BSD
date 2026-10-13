/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SEVENTEENTH for argument meanings.
 * Scalar arguments only; no payloads, paths or credential data.
 * Start before the workload. Lost events invalidate latency pairing.
 */

sdt:::kqueue-timer-limit
/* @bsdinstruments-predicate */
{
    @timer_limits[(uint_t)arg1] = count();
}

sdt:::kqueue-expand-pressure
/* @bsdinstruments-predicate */
{
    @storage_failures[(int)arg1, (int)arg2] = count();
}
