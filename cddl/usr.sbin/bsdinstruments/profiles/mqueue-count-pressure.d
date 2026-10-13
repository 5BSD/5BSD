/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SEVENTEENTH for argument meanings.
 * Scalar arguments only; no payloads, paths or credential data.
 * Start before the workload. Lost events invalidate latency pairing.
 */

sdt:::mqueue-count-limit
/* @bsdinstruments-predicate */
{
    @queue_limits[(int)arg0] = count();
}
