/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-EIGHTEENTH for argument semantics.
 * Scalar arguments only, no payloads, addresses or credentials.
 * Start before the workload; dropped events invalidate latency pairing.
 * Elapsed times include scheduling and reacquiring existing locks.
 */

sdt:::sockbuf-reserve-failure
/* @bsdinstruments-predicate */
{
    @reserve_failures[(int)arg1, (int)arg2] = count();
    @requested_bytes[(int)arg1, (int)arg2] = quantize((uint64_t)arg3);
    @limits[(int)arg1, (int)arg2, (uint64_t)arg4] = count();
}

sdt:::sockbuf-listen-limit
/* @bsdinstruments-predicate */
{
    @listener_limits[(int)arg1] = count();
    @listener_bytes[(int)arg1] = quantize((uint_t)arg2);
}

sdt:::socket-alloc-failure
/* @bsdinstruments-predicate */
{
    @allocation_failures[(int)arg0] = count();
}
