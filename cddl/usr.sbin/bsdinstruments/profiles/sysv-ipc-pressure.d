/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SEVENTEENTH for argument meanings.
 * Scalar arguments only; no payloads, paths or credential data.
 * Start before the workload. Lost events invalidate latency pairing.
 */

sdt:::sysvshm-limit
/* @bsdinstruments-predicate */
{
    @shared_memory_limits[(int)arg0] = count();
    @requested_bytes[(int)arg0] = quantize((uint64_t)arg1);
}

sdt:::sysvshm-pager-pressure
/* @bsdinstruments-predicate */
{
    @pager_failures[(int)arg1] = count();
    @pager_bytes = quantize((uint64_t)arg0);
}

sdt:::sysvmsg-limit
/* @bsdinstruments-predicate */
{
    @message_queue_limits[(int)arg0] = count();
}

sdt:::sysvsem-limit
/* @bsdinstruments-predicate */
{
    @semaphore_limits[(int)arg0] = count();
    @requested_semaphores[(int)arg0] = quantize((int)arg1);
}
