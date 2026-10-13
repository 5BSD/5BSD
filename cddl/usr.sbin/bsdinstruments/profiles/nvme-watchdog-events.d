/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::nvme-watchdog-reset
/* @bsdinstruments-predicate */
{
    @reset_status[(uint32_t)arg1] = count();
}

sdt:::nvme-request-expired
/* @bsdinstruments-predicate */
{
    @expired_abort_sent[(int)arg2] = count();
}

sdt:::nvme-abort-pressure
/* @bsdinstruments-predicate */
{
    @abort_pressure[(int)arg1] = count();
}

sdt:::nvme-abort-sent
/* @bsdinstruments-predicate */
{
    @events[probename] = count();
}

sdt:::nvme-queued-resubmit
/* @bsdinstruments-predicate */
{
    @resubmit_retries[(int)arg1] = quantize((int)arg2);
}
