/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::pfsync-queue-pressure
/* @bsdinstruments-predicate */
{
    @queued_bytes[(int)arg0] = quantize((size_t)arg1);
    @pending_bytes = quantize((size_t)arg2);
}

sdt:::pfsync-bulk-start
/* @bsdinstruments-predicate */
{
    @events[probename] = count();
}

sdt:::pfsync-bulk-status-send
/* @bsdinstruments-predicate */
{
    @bulk_status[(int)arg1] = count();
}

sdt:::pfsync-bulk-retry
/* @bsdinstruments-predicate */
{
    @bulk_attempts[probename] = quantize((int)arg0);
}

sdt:::pfsync-bulk-failed
/* @bsdinstruments-predicate */
{
    @bulk_attempts[probename] = quantize((int)arg0);
}
