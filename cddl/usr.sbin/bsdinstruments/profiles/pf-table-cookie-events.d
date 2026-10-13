/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FIFTEENTH.
 * Scalar metadata only; opaque identities must not be dereferenced.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling. Kernel work may run outside caller PID.
 */

sdt:::pf-syncookie-active
/* @bsdinstruments-predicate */
{
    @active[(int)arg0, (int)arg1] = count();
}

sdt:::pf-table-begin
/* @bsdinstruments-predicate */
{
    @table_results[probename, (int)arg0, (int)arg2] = count();
    @table_counts[probename] = quantize((int)arg1);
}

sdt:::pf-table-rollback
/* @bsdinstruments-predicate */
{
    @table_results[probename, (int)arg0, (int)arg2] = count();
    @table_counts[probename] = quantize((int)arg1);
}

sdt:::pf-table-commit
/* @bsdinstruments-predicate */
{
    @table_results[probename, (int)arg0, (int)arg2] = count();
    @table_counts[probename] = quantize((int)arg1);
}
