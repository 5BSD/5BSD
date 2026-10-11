/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-THIRD for argument contracts.
 * Start/completion pairs are nested per thread. Missing starts are ignored.
 * Stopping tracing or nonlocal exits can leave unmatched operations.
 */

capsicum:::limit-start
/* @bsdinstruments-predicate */
{
    self->depth++;
    started[pid, tid, self->depth] = timestamp;

}

capsicum:::limit-done
/started[pid, tid, self->depth] != 0/
{
    @latency_us[stringof(arg0), (int)arg1, (int)arg2] = quantize((timestamp - started[pid, tid, self->depth]) / 1000);

    started[pid, tid, self->depth] = 0;

    self->depth--;
}
