/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-THIRD for argument contracts.
 * Start/completion pairs are nested per thread. Missing starts are ignored.
 * Stopping tracing or nonlocal exits can leave unmatched operations.
 */

mac_framework:::hook-start
/* @bsdinstruments-predicate */
{
    self->depth++;
    started[pid, tid, self->depth] = timestamp;

}

mac_framework:::hook-done
/started[pid, tid, self->depth] != 0/
{
    @latency_us[stringof(arg0), stringof(arg1), (int)arg3, (int)arg2] = quantize((timestamp - started[pid, tid, self->depth]) / 1000);

    started[pid, tid, self->depth] = 0;

    self->depth--;
}

/* Reason 1: absent callback; reason 2: boolean short circuit. Not denials. */
mac_framework:::hook-skip
/* @bsdinstruments-predicate */
{
    @skipped[stringof(arg0), stringof(arg1), (int)arg2] = count();
}
