/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-THIRD for argument contracts.
 * Start/completion pairs are nested per thread. Missing starts are ignored.
 * Stopping tracing or nonlocal exits can leave unmatched operations.
 */

rtldtrace*:::dlopen-start
/* @bsdinstruments-predicate */
{
    self->depth++;
    started[pid, tid, self->depth] = timestamp;
    library[pid, tid, self->depth] = arg0 ? copyinstr(arg0) : (arg1 == -1 ? "<main>" : "<fdlopen>");
    @requests[library[pid, tid, self->depth], (int)arg1, (int)arg2] = count();
}

rtldtrace*:::dlopen-done
/started[pid, tid, self->depth] != 0/
{
    @latency_us[library[pid, tid, self->depth], arg3 == 0] = quantize((timestamp - started[pid, tid, self->depth]) / 1000);

    started[pid, tid, self->depth] = 0;
    library[pid, tid, self->depth] = 0;
    self->depth--;
}
