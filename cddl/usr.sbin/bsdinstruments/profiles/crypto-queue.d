/* SPDX-License-Identifier: BSD-2-Clause
 * Semantic DTrace coverage: see tools/test/system-tracing/COVERAGE-THIRD.
 * Durations are microseconds; pointers are identities, never dereferenced.
 * Start tracing before the workload. Missing starts are ignored. Nesting is
 * tracked per PID/thread; swap and crypto completions correlate by object.
 * Termination/nonlocal exits may leave an unfinished operation: a missing
 * completion is not success. Histogram keys follow the documented arguments.
 * Userspace provider names include a PID suffix; compile with MK_DTRACE=yes.
 */

crypto:::submit
/* @bsdinstruments-predicate */
{
    request_start[arg0] = timestamp;
}

crypto:::complete
/request_start[arg0] != 0/
{
    @request_us[(int)arg1] = quantize((timestamp - request_start[arg0]) / 1000);
    request_start[arg0] = 0;
}

crypto:::submit-error
/request_start[arg0] != 0/
{
    @submit_errors[(int)arg1] = count();
    request_start[arg0] = 0;
}

crypto:::defer
/* @bsdinstruments-predicate */
{
    @deferred[0] = count();
}
