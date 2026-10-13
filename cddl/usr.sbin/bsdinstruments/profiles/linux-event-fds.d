/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

linuxulator*:epoll::eventfd-create
/* @bsdinstruments-predicate */
{
    @eventfd_results[(int)arg1, (int)arg3] = count();
}

linuxulator*:epoll::timerfd-create
/* @bsdinstruments-predicate */
{
    @timerfd_results[(int)arg0, (int)arg1, (int)arg3] = count();
}
