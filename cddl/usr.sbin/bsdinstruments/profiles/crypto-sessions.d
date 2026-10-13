/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

opencrypto:::session-start
/* @bsdinstruments-predicate */
{
    crypto_session_depth[pid, tid]++;
    crypto_session_start[pid, tid, crypto_session_depth[pid, tid]] = timestamp;
}

opencrypto:::session-done
/crypto_session_start[pid, tid, crypto_session_depth[pid, tid]] != 0/
{
    @crypto_session_us[(int)arg1] = quantize((timestamp - crypto_session_start[pid, tid, crypto_session_depth[pid, tid]]) / 1000);
    crypto_session_start[pid, tid, crypto_session_depth[pid, tid]] = 0;
    crypto_session_depth[pid, tid]--;
}
