/* SPDX-License-Identifier: BSD-2-Clause
 * See tools/test/system-tracing/COVERAGE-SIXTEENTH for argument semantics.
 * No pointer dereferences, payloads, paths, addresses or credentials.
 * Start before the workload. Lost events invalidate latency pairing.
 * Elapsed times include scheduling; PID filters omit unrelated worker threads.
 */

sdt:::ath-deferred-reset-start
/* @bsdinstruments-predicate */
{
    ath_reset_depth[pid, tid]++;
    ath_reset_time[pid, tid, ath_reset_depth[pid, tid]] = timestamp;
}

sdt:::ath-deferred-reset-done
/ath_reset_time[pid, tid, ath_reset_depth[pid, tid]] != 0/
{
    @ath_reset_us = quantize((timestamp - ath_reset_time[pid, tid, ath_reset_depth[pid, tid]]) / 1000);
    @ath_reset_status[(int)arg1] = count();
    ath_reset_time[pid, tid, ath_reset_depth[pid, tid]] = 0;
    ath_reset_depth[pid, tid]--;
}

sdt:::rtwn-init-start
/* @bsdinstruments-predicate */
{
    rtwn_init_depth[pid, tid]++;
    rtwn_init_time[pid, tid, rtwn_init_depth[pid, tid]] = timestamp;
}

sdt:::rtwn-init-done
/rtwn_init_time[pid, tid, rtwn_init_depth[pid, tid]] != 0/
{
    @rtwn_init_us = quantize((timestamp - rtwn_init_time[pid, tid, rtwn_init_depth[pid, tid]]) / 1000);
    @rtwn_init_status[(int)arg1] = count();
    rtwn_init_time[pid, tid, rtwn_init_depth[pid, tid]] = 0;
    rtwn_init_depth[pid, tid]--;
}

sdt:::ath-watchdog-expired
/* @bsdinstruments-predicate */
{
    @watchdogs[probename] = count();
}

sdt:::rtwn-watchdog-expired
/* @bsdinstruments-predicate */
{
    @watchdogs[probename] = count();
}

sdt:::wlan-auth-retry
/* @bsdinstruments-predicate */
{
    @auth_retry_reason[(int)arg1] = count();
}

sdt:::wlan-association-failed
/* @bsdinstruments-predicate */
{
    @association_failure[(int)arg1, (int)arg2] = count();
}
