/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

linuxkpi_work:::delayed-cancel-start
/* @bsdinstruments-predicate */
{
    delayed_cancel_depth[pid, tid]++;
    delayed_cancel_start[pid, tid, delayed_cancel_depth[pid, tid]] = timestamp;
}

linuxkpi_work:::delayed-cancel-done
/delayed_cancel_start[pid, tid, delayed_cancel_depth[pid, tid]] != 0/
{
    @delayed_cancel_us[(int)arg1] = quantize((timestamp - delayed_cancel_start[pid, tid, delayed_cancel_depth[pid, tid]]) / 1000);
    delayed_cancel_start[pid, tid, delayed_cancel_depth[pid, tid]] = 0;
    delayed_cancel_depth[pid, tid]--;
}

linuxkpi_shrinker:::count-start
/* @bsdinstruments-predicate */
{
    shrinker_count_depth[pid, tid]++;
    shrinker_count_start[pid, tid, shrinker_count_depth[pid, tid]] = timestamp;
}

linuxkpi_shrinker:::count-done
/shrinker_count_start[pid, tid, shrinker_count_depth[pid, tid]] != 0/
{
    @shrinker_count_us[0] = quantize((timestamp - shrinker_count_start[pid, tid, shrinker_count_depth[pid, tid]]) / 1000);
    shrinker_count_start[pid, tid, shrinker_count_depth[pid, tid]] = 0;
    shrinker_count_depth[pid, tid]--;
}

linuxkpi_shrinker:::scan-start
/* @bsdinstruments-predicate */
{
    shrinker_scan_depth[pid, tid]++;
    shrinker_scan_start[pid, tid, shrinker_scan_depth[pid, tid]] = timestamp;
}

linuxkpi_shrinker:::scan-done
/shrinker_scan_start[pid, tid, shrinker_scan_depth[pid, tid]] != 0/
{
    @shrinker_scan_us[0] = quantize((timestamp - shrinker_scan_start[pid, tid, shrinker_scan_depth[pid, tid]]) / 1000);
    shrinker_scan_start[pid, tid, shrinker_scan_depth[pid, tid]] = 0;
    shrinker_scan_depth[pid, tid]--;
}

linuxkpi_shrinker:::scan-done
/* @bsdinstruments-predicate */
{
    @scan_results[arg1] = count();
}
