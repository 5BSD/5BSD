/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts and limits: tools/test/system-tracing/COVERAGE-FOURTH.
 * Durations are elapsed microseconds, including blocking and callbacks.
 * Identities are never dereferenced. Start tracing before the workload.
 * Missing completions (termination, cancellation or nonlocal exits) are not
 * success. Per-thread depth handles synchronous nesting; lost events can
 * invalidate pairing. User providers require MK_DTRACE=yes.
 */

cpcopy*:::transfer-start
/* @bsdinstruments-predicate */
{
    cp_transfer_depth[pid, tid]++;
    cp_transfer_start[pid, tid, cp_transfer_depth[pid, tid]] = timestamp;
}

cpcopy*:::transfer-done
/cp_transfer_start[pid, tid, cp_transfer_depth[pid, tid]] != 0/
{
    @cp_transfer_us[(int)arg3] = quantize((timestamp - cp_transfer_start[pid, tid, cp_transfer_depth[pid, tid]]) / 1000);
    cp_transfer_start[pid, tid, cp_transfer_depth[pid, tid]] = 0;
    cp_transfer_depth[pid, tid]--;
}

installcopy*:::range-start
/* @bsdinstruments-predicate */
{
    install_range_depth[pid, tid]++;
    install_range_start[pid, tid, install_range_depth[pid, tid]] = timestamp;
}

installcopy*:::range-done
/install_range_start[pid, tid, install_range_depth[pid, tid]] != 0/
{
    @install_range_us[(int)arg3] = quantize((timestamp - install_range_start[pid, tid, install_range_depth[pid, tid]]) / 1000);
    install_range_start[pid, tid, install_range_depth[pid, tid]] = 0;
    install_range_depth[pid, tid]--;
}

installcopy*:::sync-start
/* @bsdinstruments-predicate */
{
    install_sync_depth[pid, tid]++;
    install_sync_start[pid, tid, install_sync_depth[pid, tid]] = timestamp;
}

installcopy*:::sync-done
/install_sync_start[pid, tid, install_sync_depth[pid, tid]] != 0/
{
    @install_sync_us[(int)arg1] = quantize((timestamp - install_sync_start[pid, tid, install_sync_depth[pid, tid]]) / 1000);
    install_sync_start[pid, tid, install_sync_depth[pid, tid]] = 0;
    install_sync_depth[pid, tid]--;
}

cpcopy*:::fallback
/* @bsdinstruments-predicate */
{
    @cp_fallback[(int)arg2] = count();
}

installcopy*:::fallback
/* @bsdinstruments-predicate */
{
    @install_fallback[(int)arg2] = count();
}
