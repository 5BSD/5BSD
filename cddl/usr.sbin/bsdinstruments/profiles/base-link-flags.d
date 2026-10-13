/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-NINTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

linkop*:::operation-start
/* @bsdinstruments-predicate */
{
    linkop_depth[pid, tid]++;
    linkop_time[pid, tid, linkop_depth[pid, tid]] = timestamp;
}

linkop*:::operation-done
/linkop_time[pid, tid, linkop_depth[pid, tid]] != 0/
{
    @linkop_us[arg0, (int)arg2] = quantize((timestamp - linkop_time[pid, tid, linkop_depth[pid, tid]]) / 1000);
    @linkop_count[arg0, (int)arg2] = count();
    linkop_time[pid, tid, linkop_depth[pid, tid]] = 0;
    linkop_depth[pid, tid]--;
}

dirremove*:::operation-start
/* @bsdinstruments-predicate */
{
    dirremove_depth[pid, tid]++;
    dirremove_time[pid, tid, dirremove_depth[pid, tid]] = timestamp;
}

dirremove*:::operation-done
/dirremove_time[pid, tid, dirremove_depth[pid, tid]] != 0/
{
    @dirremove_us[arg0, (int)arg2] = quantize((timestamp - dirremove_time[pid, tid, dirremove_depth[pid, tid]]) / 1000);
    @dirremove_count[arg0, (int)arg2] = count();
    dirremove_time[pid, tid, dirremove_depth[pid, tid]] = 0;
    dirremove_depth[pid, tid]--;
}

fileflags*:::operation-start
/* @bsdinstruments-predicate */
{
    fileflags_depth[pid, tid]++;
    fileflags_time[pid, tid, fileflags_depth[pid, tid]] = timestamp;
}

fileflags*:::operation-done
/fileflags_time[pid, tid, fileflags_depth[pid, tid]] != 0/
{
    @fileflags_us[arg0, (int)arg2] = quantize((timestamp - fileflags_time[pid, tid, fileflags_depth[pid, tid]]) / 1000);
    @fileflags_count[arg0, (int)arg2] = count();
    fileflags_time[pid, tid, fileflags_depth[pid, tid]] = 0;
    fileflags_depth[pid, tid]--;
}
