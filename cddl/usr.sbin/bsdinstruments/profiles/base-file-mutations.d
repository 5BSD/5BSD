/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

removeio*:::operation-start
/* @bsdinstruments-predicate */
{
    removeio_depth[pid, tid]++;
    removeio_time[pid, tid, removeio_depth[pid, tid]] = timestamp;
}

removeio*:::operation-done
/removeio_time[pid, tid, removeio_depth[pid, tid]] != 0/
{
    @removeio_us[(int)arg0, (int)arg2] = quantize((timestamp - removeio_time[pid, tid, removeio_depth[pid, tid]]) / 1000);
    @removeio_count[(int)arg0, (int)arg2] = count();
    removeio_time[pid, tid, removeio_depth[pid, tid]] = 0;
    removeio_depth[pid, tid]--;
}

modechange*:::operation-start
/* @bsdinstruments-predicate */
{
    modechange_depth[pid, tid]++;
    modechange_time[pid, tid, modechange_depth[pid, tid]] = timestamp;
}

modechange*:::operation-done
/modechange_time[pid, tid, modechange_depth[pid, tid]] != 0/
{
    @modechange_us[(int)arg0, (int)arg2] = quantize((timestamp - modechange_time[pid, tid, modechange_depth[pid, tid]]) / 1000);
    @modechange_count[(int)arg0, (int)arg2] = count();
    modechange_time[pid, tid, modechange_depth[pid, tid]] = 0;
    modechange_depth[pid, tid]--;
}

dircreate*:::operation-start
/* @bsdinstruments-predicate */
{
    dircreate_depth[pid, tid]++;
    dircreate_time[pid, tid, dircreate_depth[pid, tid]] = timestamp;
}

dircreate*:::operation-done
/dircreate_time[pid, tid, dircreate_depth[pid, tid]] != 0/
{
    @dircreate_us[(int)arg0, (int)arg2] = quantize((timestamp - dircreate_time[pid, tid, dircreate_depth[pid, tid]]) / 1000);
    @dircreate_count[(int)arg0, (int)arg2] = count();
    dircreate_time[pid, tid, dircreate_depth[pid, tid]] = 0;
    dircreate_depth[pid, tid]--;
}

resizeio*:::operation-start
/* @bsdinstruments-predicate */
{
    resizeio_depth[pid, tid]++;
    resizeio_time[pid, tid, resizeio_depth[pid, tid]] = timestamp;
}

resizeio*:::operation-done
/resizeio_time[pid, tid, resizeio_depth[pid, tid]] != 0/
{
    @resizeio_us[(int)arg1, (int)arg3] = quantize((timestamp - resizeio_time[pid, tid, resizeio_depth[pid, tid]]) / 1000);
    @resizeio_count[(int)arg1, (int)arg3] = count();
    resizeio_time[pid, tid, resizeio_depth[pid, tid]] = 0;
    resizeio_depth[pid, tid]--;
}
