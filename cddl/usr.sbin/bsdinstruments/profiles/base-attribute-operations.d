/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

attrtool*:::delete-start
/* @bsdinstruments-predicate */
{
    attrtool_delete_depth[pid, tid]++;
    attrtool_delete_time[pid, tid, attrtool_delete_depth[pid, tid]] = timestamp;
}

attrtool*:::delete-done
/attrtool_delete_time[pid, tid, attrtool_delete_depth[pid, tid]] != 0/
{
    @attrtool_delete_us[(int)arg3] = quantize((timestamp - attrtool_delete_time[pid, tid, attrtool_delete_depth[pid, tid]]) / 1000);
    @attrtool_delete_count[(int)arg3] = count();
    attrtool_delete_time[pid, tid, attrtool_delete_depth[pid, tid]] = 0;
    attrtool_delete_depth[pid, tid]--;
}

attrtool*:::set-start
/* @bsdinstruments-predicate */
{
    attrtool_set_depth[pid, tid]++;
    attrtool_set_time[pid, tid, attrtool_set_depth[pid, tid]] = timestamp;
}

attrtool*:::set-done
/attrtool_set_time[pid, tid, attrtool_set_depth[pid, tid]] != 0/
{
    @attrtool_set_us[(int)arg5] = quantize((timestamp - attrtool_set_time[pid, tid, attrtool_set_depth[pid, tid]]) / 1000);
    @attrtool_set_count[(int)arg5] = count();
    attrtool_set_time[pid, tid, attrtool_set_depth[pid, tid]] = 0;
    attrtool_set_depth[pid, tid]--;
}

attrtool*:::list-start
/* @bsdinstruments-predicate */
{
    attrtool_list_depth[pid, tid]++;
    attrtool_list_time[pid, tid, attrtool_list_depth[pid, tid]] = timestamp;
}

attrtool*:::list-done
/attrtool_list_time[pid, tid, attrtool_list_depth[pid, tid]] != 0/
{
    @attrtool_list_us[(int)arg5] = quantize((timestamp - attrtool_list_time[pid, tid, attrtool_list_depth[pid, tid]]) / 1000);
    @attrtool_list_count[(int)arg5] = count();
    attrtool_list_time[pid, tid, attrtool_list_depth[pid, tid]] = 0;
    attrtool_list_depth[pid, tid]--;
}

attrtool*:::get-start
/* @bsdinstruments-predicate */
{
    attrtool_get_depth[pid, tid]++;
    attrtool_get_time[pid, tid, attrtool_get_depth[pid, tid]] = timestamp;
}

attrtool*:::get-done
/attrtool_get_time[pid, tid, attrtool_get_depth[pid, tid]] != 0/
{
    @attrtool_get_us[(int)arg5] = quantize((timestamp - attrtool_get_time[pid, tid, attrtool_get_depth[pid, tid]]) / 1000);
    @attrtool_get_count[(int)arg5] = count();
    attrtool_get_time[pid, tid, attrtool_get_depth[pid, tid]] = 0;
    attrtool_get_depth[pid, tid]--;
}
