/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-FOURTEENTH.
 * No paths, payloads, credentials or pointer dereferences. Start before the
 * workload; event loss invalidates pairing. Elapsed time includes preemption.
 * processquery's final argument is an unavailable flag, not errno.
 */

modulequery*:::operation-start
/* @bsdinstruments-predicate */
{
    modulequery_operation_depth[pid, tid]++;
    modulequery_operation_time[pid, tid, modulequery_operation_depth[pid, tid]] = timestamp;
}

modulequery*:::operation-done
/modulequery_operation_time[pid, tid, modulequery_operation_depth[pid, tid]] != 0/
{
    @modulequery_operation_us[(int)arg2] = quantize((timestamp - modulequery_operation_time[pid, tid, modulequery_operation_depth[pid, tid]]) / 1000);
    @modulequery_operation_count[(int)arg2] = count();
    modulequery_operation_time[pid, tid, modulequery_operation_depth[pid, tid]] = 0;
    modulequery_operation_depth[pid, tid]--;
}

envquery*:::operation-start
/* @bsdinstruments-predicate */
{
    envquery_operation_depth[pid, tid]++;
    envquery_operation_time[pid, tid, envquery_operation_depth[pid, tid]] = timestamp;
}

envquery*:::operation-done
/envquery_operation_time[pid, tid, envquery_operation_depth[pid, tid]] != 0/
{
    @envquery_operation_us[(int)arg3] = quantize((timestamp - envquery_operation_time[pid, tid, envquery_operation_depth[pid, tid]]) / 1000);
    @envquery_operation_count[(int)arg3] = count();
    envquery_operation_time[pid, tid, envquery_operation_depth[pid, tid]] = 0;
    envquery_operation_depth[pid, tid]--;
}

processquery*:::operation-start
/* @bsdinstruments-predicate */
{
    processquery_operation_depth[pid, tid]++;
    processquery_operation_time[pid, tid, processquery_operation_depth[pid, tid]] = timestamp;
}

processquery*:::operation-done
/processquery_operation_time[pid, tid, processquery_operation_depth[pid, tid]] != 0/
{
    @processquery_operation_us[(int)arg2] = quantize((timestamp - processquery_operation_time[pid, tid, processquery_operation_depth[pid, tid]]) / 1000);
    @processquery_operation_count[(int)arg2] = count();
    processquery_operation_time[pid, tid, processquery_operation_depth[pid, tid]] = 0;
    processquery_operation_depth[pid, tid]--;
}

vmquery*:::operation-start
/* @bsdinstruments-predicate */
{
    vmquery_operation_depth[pid, tid]++;
    vmquery_operation_time[pid, tid, vmquery_operation_depth[pid, tid]] = timestamp;
}

vmquery*:::operation-done
/vmquery_operation_time[pid, tid, vmquery_operation_depth[pid, tid]] != 0/
{
    @vmquery_operation_us[(int)arg2] = quantize((timestamp - vmquery_operation_time[pid, tid, vmquery_operation_depth[pid, tid]]) / 1000);
    @vmquery_operation_count[(int)arg2] = count();
    vmquery_operation_time[pid, tid, vmquery_operation_depth[pid, tid]] = 0;
    vmquery_operation_depth[pid, tid]--;
}
