/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

mqueue:::send-block
/* @bsdinstruments-predicate */
{
    mqsend_depth[pid, tid]++;
    mqsend_time[pid, tid, mqsend_depth[pid, tid]] = timestamp;
}

mqueue:::send-wake
/mqsend_time[pid, tid, mqsend_depth[pid, tid]] != 0/
{
    @mqsend_us[(int)arg1] = quantize((timestamp - mqsend_time[pid, tid, mqsend_depth[pid, tid]]) / 1000);
    @mqsend_count[(int)arg1] = count();
    mqsend_time[pid, tid, mqsend_depth[pid, tid]] = 0;
    mqsend_depth[pid, tid]--;
}

mqueue:::receive-block
/* @bsdinstruments-predicate */
{
    mqrecv_depth[pid, tid]++;
    mqrecv_time[pid, tid, mqrecv_depth[pid, tid]] = timestamp;
}

mqueue:::receive-wake
/mqrecv_time[pid, tid, mqrecv_depth[pid, tid]] != 0/
{
    @mqrecv_us[(int)arg1] = quantize((timestamp - mqrecv_time[pid, tid, mqrecv_depth[pid, tid]]) / 1000);
    @mqrecv_count[(int)arg1] = count();
    mqrecv_time[pid, tid, mqrecv_depth[pid, tid]] = 0;
    mqrecv_depth[pid, tid]--;
}

sysvmsg:::msgsnd-block
/* @bsdinstruments-predicate */
{
    msgsend_depth[pid, tid]++;
    msgsend_time[pid, tid, msgsend_depth[pid, tid]] = timestamp;
}

sysvmsg:::msgsnd-wake
/msgsend_time[pid, tid, msgsend_depth[pid, tid]] != 0/
{
    @msgsend_us[(int)arg1] = quantize((timestamp - msgsend_time[pid, tid, msgsend_depth[pid, tid]]) / 1000);
    @msgsend_count[(int)arg1] = count();
    msgsend_time[pid, tid, msgsend_depth[pid, tid]] = 0;
    msgsend_depth[pid, tid]--;
}

sysvmsg:::msgrcv-block
/* @bsdinstruments-predicate */
{
    msgrecv_depth[pid, tid]++;
    msgrecv_time[pid, tid, msgrecv_depth[pid, tid]] = timestamp;
}

sysvmsg:::msgrcv-wake
/msgrecv_time[pid, tid, msgrecv_depth[pid, tid]] != 0/
{
    @msgrecv_us[(int)arg1] = quantize((timestamp - msgrecv_time[pid, tid, msgrecv_depth[pid, tid]]) / 1000);
    @msgrecv_count[(int)arg1] = count();
    msgrecv_time[pid, tid, msgrecv_depth[pid, tid]] = 0;
    msgrecv_depth[pid, tid]--;
}

sysvsem:::semop-block
/* @bsdinstruments-predicate */
{
    semwait_depth[pid, tid]++;
    semwait_time[pid, tid, semwait_depth[pid, tid]] = timestamp;
}

sysvsem:::semop-wake
/semwait_time[pid, tid, semwait_depth[pid, tid]] != 0/
{
    @semwait_us[(int)arg1] = quantize((timestamp - semwait_time[pid, tid, semwait_depth[pid, tid]]) / 1000);
    @semwait_count[(int)arg1] = count();
    semwait_time[pid, tid, semwait_depth[pid, tid]] = 0;
    semwait_depth[pid, tid]--;
}

mqueue:::send-wake,
mqueue:::receive-wake
/* @bsdinstruments-predicate */
{
    @queue_depth[probename] = quantize((long)arg2);
}
