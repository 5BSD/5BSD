/* SPDX-License-Identifier: BSD-2-Clause
 * Contracts: tools/test/system-tracing/COVERAGE-EIGHTH.
 * Synchronous per-thread pairs; timestamps include preemption.
 * Start before workload. Lost events invalidate pairing. No pointer dereference.
 * PID filters select executing context. Probe args contain no payloads/paths.
 */

usb:::fifo-wait-start
/* @bsdinstruments-predicate */
{
    usbfifo_depth[pid, tid]++;
    usbfifo_time[pid, tid, usbfifo_depth[pid, tid]] = timestamp;
}

usb:::fifo-wait-done
/usbfifo_time[pid, tid, usbfifo_depth[pid, tid]] != 0/
{
    @usbfifo_us[(int)arg1] = quantize((timestamp - usbfifo_time[pid, tid, usbfifo_depth[pid, tid]]) / 1000);
    @usbfifo_count[(int)arg1] = count();
    usbfifo_time[pid, tid, usbfifo_depth[pid, tid]] = 0;
    usbfifo_depth[pid, tid]--;
}

geom:::control-start
/* @bsdinstruments-predicate */
{
    geomctl_depth[pid, tid]++;
    geomctl_time[pid, tid, geomctl_depth[pid, tid]] = timestamp;
}

geom:::control-done
/geomctl_time[pid, tid, geomctl_depth[pid, tid]] != 0/
{
    @geomctl_us[(int)arg1] = quantize((timestamp - geomctl_time[pid, tid, geomctl_depth[pid, tid]]) / 1000);
    @geomctl_count[(int)arg1] = count();
    geomctl_time[pid, tid, geomctl_depth[pid, tid]] = 0;
    geomctl_depth[pid, tid]--;
}
