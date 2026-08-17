/*
 * ZFS I/O latency — service time histograms.
 *
 * Measures the time between zio_execute entry and zio_done
 * entry in the ZFS I/O pipeline. Aggregates latency as a
 * histogram by process. Uses the zio pointer to correlate
 * across threads (ZFS dispatches ZIOs asynchronously).
 * Requires zfs.ko loaded.
 */

fbt:zfs:zio_execute:entry
/* @bsdinstruments-predicate */
{
    zio_start[arg0] = timestamp;
    zio_exec[arg0] = execname;
}

fbt:zfs:zio_done:entry
/zio_start[arg0]/
{
    this->elapsed_us = (timestamp - zio_start[arg0]) / 1000;
    @latency[zio_exec[arg0]] = quantize(this->elapsed_us);
    @iops[zio_exec[arg0]] = count();
    zio_start[arg0] = 0;
    zio_exec[arg0] = 0;
}

dtrace:::END
{
    printf("\n--- ZFS I/O latency (us) by process ---\n");
    printa(@latency);
    printf("\n--- ZFS IOPS by process ---\n");
    printa("%-30s %@d\n", @iops);
}
