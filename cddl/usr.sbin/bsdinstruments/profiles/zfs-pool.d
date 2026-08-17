/*
 * ZFS pool and dataset operations.
 *
 * Traces ZFS pool-level operations: sync, txg commit, and
 * scrub activity. Shows write amplification and sync
 * frequency. Requires zfs.ko loaded.
 */

fbt:zfs:spa_sync:entry
/* @bsdinstruments-predicate */
{
    self->sync_ts = timestamp;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt:zfs:spa_sync:return
/self->sync_ts/
{
    this->ms = (timestamp - self->sync_ts) / 1000000;
    printf("%s[%d]: spa_sync %dms\n", execname, pid, this->ms);
    @sync_latency = quantize(this->ms);
    self->sync_ts = 0;
}

fbt:zfs:txg_sync_thread:entry
/* @bsdinstruments-predicate */
{
    @txg_syncs[execname] = count();
}

fbt:zfs:dsl_scan_sync:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ZFS scrub sync\n", execname, pid);
    @scrub_ops = count();
}

dtrace:::END
{
    printf("\n--- ZFS spa_sync latency (ms) ---\n");
    printa(@sync_latency);
    printf("\n--- TXG syncs by process ---\n");
    printa("%-30s %@d\n", @txg_syncs);
    printf("\n--- Scrub operations ---\n");
    printa("%@d\n", @scrub_ops);
}
