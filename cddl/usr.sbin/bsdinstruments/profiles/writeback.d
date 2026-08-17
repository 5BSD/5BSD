/*
 * Dirty page writeback and buffer flushing.
 *
 * Traces bufdaemon and syncer activity to show when and how
 * often dirty pages are written back to disk. Spikes indicate
 * memory pressure or sync deadlines.
 */

fbt::bufwrite:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: bufwrite\n", execname, pid);
    @writes[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::bufdone:entry
/* @bsdinstruments-predicate */
{
    @done[execname] = count();
}

fbt::vfs_bio_awrite:entry
/* @bsdinstruments-predicate */
{
    @async_writes[execname] = count();
}

dtrace:::END
{
    printf("\n--- Buffer writes by process ---\n");
    printa("%-30s %@d\n", @writes);
    printf("\n--- Buffer completions by process ---\n");
    printa("%-30s %@d\n", @done);
    printf("\n--- Async buffer writes by process ---\n");
    printa("%-30s %@d\n", @async_writes);
}
