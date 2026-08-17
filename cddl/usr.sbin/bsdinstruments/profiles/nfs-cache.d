/*
 * NFS client cache hit/miss rates.
 *
 * Traces NFS access and attribute cache effectiveness via
 * FBT on the NFS client cache functions. High miss rates
 * indicate stale cache or undersized timeout settings.
 * Requires nfsclient loaded.
 */

fbt::nfs_getattrcache:entry
/* @bsdinstruments-predicate */
{
    @attr_lookups[execname] = count();
}

fbt::nfs_getattrcache:return
/arg1 == 0/
{
    @attr_hits[execname] = count();
}

fbt::nfs_getattrcache:return
/arg1 != 0/
{
    @attr_misses[execname] = count();
}

dtrace:::END
{
    printf("\n--- NFS attribute cache lookups ---\n");
    printa("%-30s %@d\n", @attr_lookups);
    printf("\n--- NFS attribute cache hits ---\n");
    printa("%-30s %@d\n", @attr_hits);
    printf("\n--- NFS attribute cache misses ---\n");
    printa("%-30s %@d\n", @attr_misses);
}
