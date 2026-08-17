/*
 * VFS name cache (namei) hit/miss rates.
 *
 * Traces the kernel name cache to show directory lookup
 * efficiency. High miss rates cause extra disk I/O for
 * pathname resolution. Uses vfs:namecache SDT probes.
 */

vfs:namecache:lookup:hit
/* @bsdinstruments-predicate */
{
    @hits[execname] = count();
}

vfs:namecache:lookup:miss
/* @bsdinstruments-predicate */
{
    @misses[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

vfs:namecache:enter:done
/* @bsdinstruments-predicate */
{
    @enters[execname] = count();
}

dtrace:::END
{
    printf("\n--- Namecache hits by process ---\n");
    printa("%-30s %@d\n", @hits);
    printf("\n--- Namecache misses by process ---\n");
    printa("%-30s %@d\n", @misses);
    printf("\n--- Namecache entries added by process ---\n");
    printa("%-30s %@d\n", @enters);
}
