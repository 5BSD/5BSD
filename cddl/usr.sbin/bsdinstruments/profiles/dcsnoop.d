/*
 * Directory cache (namecache) snoop — every lookup event.
 *
 * Prints every VFS name cache lookup with hit/miss result.
 * High miss rates cause disk I/O for pathname resolution.
 * High-overhead — use with --execname or --pid filters.
 */

vfs:namecache:lookup:hit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: namecache HIT\n", execname, pid);
    @hits[execname] = count();
}

vfs:namecache:lookup:miss
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: namecache MISS\n", execname, pid);
    @misses[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Namecache hits ---\n");
    printa("%-30s %@d\n", @hits);
    printf("\n--- Namecache misses ---\n");
    printa("%-30s %@d\n", @misses);
}
