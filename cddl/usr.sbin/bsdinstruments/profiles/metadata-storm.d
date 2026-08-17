/*
 * Metadata storm detector — stat/open/close/readdir hotspots.
 *
 * Aggregates high-frequency metadata operations by process.
 * Catches package managers, build systems, and misbehaving
 * applications that hammer the filesystem namespace.
 */

syscall::stat:entry,
syscall::lstat:entry,
syscall::fstat:entry,
syscall::fstatat:entry
/* @bsdinstruments-predicate */
{
    @stats[execname] = count();
}

syscall::open:entry,
syscall::openat:entry
/* @bsdinstruments-predicate */
{
    @opens[execname] = count();
}

syscall::close:entry
/* @bsdinstruments-predicate */
{
    @closes[execname] = count();
}

syscall::getdirentries:entry
/* @bsdinstruments-predicate */
{
    @readdirs[execname] = count();
}

fbt::VOP_LOOKUP:entry
/* @bsdinstruments-predicate */
{
    @lookups[execname] = count();
}

dtrace:::END
{
    printf("\n--- stat/fstat calls by process ---\n");
    printa("%-30s %@d\n", @stats);
    printf("\n--- open/openat calls by process ---\n");
    printa("%-30s %@d\n", @opens);
    printf("\n--- close calls by process ---\n");
    printa("%-30s %@d\n", @closes);
    printf("\n--- readdir calls by process ---\n");
    printa("%-30s %@d\n", @readdirs);
    printf("\n--- VOP_LOOKUP calls by process ---\n");
    printa("%-30s %@d\n", @lookups);
}
