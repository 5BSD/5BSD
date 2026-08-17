/* Count syscalls by (execname, probefunc); print the table on END */

syscall:::entry
/* @bsdinstruments-predicate */
{
    @counts[execname, probefunc] = count();
}

dtrace:::END
{
    printa("%-24s %-30s %@d\n", @counts);
}
