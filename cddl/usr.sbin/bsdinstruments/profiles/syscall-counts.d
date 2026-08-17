/* Count every syscall by name; print the table on END */

syscall:::entry
/* @bsdinstruments-predicate */
{
    @counts[probefunc] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printa("%-30s %@d\n", @counts);
}
