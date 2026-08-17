/*
 * Socket creation audit — track new socket allocations.
 *
 * Traces socket(2) and socketpair(2) syscalls showing domain,
 * type, and protocol. Useful for identifying unexpected network
 * connections and auditing application behavior.
 */

syscall::socket:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: socket(domain=%d, type=%d, proto=%d)\n",
        execname, pid, arg0, arg1, arg2);
    @sockets[execname, arg0, arg1] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::socketpair:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: socketpair(domain=%d, type=%d)\n",
        execname, pid, arg0, arg1);
    @sockets[execname, arg0, arg1] = count();
}

dtrace:::END
{
    printf("\n--- Socket creations by process/domain/type ---\n");
    printf("%-20s %8s %8s %8s\n", "EXECNAME", "DOMAIN", "TYPE", "COUNT");
    printa("%-20s %8d %8d %@8d\n", @sockets);
}
