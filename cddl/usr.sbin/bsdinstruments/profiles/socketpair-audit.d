/*
 * Socketpair audit — local IPC pipe creation.
 *
 * Traces socketpair(2) calls which create paired sockets
 * for bidirectional local IPC. Shows which processes create
 * socketpairs and how frequently.
 */

syscall::socketpair:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: socketpair domain=%d type=%d protocol=%d\n",
        execname, pid, arg0, arg1, arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::socketpair:return
/arg1 == 0 /* @bsdinstruments-predicate-and *//
{
    @pairs[execname] = count();
}

dtrace:::END
{
    printf("\n--- Socketpair creation count by process ---\n");
    printa("%-30s %@d\n", @pairs);
}
