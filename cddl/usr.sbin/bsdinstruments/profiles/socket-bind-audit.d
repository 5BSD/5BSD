/*
 * Socket lifecycle audit — bind/listen/connect/accept events.
 *
 * Traces socket lifecycle calls with file descriptor and
 * backlog context. Aggregates counts by process. For port/
 * address details, combine with tcp:::connect-* or ip:::send
 * probes.
 */

syscall::bind:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: bind fd=%d\n", execname, pid, arg0);
    @binds[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::listen:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: listen fd=%d backlog=%d\n", execname, pid, arg0, arg1);
    @listens[execname] = count();
}

syscall::connect:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: connect fd=%d\n", execname, pid, arg0);
    @connects[execname] = count();
}

syscall::accept:entry,
syscall::accept4:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s fd=%d\n", execname, pid, probefunc, arg0);
    @accepts[execname] = count();
}

dtrace:::END
{
    printf("\n--- bind count by process ---\n");
    printa("%-30s %@d\n", @binds);
    printf("\n--- listen count by process ---\n");
    printa("%-30s %@d\n", @listens);
    printf("\n--- connect count by process ---\n");
    printa("%-30s %@d\n", @connects);
    printf("\n--- accept count by process ---\n");
    printa("%-30s %@d\n", @accepts);
}
