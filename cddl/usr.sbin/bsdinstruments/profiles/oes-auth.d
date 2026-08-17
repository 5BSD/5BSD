/*
 * OpenEndpointSecurity AUTH decisions — allow, deny, and timeout.
 *
 * Traces OES authorization events to show which operations were
 * allowed, denied, or timed out by endpoint security policies.
 * Requires oes.ko loaded. See OpenEndpointSecurity for event
 * type constants.
 */

oes:::auth-allow
/* @bsdinstruments-predicate */
{
    @allowed[execname, arg0] = count();
}

oes:::auth-deny
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES DENIED event=%d\n", execname, arg1, arg0);
    @denied[execname, arg0] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

oes:::auth-timeout
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: OES TIMEOUT event=%d action=%d\n",
        execname, arg1, arg0, arg2);
    @timeouts[execname, arg0] = count();
}

dtrace:::END
{
    printf("\n--- OES AUTH allowed by process/event ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "EVENT", "COUNT");
    printa("%-20s %8d %@8d\n", @allowed);
    printf("\n--- OES AUTH denied by process/event ---\n");
    printa("%-20s %8d %@8d\n", @denied);
    printf("\n--- OES AUTH timeouts by process/event ---\n");
    printa("%-20s %8d %@8d\n", @timeouts);
}
