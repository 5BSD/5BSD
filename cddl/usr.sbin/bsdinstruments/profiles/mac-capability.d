/*
 * MAC_CAPABILITY framework — connect, send, receive, call events.
 *
 * Traces the mac_capability message-passing framework. Shows
 * service connects, async message flow, sync calls, revocations,
 * and instance closes.
 */

mac_capability:::connect
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: connect service=%s badge=%d\n",
        execname, pid, stringof(arg0), arg1);
    @connects[execname, stringof(arg0)] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

mac_capability:::send
/* @bsdinstruments-predicate */
{
    @sends[execname, stringof(arg0)] = count();
}

mac_capability:::recv
/* @bsdinstruments-predicate */
{
    @recvs[execname, stringof(arg0)] = count();
}

mac_capability:::call
/* @bsdinstruments-predicate */
{
    @calls[execname, stringof(arg0)] = count();
}

mac_capability:::revoke
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: REVOKE service=%s badge=%d reason=%d\n",
        execname, pid, stringof(arg0), arg1, arg2);
    @revokes[execname, stringof(arg0)] = count();
}

mac_capability:::close
/* @bsdinstruments-predicate */
{
    @closes[execname, stringof(arg0)] = count();
}

dtrace:::END
{
    printf("\n--- connects ---\n");
    printf("%-20s %-24s %8s\n", "EXECNAME", "SERVICE", "COUNT");
    printa("%-20s %-24s %@8d\n", @connects);
    printf("\n--- sends ---\n");
    printa("%-20s %-24s %@8d\n", @sends);
    printf("\n--- recvs ---\n");
    printa("%-20s %-24s %@8d\n", @recvs);
    printf("\n--- calls ---\n");
    printa("%-20s %-24s %@8d\n", @calls);
    printf("\n--- revokes ---\n");
    printa("%-20s %-24s %@8d\n", @revokes);
    printf("\n--- closes ---\n");
    printa("%-20s %-24s %@8d\n", @closes);
}
