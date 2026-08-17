/*
 * ICMP send and receive events.
 *
 * Traces ICMP message generation and input via FBT on
 * icmp_input and icmp_error. Shows ping, unreachable,
 * redirect, and other ICMP traffic by process.
 */

fbt::icmp_input:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: icmp input\n", execname, pid);
    @icmp_in[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::icmp_error:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: icmp error type=%d code=%d\n",
        execname, pid, arg1, arg2);
    @icmp_err[execname, arg1] = count();
}

dtrace:::END
{
    printf("\n--- ICMP input by process ---\n");
    printa("%-30s %@d\n", @icmp_in);
    printf("\n--- ICMP errors by process/type ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "TYPE", "COUNT");
    printa("%-20s %8d %@8d\n", @icmp_err);
}
