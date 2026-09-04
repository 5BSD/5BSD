/*
 * MAC_CAPABILITY error tracking — framework errors and revocations.
 *
 * Traces revoke events, framework-level errors, and instance closes.
 */

mac_capability:::revoke
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: REVOKE service=%s badge=%d reason=%d\n",
        execname, pid, stringof(arg0), arg1, arg2);
    @revokes[stringof(arg0), arg2] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

mac_capability:::error
/* @bsdinstruments-predicate */
{
    @errors[execname] = count();
}

mac_capability:::close
/* @bsdinstruments-predicate */
{
    @closes[stringof(arg0)] = count();
}

dtrace:::END
{
    printf("\n--- revokes by service/reason ---\n");
    printf("%-24s %8s %8s\n", "SERVICE", "REASON", "COUNT");
    printa("%-24s %8d %@8d\n", @revokes);
    printf("\n--- framework errors by process ---\n");
    printa("%-24s %@d\n", @errors);
    printf("\n--- closes by service ---\n");
    printa("%-24s %@d\n", @closes);
}
