/*
 * CAP_RT error tracking — failed operations and revocations.
 *
 * Traces cap_rt revoke events and framework-level errors.
 * Revoke reasons: 0=explicit, 1=service unload, 2=terminate.
 * Requires cap_rt.ko loaded.
 */

cap_rt:::revoke
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: cap_rt REVOKE service=%s badge=%d reason=%d\n",
        execname, pid, copyinstr(arg0), arg1, arg2);
    @revokes[copyinstr(arg0), arg2] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

cap_rt:::close
/* @bsdinstruments-predicate */
{
    @closes[copyinstr(arg0)] = count();
}

dtrace:::END
{
    printf("\n--- cap_rt revokes by service/reason ---\n");
    printf("%-20s %8s %8s\n", "SERVICE", "REASON", "COUNT");
    printa("%-20s %8d %@8d\n", @revokes);
    printf("\n--- cap_rt closes by service ---\n");
    printa("%-20s %@d\n", @closes);
}
