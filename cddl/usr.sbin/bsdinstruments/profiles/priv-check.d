/*
 * Privilege checks — which processes check which privileges.
 *
 * Traces priv_check and priv_check_cred kernel calls to show
 * privilege escalation attempts. arg0 is the privilege number
 * (see sys/priv.h). Useful for security auditing.
 */

fbt::priv_check:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: priv_check priv=%d\n", execname, pid, arg1);
    @checks[execname, arg1] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::priv_check:return
/arg1 != 0/
{
    printf("%s[%d]: priv_check DENIED\n", execname, pid);
    @denied[execname] = count();
}

dtrace:::END
{
    printf("\n--- Privilege checks by process/priv ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "PRIV", "COUNT");
    printa("%-20s %8d %@8d\n", @checks);
    printf("\n--- Privilege denials by process ---\n");
    printa("%-30s %@d\n", @denied);
}
