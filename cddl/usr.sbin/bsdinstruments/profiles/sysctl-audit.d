/*
 * Sysctl audit — kernel parameter reads and writes.
 *
 * Traces __sysctl syscalls to show which processes read or
 * modify kernel tunables. Useful for detecting unauthorized
 * tuning and understanding system configuration changes.
 */

syscall::__sysctl:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sysctl namelen=%d\n", execname, pid, arg1);
    @sysctl_ops[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Sysctl calls by process ---\n");
    printa("%-30s %@d\n", @sysctl_ops);
}
