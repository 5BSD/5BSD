/*
 * capprotect — process integrity shielding events.
 *
 * Traces the capprotect shield: allowed and denied access attempts
 * against protected processes (ptrace, signals, visibility).
 */

mac_capability_capprotect:::allow
/* @bsdinstruments-predicate */
{
    @allowed[execname, stringof(arg0)] = count();
}

mac_capability_capprotect:::deny
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: capprotect DENIED %s\n",
        execname, pid, stringof(arg0));
    @denied[execname, stringof(arg0)] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- capprotect allowed ---\n");
    printf("%-20s %-16s %8s\n", "EXECNAME", "CHECK", "COUNT");
    printa("%-20s %-16s %@8d\n", @allowed);
    printf("\n--- capprotect DENIED ---\n");
    printa("%-20s %-16s %@8d\n", @denied);
}
