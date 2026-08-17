/*
 * MAC policy module lifecycle — register, unregister, events.
 *
 * Traces MAC policy module loading and unloading via FBT.
 * Shows when MAC policies are activated or deactivated.
 * Useful for security configuration auditing.
 */

fbt::mac_policy_register:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC policy register\n", execname, pid);
    @ops[execname, "register"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::mac_policy_unregister:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: MAC policy unregister\n", execname, pid);
    @ops[execname, "unregister"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- MAC policy operations ---\n");
    printf("%-20s %-14s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-14s %@8d\n", @ops);
}
