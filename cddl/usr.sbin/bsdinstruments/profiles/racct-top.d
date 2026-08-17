/*
 * Resource accounting (RACCT) activity by process.
 *
 * Traces racct_add to show which processes consume kernel
 * resources tracked by RACCT (CPU, memory, disk, network).
 * Useful for jail resource monitoring. Requires RACCT
 * enabled in kernel (GENERIC includes it).
 */

fbt::racct_add:entry
/* @bsdinstruments-predicate */
{
    @racct_ops[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- RACCT resource charges by process ---\n");
    printa("%-30s %@d\n", @racct_ops);
}
