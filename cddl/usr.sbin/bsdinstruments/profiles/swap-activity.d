/*
 * Swap and paging activity — page-in and page-out events.
 *
 * Traces the VM page daemon and swap pager to show memory
 * pressure. High swap activity indicates insufficient RAM
 * for the workload.
 */

fbt::vm_page_deactivate:entry
/* @bsdinstruments-predicate */
{
    @deactivations[execname] = count();
}

fbt::swp_pager_getpages:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: swap page-in\n", execname, pid);
    @page_ins[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::swp_pager_putpages:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: swap page-out\n", execname, pid);
    @page_outs[execname] = count();
}

dtrace:::END
{
    printf("\n--- Swap page-ins by process ---\n");
    printa("%-30s %@d\n", @page_ins);
    printf("\n--- Swap page-outs by process ---\n");
    printa("%-30s %@d\n", @page_outs);
    printf("\n--- Page deactivations by process ---\n");
    printa("%-30s %@d\n", @deactivations);
}
