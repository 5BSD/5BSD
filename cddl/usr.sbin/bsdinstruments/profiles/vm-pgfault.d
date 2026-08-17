/*
 * Count page faults by process — identifies memory-intensive workloads.
 */

fbt::vm_fault:entry
/* @bsdinstruments-predicate */
{
    @faults[execname, pid] = count();
}

dtrace:::END
{
    printf("%-20s %8s %8s\n", "EXECNAME", "PID", "FAULTS");
    printa("%-20s %8d %@8d\n", @faults);
}
