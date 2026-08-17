/*
 * VM fault hotspots — faulting processes with stacks.
 *
 * Aggregates page faults by process and kernel stack to show
 * where memory pressure originates. The stack trace reveals
 * whether faults come from mmap, exec, heap growth, etc.
 */

fbt::vm_fault:entry
/* @bsdinstruments-predicate */
{
    @faults[execname, stack()] = count();
    @by_process[execname] = count();
}

dtrace:::END
{
    printf("\n--- Page faults by process ---\n");
    printa("%-30s %@d\n", @by_process);
    printf("\n--- Page fault stacks ---\n");
    printa(@faults);
}
