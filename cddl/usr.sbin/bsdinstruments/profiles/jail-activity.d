/*
 * Per-jail syscall activity — aggregate syscalls by jail.
 *
 * Counts syscalls per jail ID to show which jails are most
 * active. Useful for multi-tenant resource monitoring and
 * noisy-neighbor detection. FreeBSD-specific.
 */

syscall:::entry
/* @bsdinstruments-predicate */
{
    @by_jail[curthread->td_ucred->cr_prison->pr_id,
             curthread->td_ucred->cr_prison->pr_name] = count();
    @by_jail_syscall[curthread->td_ucred->cr_prison->pr_id,
                     probefunc] = count();
}

dtrace:::END
{
    printf("\n--- Syscall count by jail ---\n");
    printf("%6s %-20s %8s\n", "JID", "JAIL", "COUNT");
    printa("%6d %-20s %@8d\n", @by_jail);
    printf("\n--- Top syscalls by jail ---\n");
    printf("%6s %-20s %8s\n", "JID", "SYSCALL", "COUNT");
    printa("%6d %-20s %@8d\n", @by_jail_syscall);
}
