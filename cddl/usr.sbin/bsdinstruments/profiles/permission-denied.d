/*
 * Permission denied tracker — EACCES/EPERM across all syscalls.
 *
 * Focused instrument for diagnosing permission issues. Aggregates
 * every syscall that fails with EACCES (13) or EPERM (1) by
 * process and syscall name.
 */

syscall:::return
/arg1 == -1 && (errno == 13 || errno == 1) /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: %s failed errno=%d (%s)\n",
        execname, pid, probefunc, errno,
        errno == 13 ? "EACCES" : "EPERM");
    @denied[execname, probefunc, errno == 13 ? "EACCES" : "EPERM"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Permission denied by process/syscall ---\n");
    printf("%-20s %-18s %-8s %6s\n", "EXECNAME", "SYSCALL", "ERROR", "COUNT");
    printa("%-20s %-18s %-8s %@6d\n", @denied);
}
