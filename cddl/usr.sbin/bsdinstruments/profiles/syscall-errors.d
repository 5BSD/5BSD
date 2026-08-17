/*
 * Syscall errors — aggregate failures by process, syscall, errno.
 *
 * Identifies which processes are hitting which errors most
 * frequently. Useful for diagnosing permission issues, missing
 * files, resource exhaustion, etc.
 */

syscall:::return
/arg1 == -1 /* @bsdinstruments-predicate-and *//
{
    @errors[execname, probefunc, errno] = count();
}

dtrace:::END
{
    printf("\n--- Syscall errors by process/syscall/errno ---\n");
    printf("%-20s %-18s %6s %8s\n", "EXECNAME", "SYSCALL", "ERRNO", "COUNT");
    printa("%-20s %-18s %6d %@8d\n", @errors);
}
