/* Aggregate syscall errors by process, syscall, and errno */

syscall:::return
/errno != 0 /* @bsdinstruments-predicate-and */ /
{
    printf("%s[%d]: %s -> errno %d\n", execname, pid, probefunc, errno);
    @errs[execname, probefunc, errno] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Errors by process/syscall/errno ---\n");
    printf("%-20s %-20s %6s %8s\n", "EXECNAME", "SYSCALL", "ERRNO", "COUNT");
    printa("%-20s %-20s %6d %@8d\n", @errs);
}
