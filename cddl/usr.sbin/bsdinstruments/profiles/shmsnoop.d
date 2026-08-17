/*
 * Shared memory operations — shm_open, shm_unlink, mmap.
 *
 * Traces POSIX shared memory syscalls to identify processes
 * creating or mapping shared segments. Useful for IPC
 * debugging and security auditing.
 */

syscall::shm_open:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: shm_open(\"%s\", 0x%x)\n",
        execname, pid, copyinstr(arg0), arg1);
    @shm_ops[execname, "shm_open"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::shm_open2:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: shm_open2(\"%s\", 0x%x)\n",
        execname, pid, copyinstr(arg0), arg1);
    @shm_ops[execname, "shm_open2"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::shm_unlink:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: shm_unlink(\"%s\")\n",
        execname, pid, copyinstr(arg0));
    @shm_ops[execname, "shm_unlink"] = count();
}

dtrace:::END
{
    printf("\n--- Shared memory operations by process ---\n");
    printf("%-20s %-14s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-14s %@8d\n", @shm_ops);
}
