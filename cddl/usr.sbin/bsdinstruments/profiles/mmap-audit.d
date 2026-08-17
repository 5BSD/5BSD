/*
 * Memory mapping audit — mmap, munmap, mprotect, madvise.
 *
 * Traces memory mapping syscalls for security auditing and
 * memory profiling. Shows which processes create executable
 * mappings (RWX), change protections, or map large regions.
 */

syscall::mmap:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: mmap addr=0x%x len=%d prot=0x%x flags=0x%x\n",
        execname, pid, arg0, arg1, arg2, arg3);
    @mmap_ops[execname, "mmap"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::munmap:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: munmap addr=0x%x len=%d\n",
        execname, pid, arg0, arg1);
    @mmap_ops[execname, "munmap"] = count();
}

syscall::mprotect:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: mprotect addr=0x%x len=%d prot=0x%x\n",
        execname, pid, arg0, arg1, arg2);
    @mmap_ops[execname, "mprotect"] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::madvise:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: madvise addr=0x%x len=%d behav=%d\n",
        execname, pid, arg0, arg1, arg2);
    @mmap_ops[execname, "madvise"] = count();
}

dtrace:::END
{
    printf("\n--- Memory mapping operations by process ---\n");
    printf("%-20s %-10s %8s\n", "EXECNAME", "OP", "COUNT");
    printa("%-20s %-10s %@8d\n", @mmap_ops);
}
