/*
 * Pipe I/O activity — read/write on pipe file descriptors.
 *
 * Traces pipe creation and subsequent read/write syscalls
 * on pipe fds. Useful for understanding IPC volume between
 * processes connected by pipes.
 */

syscall::pipe:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pipe()\n", execname, pid);
    @pipe_creates[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::pipe2:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: pipe2(flags=0x%x)\n", execname, pid, arg1);
    @pipe_creates[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Pipe creations by process ---\n");
    printa("%-30s %@d\n", @pipe_creates);
}
