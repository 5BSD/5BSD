/*
 * sendmsg/recvmsg activity by process (IPC monitor).
 *
 * Traces all sendmsg and recvmsg syscalls with byte counts.
 * Useful for identifying IPC-heavy processes. Captures all
 * address families (AF_UNIX, AF_INET, etc.) — does not filter
 * to Unix domain sockets or inspect ancillary data (SCM_RIGHTS).
 */

syscall::sendmsg:entry
/* @bsdinstruments-predicate */
{
    self->sendmsg_fd = arg0;
}

syscall::sendmsg:return
/self->sendmsg_fd && arg1 >= 0/
{
    printf("%s[%d]: sendmsg fd=%d bytes=%d\n",
        execname, pid, self->sendmsg_fd, arg1);
    @sends[execname] = count();
    self->sendmsg_fd = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::sendmsg:return
/self->sendmsg_fd/
{
    self->sendmsg_fd = 0;
}

syscall::recvmsg:entry
/* @bsdinstruments-predicate */
{
    self->recvmsg_fd = arg0;
}

syscall::recvmsg:return
/self->recvmsg_fd && arg1 >= 0/
{
    printf("%s[%d]: recvmsg fd=%d bytes=%d\n",
        execname, pid, self->recvmsg_fd, arg1);
    @recvs[execname] = count();
    self->recvmsg_fd = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::recvmsg:return
/self->recvmsg_fd/
{
    self->recvmsg_fd = 0;
}

dtrace:::END
{
    printf("\n--- sendmsg count by process ---\n");
    printa("%-30s %@d\n", @sends);
    printf("\n--- recvmsg count by process ---\n");
    printa("%-30s %@d\n", @recvs);
}
