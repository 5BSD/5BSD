/* Print every sendto/sendmsg entry and recvfrom/recvmsg return.
 * FreeBSD's libc send()/recv() are wrappers around sendto()/recvfrom()
 * with NULL address args, so there is no kernel-level send or recv —
 * sendto/sendmsg/recvfrom/recvmsg are the real entry points. */

syscall::sendto:entry,
syscall::sendmsg:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s(fd=%d)\n", execname, pid, probefunc, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::recvfrom:return,
syscall::recvmsg:return
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: %s -> %d\n", execname, pid, probefunc, (int)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
