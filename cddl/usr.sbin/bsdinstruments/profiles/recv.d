/* Print every recv(2) entry. FreeBSD's libc recv() is a wrapper
 * around recvfrom() with NULL address args, so the kernel-level
 * probe is recvfrom — there is no syscall::recv:entry on FreeBSD. */

syscall::recvfrom:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: recvfrom(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
