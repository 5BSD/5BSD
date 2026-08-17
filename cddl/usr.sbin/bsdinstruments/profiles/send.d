/* Print every send(2) entry. FreeBSD's libc send() is a wrapper
 * around sendto() with NULL address args, so the kernel-level
 * probe is sendto — there is no syscall::send:entry on FreeBSD. */

syscall::sendto:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: send(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
