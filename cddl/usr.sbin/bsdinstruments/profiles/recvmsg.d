/* Print every recvmsg(2) entry */

syscall::recvmsg:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: recvmsg(fd=%d)\n",
           execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
