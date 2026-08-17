/* Print every sendmsg(2) entry */

syscall::sendmsg:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sendmsg(fd=%d)\n",
           execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
