/* Print every sendto(2) entry */

syscall::sendto:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: sendto(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
