/* Print every read(2) entry with fd and length */

syscall::read:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: read(fd=%d, %d)\n",
           execname, pid, (int)arg0, (size_t)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
