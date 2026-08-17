/* Print every syscall::nanosleep:entry */

syscall::nanosleep:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: nanosleep\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
