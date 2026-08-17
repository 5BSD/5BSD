/* Print every proc:::create event */

proc:::create
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc create\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
