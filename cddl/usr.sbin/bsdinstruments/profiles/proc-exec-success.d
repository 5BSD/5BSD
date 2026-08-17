/* Print every proc:::exec-success event */

proc:::exec-success
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc exec-success\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
