/* Print every proc:::exec-success and proc:::exec-failure event */

proc:::exec-success
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exec-success\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::exec-failure
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exec-failure (errno=%d)\n", execname, pid, (int)arg0);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
