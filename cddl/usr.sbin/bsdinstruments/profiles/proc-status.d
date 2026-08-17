/* Print every proc lifecycle status event (exec-success, exec-failure, exit) */

proc:::exec-success,
proc:::exec-failure,
proc:::exit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
