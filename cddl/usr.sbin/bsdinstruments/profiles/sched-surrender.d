/* Print every sched:::surrender event */

sched:::surrender
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched surrender\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
