/* Print every sched:::sleep event */

sched:::sleep
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched sleep\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
