/* Print every sched:::tick event */

sched:::tick
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched tick\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
