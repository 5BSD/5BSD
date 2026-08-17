/* Print every sched:::load-change event */

sched:::load-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched load-change\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
