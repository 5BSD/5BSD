/* Print every sched:::preempt event */

sched:::preempt
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched preempt\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
