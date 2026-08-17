/* Print every sched:::dequeue event */

sched:::dequeue
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched dequeue\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
