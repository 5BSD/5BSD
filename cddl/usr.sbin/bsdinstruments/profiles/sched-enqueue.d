/* Print every sched:::enqueue event */

sched:::enqueue
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched enqueue\n", execname, pid, tid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
