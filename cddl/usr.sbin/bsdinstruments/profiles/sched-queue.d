/* Print sched runqueue events (dequeue + enqueue + load-change) */

sched:::dequeue,
sched:::enqueue,
sched:::load-change
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
