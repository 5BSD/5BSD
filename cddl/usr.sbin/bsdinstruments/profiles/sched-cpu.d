/* Print sched cpu transition events (off-cpu / on-cpu / remain-cpu) */

sched:::off-cpu,
sched:::on-cpu,
sched:::remain-cpu
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
