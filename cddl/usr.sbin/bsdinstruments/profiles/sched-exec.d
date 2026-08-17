/* Print sched execution transitions (sleep + wakeup) — dwatch parity */

sched:::sleep,
sched:::wakeup
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s\n", execname, pid, tid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
