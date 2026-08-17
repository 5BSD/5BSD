/*
 * System Trace — full event stream.
 *
 * The kitchen-sink view: every syscall, every proc lifecycle event,
 * every sched on-cpu / off-cpu transition, every signal delivery,
 * every page fault. Use with --execname or --pid to scope it to
 * one process — you'll regret leaving it system-wide.
 */

syscall:::entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: syscall %s entry\n", execname, pid, probefunc);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall:::return
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: syscall %s return = %d\n", execname, pid, probefunc, (int)arg1);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::create,
proc:::exec-success,
proc:::exec-failure,
proc:::exit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::signal-send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc signal-send sig=%d\n", execname, pid, (int)arg2);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

sched:::on-cpu,
sched:::off-cpu
/* @bsdinstruments-predicate */
{
    printf("%s[%d/tid %d]: sched %s cpu=%d\n", execname, pid, tid, probename, cpu);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::vm_fault:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vm_fault\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
