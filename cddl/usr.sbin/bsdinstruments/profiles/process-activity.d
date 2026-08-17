/*
 * Process Activity — lifecycle event stream.
 *
 * Tracks the process lifecycle: creation, exec, exit, signal delivery.
 * Useful for "what is starting and stopping on this host" forensic
 * logging.
 */

proc:::create
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: create\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::exec-success
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exec-success\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::exec-failure
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exec-failure\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::exit
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: exit\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::signal-send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: signal-send sig=%d to pid=%d\n", execname, pid, (int)arg2, args[1]->p_pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
