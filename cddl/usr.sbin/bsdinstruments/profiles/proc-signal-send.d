/* Print every proc:::signal-send event */

proc:::signal-send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: proc signal-send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
