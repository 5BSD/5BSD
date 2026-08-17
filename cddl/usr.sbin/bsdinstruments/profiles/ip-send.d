/* Print every ip:::send event */

ip:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ip send\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
