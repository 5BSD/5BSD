/* Print every ip:::receive event */

ip:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ip recv\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
