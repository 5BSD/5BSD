/* Print every tcp:::receive event */

tcp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
