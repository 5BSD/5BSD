/* Print every tcp send and receive event with byte count */

tcp:::send
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp send len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

tcp:::receive
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp recv len=%d\n", execname, pid, args[2]->ip_plength);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
