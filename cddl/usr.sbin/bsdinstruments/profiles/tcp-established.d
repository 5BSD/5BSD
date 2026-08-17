/* Print tcp accept-established and connect-established events */

tcp:::accept-established,
tcp:::connect-established
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
