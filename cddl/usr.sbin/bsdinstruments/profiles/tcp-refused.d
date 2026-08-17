/* Print tcp accept-refused and connect-refused events */

tcp:::accept-refused,
tcp:::connect-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp %s\n", execname, pid, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
