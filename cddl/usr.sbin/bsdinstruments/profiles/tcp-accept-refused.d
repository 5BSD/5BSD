/* Print every tcp:::accept-refused */

tcp:::accept-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp accept-refused\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
