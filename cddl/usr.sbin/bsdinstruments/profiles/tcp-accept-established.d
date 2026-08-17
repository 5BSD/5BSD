/* Print every tcp:::accept-established */

tcp:::accept-established
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp accept-established\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
