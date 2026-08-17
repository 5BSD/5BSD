/* Print every tcp:::connect-request */

tcp:::connect-request
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp connect-request\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
