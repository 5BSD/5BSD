/* Print every tcp:::connect-established */

tcp:::connect-established
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp connect-established\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
