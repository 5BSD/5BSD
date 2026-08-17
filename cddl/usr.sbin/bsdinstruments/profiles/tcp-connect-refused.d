/* Print every tcp:::connect-refused */

tcp:::connect-refused
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: tcp connect-refused\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
