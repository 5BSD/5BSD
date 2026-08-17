/* Print every block-I/O start and done event */

io:::start
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io start\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

io:::done
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: io done\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
