/* Print every vfs:::vop_remove event */

vfs::vop_remove:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_remove\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
