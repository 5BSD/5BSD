/* Print every vfs:::vop_rmdir event */

vfs::vop_rmdir:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_rmdir\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
