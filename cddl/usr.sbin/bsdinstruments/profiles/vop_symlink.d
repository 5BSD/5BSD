/* Print every vfs:::vop_symlink event */

vfs::vop_symlink:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_symlink\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
