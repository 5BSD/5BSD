/* Print every vfs:::vop_create event */

vfs::vop_create:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: vop_create\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
