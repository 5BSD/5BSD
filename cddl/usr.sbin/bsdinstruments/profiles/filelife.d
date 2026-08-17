/*
 * File creation to deletion lifespan.
 *
 * Tracks files from vop_create to vop_remove to measure
 * how long files live. Short-lived files indicate temp
 * file churn. Uses the vfs provider.
 */

vfs::vop_create:entry
/* @bsdinstruments-predicate */
{
    file_create[execname, tid] = timestamp;
}

vfs::vop_create:return
/file_create[execname, tid]/
{
    printf("%s[%d]: file created\n", execname, pid);
    file_create[execname, tid] = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

vfs::vop_remove:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: file removed\n", execname, pid);
    @removes[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- File removes by process ---\n");
    printa("%-30s %@d\n", @removes);
}
