/*
 * UMA (Universal Memory Allocator) activity.
 *
 * Traces kernel slab allocator operations to show which
 * subsystems consume the most kernel memory. High allocation
 * rates in specific zones indicate potential leaks or
 * excessive object churn.
 */

fbt::uma_zalloc_arg:entry
/* @bsdinstruments-predicate */
{
    @allocs[execname] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

fbt::uma_zfree_arg:entry
/* @bsdinstruments-predicate */
{
    @frees[execname] = count();
}

dtrace:::END
{
    printf("\n--- UMA allocations by process ---\n");
    printa("%-30s %@d\n", @allocs);
    printf("\n--- UMA frees by process ---\n");
    printa("%-30s %@d\n", @frees);
}
