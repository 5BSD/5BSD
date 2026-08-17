/*
 * Allocation site tracker for leak analysis.
 *
 * Counts malloc calls and bytes by allocation-site stack, and
 * separately counts free calls. Compare the two tables: sites
 * with many mallocs but few frees are likely leaking.
 *
 * DTrace cannot iterate associative arrays, so true per-pointer
 * leak tracking is not possible. This profile gives you the
 * allocation-site view instead.
 *
 * Usage: bsdinstruments watch malloc-leaks --param pid=<pid> --duration 10
 */

pid${pid}::malloc:entry
{
    self->msize = arg0;
}

pid${pid}::malloc:return
/arg1 != 0/
{
    @alloc_count[ustack()] = count();
    @alloc_bytes[ustack()] = sum(self->msize);
    self->msize = 0;
}

pid${pid}::free:entry
/arg0 != 0/
{
    @free_count[ustack()] = count();
}

dtrace:::END
{
    printf("\n--- Allocation sites (count) ---\n");
    printa(@alloc_count);
    printf("\n--- Allocation sites (total bytes) ---\n");
    printa(@alloc_bytes);
    printf("\n--- Free sites (count) ---\n");
    printa(@free_count);
}
