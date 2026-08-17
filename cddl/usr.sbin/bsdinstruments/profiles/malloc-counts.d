/*
 * Count malloc/realloc/calloc/free calls by size bucket for a process.
 * Usage: bsdinstruments watch malloc-counts --param pid=<pid>
 */

pid${pid}::malloc:entry
{
    @allocs[execname, "malloc"] = count();
    @sizes["malloc"] = quantize(arg0);
}

pid${pid}::calloc:entry
{
    @allocs[execname, "calloc"] = count();
    @sizes["calloc"] = quantize(arg0 * arg1);
}

pid${pid}::realloc:entry
{
    @allocs[execname, "realloc"] = count();
    @sizes["realloc"] = quantize(arg1);
}

pid${pid}::free:entry
{
    @allocs[execname, "free"] = count();
}

dtrace:::END
{
    printa(@allocs);
    printa(@sizes);
}
