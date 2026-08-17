/*
 * Database slow query tracer — PostgreSQL queries exceeding threshold.
 *
 * Traces PostgreSQL query execution via pid provider and reports
 * queries slower than 10ms. Shows the query text and duration.
 * Usage: bsdinstruments watch dbslower --param pid=<postgres-pid>
 */

pid${pid}::query__start:entry
{
    self->query = copyinstr(arg0);
    self->query_ts = timestamp;
}

pid${pid}::query__done:entry
/self->query_ts/
{
    this->ms = (timestamp - self->query_ts) / 1000000;
    @latency = quantize(this->ms);
    @slow_queries[self->query] = max(this->ms);
    printf("%s[%d]: query %dms: %s\n",
        execname, pid, this->ms, self->query);
    self->query_ts = 0;
    self->query = 0;
}

dtrace:::END
{
    printf("\n--- Query latency (ms) ---\n");
    printa(@latency);
    printf("\n--- Slowest queries (max ms) ---\n");
    printa("%-60s %@d\n", @slow_queries);
}
