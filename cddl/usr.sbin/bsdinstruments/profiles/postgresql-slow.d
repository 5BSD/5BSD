/*
 * Find slow PostgreSQL queries by measuring query duration.
 * Requires PostgreSQL built with --enable-dtrace.
 * Usage: bsdinstruments watch postgresql-slow --param pid=<postgres-pid>
 */

pid${pid}::query__start:entry
{
    self->query = copyinstr(arg0);
    self->start = timestamp;
}

pid${pid}::query__done:entry
/self->start/
{
    this->elapsed_ms = (timestamp - self->start) / 1000000;
    printf("postgres[%d]: %dms %s\n", pid, this->elapsed_ms, self->query);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    @latency["query-latency-ms"] = quantize(this->elapsed_ms);
    self->start = 0;
    self->query = 0;
}

dtrace:::END
{
    printa(@latency);
}
