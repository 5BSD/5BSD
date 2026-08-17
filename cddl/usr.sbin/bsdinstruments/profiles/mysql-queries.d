/*
 * Trace MySQL/MariaDB queries via USDT probes.
 * Requires MySQL built with -DENABLE_DTRACE=1.
 * Usage: bsdinstruments watch mysql-queries --param pid=<mysqld-pid>
 */

pid${pid}::query__start:entry
{
    printf("mysql[%d]: query-start %s\n", pid, copyinstr(arg0));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    self->qstart = timestamp;
}

pid${pid}::query__done:entry
/self->qstart/
{
    this->elapsed_ms = (timestamp - self->qstart) / 1000000;
    printf("mysql[%d]: query-done %dms\n", pid, this->elapsed_ms);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    @latency["query-latency-ms"] = quantize(this->elapsed_ms);
    self->qstart = 0;
}

pid${pid}::connection__start:entry
{
    printf("mysql[%d]: connection-start\n", pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}::connection__done:entry
{
    printf("mysql[%d]: connection-done\n", pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printa(@latency);
}
