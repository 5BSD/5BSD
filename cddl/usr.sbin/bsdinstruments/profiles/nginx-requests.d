/*
 * nginx HTTP request latency via pid provider.
 *
 * Traces nginx request processing from start to finalize.
 * Shows per-request latency and aggregates by worker process.
 * Usage: bsdinstruments watch nginx-requests --param pid=<nginx-worker-pid>
 */

pid${pid}::ngx_http_process_request:entry
{
    self->req_ts = timestamp;
}

pid${pid}::ngx_http_finalize_request:entry
/self->req_ts/
{
    this->us = (timestamp - self->req_ts) / 1000;
    printf("%s[%d]: nginx request %dus\n", execname, pid, this->us);
    @latency = quantize(this->us);
    @count[execname] = count();
    self->req_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- nginx request latency (us) ---\n");
    printa(@latency);
    printf("\n--- nginx request count by worker ---\n");
    printa("%-30s %@d\n", @count);
}
