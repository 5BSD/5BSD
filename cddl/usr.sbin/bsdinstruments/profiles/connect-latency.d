/*
 * TCP connect latency — time from connect(2) to established.
 *
 * Measures outbound connection setup time. High connect latency
 * indicates DNS issues, network congestion, or remote server
 * problems.  Structured formats also emit one client span per
 * connect(2); EINPROGRESS (non-blocking connect) is not an error.
 */

syscall::connect:entry
/* @bsdinstruments-predicate */
{
    self->conn_ts = timestamp;
    self->conn_fd = arg0;
}

syscall::connect:return
/self->conn_ts/
{
    this->elapsed_us = (timestamp - self->conn_ts) / 1000;
    printf("%s[%d]: connect %dus (ret=%d)\n",
        execname, pid, this->elapsed_us, (int)arg1);
    @latency[execname] = quantize(this->elapsed_us);
    /* @bsdinstruments-span(name="connect", kind=client,
        start=self->conn_ts, error=errno == EINPROGRESS ? 0 : errno,
        int.fd=(int)self->conn_fd) */
    self->conn_ts = 0;
    self->conn_fd = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Connect latency (us) by process ---\n");
    printa(@latency);
}
