/*
 * Accept latency — time spent blocking in accept(2).
 *
 * Measures how long server processes wait for incoming
 * connections. Useful for understanding server utilization
 * and connection arrival patterns.  Structured formats also
 * emit one server span per accept(2), in error when it fails.
 */

syscall::accept:entry,
syscall::accept4:entry
/* @bsdinstruments-predicate */
{
    self->accept_ts = timestamp;
}

syscall::accept:return,
syscall::accept4:return
/self->accept_ts/
{
    this->elapsed_us = (timestamp - self->accept_ts) / 1000;
    printf("%s[%d]: accept %dus (fd=%d)\n",
        execname, pid, this->elapsed_us, (int)arg1);
    @latency[execname] = quantize(this->elapsed_us);
    /* @bsdinstruments-span(name=probefunc, kind=server,
        start=self->accept_ts, error=errno, int.fd=(int)arg1) */
    self->accept_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Accept latency (us) by process ---\n");
    printa(@latency);
}
