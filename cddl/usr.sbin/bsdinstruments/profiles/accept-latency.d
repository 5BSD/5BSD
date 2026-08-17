/*
 * Accept latency — time spent blocking in accept(2).
 *
 * Measures how long server processes wait for incoming
 * connections. Useful for understanding server utilization
 * and connection arrival patterns.
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
    self->accept_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Accept latency (us) by process ---\n");
    printa(@latency);
}
