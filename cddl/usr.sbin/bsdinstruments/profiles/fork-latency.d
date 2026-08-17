/*
 * Fork latency — time spent in fork, vfork, and pdfork.
 *
 * Measures process creation overhead. Slow forks indicate
 * memory pressure (copy-on-write setup) or resource limits.
 * Histogram in microseconds.
 */

syscall::fork:entry
/* @bsdinstruments-predicate */
{
    self->fork_ts = timestamp;
    self->fork_op = "fork";
}

syscall::vfork:entry
/* @bsdinstruments-predicate */
{
    self->fork_ts = timestamp;
    self->fork_op = "vfork";
}

syscall::pdfork:entry
/* @bsdinstruments-predicate */
{
    self->fork_ts = timestamp;
    self->fork_op = "pdfork";
}

syscall::fork:return,
syscall::vfork:return,
syscall::pdfork:return
/self->fork_ts/
{
    this->us = (timestamp - self->fork_ts) / 1000;
    printf("%s[%d]: %s %dus\n",
        execname, pid, self->fork_op, this->us);
    @latency[execname, self->fork_op] = quantize(this->us);
    self->fork_ts = 0;
    self->fork_op = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Fork latency (us) by process/type ---\n");
    printa(@latency);
}
