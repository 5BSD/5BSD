/*
 * Async I/O latency — aio_read, aio_write, lio_listio timing.
 *
 * Traces POSIX AIO syscalls to measure asynchronous I/O
 * submission and completion latency. High-performance
 * servers use AIO to avoid blocking on disk I/O.
 */

syscall::aio_read:entry
/* @bsdinstruments-predicate */
{
    self->aio_ts = timestamp;
    self->aio_op = "aio_read";
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::aio_write:entry
/* @bsdinstruments-predicate */
{
    self->aio_ts = timestamp;
    self->aio_op = "aio_write";
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

syscall::lio_listio:entry
/* @bsdinstruments-predicate */
{
    self->aio_ts = timestamp;
    self->aio_op = "lio_listio";
}

syscall::aio_read:return,
syscall::aio_write:return,
syscall::lio_listio:return
/self->aio_ts/
{
    this->us = (timestamp - self->aio_ts) / 1000;
    printf("%s[%d]: %s %dus\n", execname, pid, self->aio_op, this->us);
    @latency[execname, self->aio_op] = quantize(this->us);
    self->aio_ts = 0;
    self->aio_op = 0;
}

dtrace:::END
{
    printf("\n--- AIO latency (us) by process/op ---\n");
    printa(@latency);
}
