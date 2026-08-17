/*
 * fsync/fdatasync latency — quantize flush-to-disk time.
 *
 * Identifies processes with expensive fsync patterns.
 * High fsync latency is a common cause of write-path
 * performance problems in databases and log writers.
 */

syscall::fsync:entry,
syscall::fdatasync:entry
/* @bsdinstruments-predicate */
{
    self->fsync_ts = timestamp;
}

syscall::fsync:return,
syscall::fdatasync:return
/self->fsync_ts/
{
    this->elapsed_us = (timestamp - self->fsync_ts) / 1000;
    printf("%s[%d]: %s %dus\n", execname, pid, probefunc, this->elapsed_us);
    @latency[execname, probefunc] = quantize(this->elapsed_us);
    self->fsync_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- fsync latency (us) by process ---\n");
    printa(@latency);
}
