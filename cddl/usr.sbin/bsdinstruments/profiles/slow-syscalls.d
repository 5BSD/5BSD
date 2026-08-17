/*
 * Quantize per-syscall latency to find slow outliers.
 * Uses thread-local entry timestamps and aggregates the
 * elapsed nanoseconds at return.
 */

syscall:::entry
/* @bsdinstruments-predicate */
{
    self->ts = timestamp;
}

syscall:::return
/self->ts/
{
    @latency[probefunc] = quantize(timestamp - self->ts);
    self->ts = 0;
}

dtrace:::END
{
    printa(@latency);
}
