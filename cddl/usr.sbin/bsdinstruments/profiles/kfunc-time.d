/*
 * Measure time spent in a kernel function.
 * Usage: bsdinstruments watch kfunc-time --param func=<kernel-function>
 */

fbt::${func}:entry
/* @bsdinstruments-predicate */
{
    self->entry = timestamp;
}

fbt::${func}:return
/self->entry /* @bsdinstruments-predicate-and *//
{
    this->elapsed_us = (timestamp - self->entry) / 1000;
    printf("%s[%d]: ${func} %dus\n", execname, pid, this->elapsed_us);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    @latency["${func}-us"] = quantize(this->elapsed_us);
    self->entry = 0;
}

dtrace:::END
{
    printa(@latency);
}
