/*
 * Measure time spent in a user-space function.
 * Usage: bsdinstruments watch func-time --param pid=<pid> --param func=<function>
 */

pid${pid}::${func}:entry
{
    self->entry = timestamp;
}

pid${pid}::${func}:return
/self->entry/
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
