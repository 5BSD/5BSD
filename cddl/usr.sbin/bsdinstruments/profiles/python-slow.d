/*
 * Find slow Python functions by measuring call duration.
 * Requires CPython built with --with-dtrace.
 * Usage: bsdinstruments watch python-slow --param pid=<python-pid>
 */

pid${pid}::function__entry:entry
{
    self->depth++;
    self->file = copyinstr(arg0);
    self->func = copyinstr(arg1);
    self->entry[self->depth] = timestamp;
}

pid${pid}::function__return:entry
/self->entry[self->depth]/
{
    this->elapsed_us = (timestamp - self->entry[self->depth]) / 1000;
    printf("python[%d]: %dus %s:%s\n",
        pid, this->elapsed_us, copyinstr(arg0), copyinstr(arg1));
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    @slow[copyinstr(arg0), copyinstr(arg1)] = quantize(this->elapsed_us);
    self->entry[self->depth] = 0;
    self->depth--;
}

dtrace:::END
{
    printa(@slow);
}
