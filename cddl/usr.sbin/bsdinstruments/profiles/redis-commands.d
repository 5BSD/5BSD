/*
 * Redis command execution tracing via pid provider.
 *
 * Traces Redis command processing to show command latency.
 * Usage: bsdinstruments watch redis-commands --param pid=<redis-pid>
 */

pid${pid}::processCommand:entry
{
    self->cmd_ts = timestamp;
}

pid${pid}::call:entry
/self->cmd_ts/
{
    self->call_ts = timestamp;
}

pid${pid}::call:return
/self->call_ts/
{
    this->us = (timestamp - self->call_ts) / 1000;
    printf("%s[%d]: redis call %dus\n", execname, pid, this->us);
    @latency = quantize(this->us);
    @count[execname] = count();
    self->call_ts = 0;
    self->cmd_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Redis command latency (us) ---\n");
    printa(@latency);
    printf("\n--- Redis command count ---\n");
    printa("%-30s %@d\n", @count);
}
