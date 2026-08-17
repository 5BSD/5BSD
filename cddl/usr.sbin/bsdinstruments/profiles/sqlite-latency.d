/*
 * SQLite operation latency via pid-provider.
 *
 * Traces sqlite3_step (query execution) and sqlite3_exec
 * (convenience wrapper) timing. Most FreeBSD applications
 * that use SQLite link libsqlite3.so dynamically.
 *
 * Usage: bsdinstruments watch sqlite-latency --param pid=<pid>
 */

pid${pid}:libsqlite3.so:sqlite3_step:entry
{
    self->step_ts = timestamp;
}

pid${pid}:libsqlite3.so:sqlite3_step:return
/self->step_ts/
{
    this->elapsed_us = (timestamp - self->step_ts) / 1000;
    printf("%s[%d]: sqlite3_step %dus (ret=%d)\n",
        execname, pid, this->elapsed_us, arg1);
    @step_latency = quantize(this->elapsed_us);
    self->step_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}:libsqlite3.so:sqlite3_exec:entry
{
    self->exec_ts = timestamp;
}

pid${pid}:libsqlite3.so:sqlite3_exec:return
/self->exec_ts/
{
    this->elapsed_us = (timestamp - self->exec_ts) / 1000;
    printf("%s[%d]: sqlite3_exec %dus (ret=%d)\n",
        execname, pid, this->elapsed_us, arg1);
    @exec_latency = quantize(this->elapsed_us);
    self->exec_ts = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- sqlite3_step latency (us) ---\n");
    printa(@step_latency);
    printf("\n--- sqlite3_exec latency (us) ---\n");
    printa(@exec_latency);
}
