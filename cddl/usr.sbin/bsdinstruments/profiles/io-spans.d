/*
 * Read/write spans with their block I/O as child spans.
 *
 * Each read(2)/write(2) becomes a span; every block I/O it issues
 * becomes a child span of it, even though the I/O completes in
 * another thread, so a trace shows where a slow read spent its time.
 * Text output prints one line per syscall and per I/O.  Structured
 * formats only: the spans need --format json, otel or otlp-json.
 */

syscall::read:entry,
syscall::write:entry
/* @bsdinstruments-predicate */
{
    self->rw_ts = timestamp;
}

io:::start
/self->rw_ts/
{
    io_ts[arg0] = timestamp;
    io_parent[arg0] = self->rw_ts;
    io_tid[arg0] = tid;
    io_pid[arg0] = pid;
    io_exec[arg0] = execname;
}

io:::done
/io_ts[arg0]/
{
    printf("%s[%d]: io %d bytes %dus\n", io_exec[arg0], io_pid[arg0],
        ((struct bio *)arg0)->bio_bcount,
        (timestamp - io_ts[arg0]) / 1000);
    /* @bsdinstruments-span(name="block io", start=io_ts[arg0],
        parent=io_parent[arg0], thread=io_tid[arg0], pid=io_pid[arg0],
        execname=io_exec[arg0], error=((struct bio *)arg0)->bio_error,
        int.disk.io.bytes=((struct bio *)arg0)->bio_bcount) */
    io_ts[arg0] = 0;
    io_parent[arg0] = 0;
    io_tid[arg0] = 0;
    io_pid[arg0] = 0;
    io_exec[arg0] = 0;
}

syscall::read:return,
syscall::write:return
/self->rw_ts/
{
    printf("%s[%d]: %s %dus\n", execname, pid, probefunc,
        (timestamp - self->rw_ts) / 1000);
    /* @bsdinstruments-span(name=probefunc, start=self->rw_ts,
        error=errno, int.result=(int64_t)arg1) */
    self->rw_ts = 0;
}
