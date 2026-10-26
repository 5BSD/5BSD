/*
 * Block I/O snoop — per-event I/O with process, size, and latency.
 *
 * Like io-latency but prints every I/O event individually instead
 * of aggregating. Shows process, device, bytes, and microseconds
 * for each I/O completion. High-overhead — use with filters.
 * Structured formats also emit one span per I/O, attributed to the
 * issuing process (completion runs in another thread), in error
 * when the bio reports one.
 */

io:::start
/* @bsdinstruments-predicate */
{
    start_ts[arg0] = timestamp;
    start_exec[arg0] = execname;
    start_pid[arg0] = pid;
    start_tid[arg0] = tid;
}

io:::done
/start_ts[arg0]/
{
    this->us = (timestamp - start_ts[arg0]) / 1000;
    printf("%s[%d]: %s %d bytes %dus\n",
        start_exec[arg0], start_pid[arg0],
        ((struct bio *)arg0)->bio_cmd == 0x01 ? "R" : "W",
        ((struct bio *)arg0)->bio_bcount, this->us);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    /* @bsdinstruments-span(name="block io", start=start_ts[arg0],
        thread=start_tid[arg0], pid=start_pid[arg0],
        execname=start_exec[arg0],
        error=((struct bio *)arg0)->bio_error,
        str.disk.io.direction=((struct bio *)arg0)->bio_cmd == 0x01 ?
            "read" : "write",
        int.disk.io.bytes=((struct bio *)arg0)->bio_bcount) */
    start_ts[arg0] = 0;
    start_exec[arg0] = 0;
    start_pid[arg0] = 0;
    start_tid[arg0] = 0;
}
