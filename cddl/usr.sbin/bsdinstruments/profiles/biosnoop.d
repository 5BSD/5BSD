/*
 * Block I/O snoop — per-event I/O with process, size, and latency.
 *
 * Like io-latency but prints every I/O event individually instead
 * of aggregating. Shows process, device, bytes, and microseconds
 * for each I/O completion. High-overhead — use with filters.
 */

io:::start
/* @bsdinstruments-predicate */
{
    start_ts[arg0] = timestamp;
    start_exec[arg0] = execname;
    start_pid[arg0] = pid;
}

io:::done
/start_ts[arg0]/
{
    this->us = (timestamp - start_ts[arg0]) / 1000;
    printf("%s[%d]: %s %d bytes %dus\n",
        start_exec[arg0], start_pid[arg0],
        args[0]->b_flags & 0x00000001 ? "R" : "W",
        args[0]->b_bcount, this->us);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
    start_ts[arg0] = 0;
    start_exec[arg0] = 0;
    start_pid[arg0] = 0;
}
