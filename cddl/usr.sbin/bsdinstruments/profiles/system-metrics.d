/*
 * System metrics — the conservative default set behind the otel_dtrace
 * rc.d service (see rc.conf(5) and otel.conf(5)).
 *
 * Only stable SDT providers, only probes that fire per event (a block
 * I/O, an exec, an exit, a signal) — never per
 * instruction, per syscall, per context switch or per page fault — and
 * only bounded aggregation keys (devices, directions, signals), never
 * processes.  Everything is aggregated in the kernel;
 * user space reads one snapshot per window.
 *
 *   io_latency_us      block I/O service time histogram by device
 *   io_bytes           block I/O bytes by device and direction
 *   exec / exec_failure / exits   process churn
 *   signals            signals sent, by signal number (crash signals)
 *
 * TCP state transitions (tcp:::state-change) are left out for now: on
 * this libdtrace, reading args[3]->tcps_state fails to link ("unsupported
 * bitfield encoding") or spins in the consumer.
 */

io:::start
{
    io_ts[arg0] = timestamp;
}

io:::done
/io_ts[arg0]/
{
    this->device = strjoin(stringof(args[1]->device_name),
        lltostr(args[1]->unit_number));
    this->direction = args[0]->bio_cmd == BIO_READ ? "read" : "write";
    @io_latency_us[this->device] = quantize((timestamp - io_ts[arg0]) / 1000);
    @io_bytes[this->device, this->direction] = sum(args[0]->bio_bcount);
    io_ts[arg0] = 0;
}

proc:::exec-success
{
    @exec = count();
}

proc:::exec-failure
{
    @exec_failure = count();
}

proc:::exit
{
    @exits = count();
}

proc:::signal-send
{
    this->signal = args[2];
    @signals[this->signal] = count();
}
