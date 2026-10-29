/*
 * System metrics — the conservative default set behind the otel_dtrace
 * rc.d service (see rc.conf(5) and otel.conf(5)).
 *
 * Only stable SDT providers, only probes that fire per event (a block
 * I/O, an exec, an exit, a signal, a TCP state transition) — never per
 * instruction, per syscall, per context switch or per page fault — and
 * only bounded aggregation keys (devices, directions, signals, TCP
 * states), never processes or addresses.  Everything is aggregated in
 * the kernel; the service reads one cumulative snapshot per
 * otel_dtrace_window (bsdinstruments --interval) without restarting, so
 * sums never reset.  The profile prints nothing: no log records, spans
 * or context markers, only the probe clock's once-a-second anchor
 * besides these probes.
 *
 * Exported as bsdinstruments.system-metrics.<name>; "__" in a
 * clause-local key name stands for "." so the dimensions carry
 * OpenTelemetry semantic-convention names:
 *
 *   io_latency_us      block I/O service time histogram by system.device
 *   io_bytes           block I/O bytes by system.device and
 *                      disk.io.direction (read, write)
 *   exec / exec_failure / exits   process churn
 *   signals            signals sent, by signal number (crash signals)
 *   tcp_state_changes  TCP state transitions by the new state as
 *                      network.connection.state (close, close_wait,
 *                      closing, established, fin_wait_1, fin_wait_2,
 *                      last_ack, listen, syn_recv, syn_sent, time_wait;
 *                      TCPS_CLOSED is "close")
 */

io:::start
{
    io_ts[arg0] = timestamp;
}

io:::done
/io_ts[arg0]/
{
    this->system__device = strjoin(stringof(args[1]->device_name),
        lltostr(args[1]->unit_number));
    this->disk__io__direction = args[0]->bio_cmd == BIO_READ ? "read" :
        "write";
    @io_latency_us[this->system__device] =
        quantize((timestamp - io_ts[arg0]) / 1000);
    @io_bytes[this->system__device, this->disk__io__direction] =
        sum(args[0]->bio_bcount);
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

tcp:::state-change
/args[3]->tcps_state >= TCPS_CLOSED && args[3]->tcps_state <= TCPS_TIME_WAIT/
{
    this->tcp_state = args[3]->tcps_state;
    this->network__connection__state =
        this->tcp_state == TCPS_CLOSED ? "close" :
        this->tcp_state == TCPS_LISTEN ? "listen" :
        this->tcp_state == TCPS_SYN_SENT ? "syn_sent" :
        this->tcp_state == TCPS_SYN_RECEIVED ? "syn_recv" :
        this->tcp_state == TCPS_ESTABLISHED ? "established" :
        this->tcp_state == TCPS_CLOSE_WAIT ? "close_wait" :
        this->tcp_state == TCPS_FIN_WAIT_1 ? "fin_wait_1" :
        this->tcp_state == TCPS_CLOSING ? "closing" :
        this->tcp_state == TCPS_LAST_ACK ? "last_ack" :
        this->tcp_state == TCPS_FIN_WAIT_2 ? "fin_wait_2" : "time_wait";
    @tcp_state_changes[this->network__connection__state] = count();
}
