/*
 * TLS handshake latency via OpenSSL/LibreSSL pid provider.
 *
 * Times SSL_do_handshake to measure TLS connection setup
 * overhead. Slow handshakes indicate certificate chain issues,
 * cipher negotiation problems, or network latency.
 * Usage: bsdinstruments watch openssl-handshake --param pid=<pid>
 */

pid${pid}::SSL_do_handshake:entry
{
    self->hs_ts = timestamp;
    /* @bsdinstruments-ustack */
}

pid${pid}::SSL_do_handshake:return
/self->hs_ts/
{
    this->us = (timestamp - self->hs_ts) / 1000;
    printf("%s[%d]: TLS handshake %dus\n", execname, pid, this->us);
    @latency = quantize(this->us);
    @count[execname] = count();
    self->hs_ts = 0;
}

dtrace:::END
{
    printf("\n--- TLS handshake latency (us) ---\n");
    printa(@latency);
    printf("\n--- TLS handshake count ---\n");
    printa("%-30s %@d\n", @count);
}
