/*
 * DNS resolution latency — getaddrinfo/gethostbyname timing.
 *
 * Traces DNS resolution calls through libc. Requires the
 * target process to link libc dynamically (most do).
 * Usage: bsdinstruments watch dns-latency --param pid=<pid>
 */

pid${pid}:libc.so.7:getaddrinfo:entry
{
    self->dns_ts = timestamp;
    self->dns_func = "getaddrinfo";
}

pid${pid}:libc.so.7:getnameinfo:entry
{
    self->dns_ts = timestamp;
    self->dns_func = "getnameinfo";
}

pid${pid}:libc.so.7:gethostbyname:entry
{
    self->dns_ts = timestamp;
    self->dns_func = "gethostbyname";
}

pid${pid}:libc.so.7:gethostbyname2:entry
{
    self->dns_ts = timestamp;
    self->dns_func = "gethostbyname2";
}

pid${pid}:libc.so.7:getaddrinfo:return,
pid${pid}:libc.so.7:getnameinfo:return
/self->dns_ts/
{
    this->elapsed_us = (timestamp - self->dns_ts) / 1000;
    printf("%s[%d]: %s %dus (status=%d)\n",
        execname, pid, self->dns_func, this->elapsed_us, arg1);
    @latency[self->dns_func] = quantize(this->elapsed_us);
    self->dns_ts = 0;
    self->dns_func = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}:libc.so.7:gethostbyname:return,
pid${pid}:libc.so.7:gethostbyname2:return
/self->dns_ts/
{
    this->elapsed_us = (timestamp - self->dns_ts) / 1000;
    printf("%s[%d]: %s %dus (result=%s)\n",
        execname, pid, self->dns_func, this->elapsed_us,
        arg1 != 0 ? "ok" : "NULL");
    @latency[self->dns_func] = quantize(this->elapsed_us);
    self->dns_ts = 0;
    self->dns_func = 0;
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- DNS resolution latency (us) ---\n");
    printa(@latency);
}
