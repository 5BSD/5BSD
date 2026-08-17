/*
 * Casper/libcasper service audit.
 *
 * Traces Casper service operations via pid-provider probes
 * into libcasper. Shows cap_service_open, cap_dns, cap_sysctl,
 * and cap_grp/cap_pwd lookups. Requires the target process to
 * link libcasper dynamically.
 *
 * Usage: bsdinstruments watch casper-audit --param pid=<pid>
 * FreeBSD-specific (libcasper).
 */

pid${pid}:libcasper.so:cap_service_open:entry
{
    printf("%s[%d]: cap_service_open\n", execname, pid);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

pid${pid}:libcasper.so:cap_service_limit:entry
{
    printf("%s[%d]: cap_service_limit\n", execname, pid);
}

pid${pid}:libcap_dns.so:cap_gethostbyname:entry
{
    printf("%s[%d]: cap_gethostbyname\n", execname, pid);
    @casper_calls[execname, "cap_dns"] = count();
}

pid${pid}:libcap_dns.so:cap_getaddrinfo:entry
{
    printf("%s[%d]: cap_getaddrinfo\n", execname, pid);
    @casper_calls[execname, "cap_dns"] = count();
}

pid${pid}:libcap_sysctl.so:cap_sysctlbyname:entry
{
    printf("%s[%d]: cap_sysctlbyname\n", execname, pid);
    @casper_calls[execname, "cap_sysctl"] = count();
}

pid${pid}:libcap_pwd.so:cap_getpwnam:entry
{
    printf("%s[%d]: cap_getpwnam\n", execname, pid);
    @casper_calls[execname, "cap_pwd"] = count();
}

pid${pid}:libcap_pwd.so:cap_getpwuid:entry
{
    printf("%s[%d]: cap_getpwuid\n", execname, pid);
    @casper_calls[execname, "cap_pwd"] = count();
}

pid${pid}:libcap_grp.so:cap_getgrnam:entry
{
    printf("%s[%d]: cap_getgrnam\n", execname, pid);
    @casper_calls[execname, "cap_grp"] = count();
}

pid${pid}:libcap_grp.so:cap_getgrgid:entry
{
    printf("%s[%d]: cap_getgrgid\n", execname, pid);
    @casper_calls[execname, "cap_grp"] = count();
}

dtrace:::END
{
    printf("\n--- Casper service calls by process/service ---\n");
    printa("%-20s %-14s %@d\n", @casper_calls);
}
