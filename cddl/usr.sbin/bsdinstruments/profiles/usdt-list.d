/*
 * Discover pid-provider (function-level) probes by firing them at runtime.
 *
 * Attaches to every entry probe in a process via the pid provider
 * and prints the full probe name on each firing. This traces all
 * function entries, not just USDT static probes. This is a runtime
 * discovery tool — only probes that fire during the window appear.
 *
 * For a static probe listing, use `bsdinstruments probes --pid <pid>`.
 *
 * Usage: bsdinstruments watch usdt-list --param pid=<pid> --duration 1
 */

pid${pid}:::entry
{
    printf("%s[%d]: %s:%s:%s:%s\n",
        execname, pid, probeprov, probemod, probefunc, probename);
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}
