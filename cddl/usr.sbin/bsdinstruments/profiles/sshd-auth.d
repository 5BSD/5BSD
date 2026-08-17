/*
 * SSH authentication event tracing.
 *
 * Traces sshd authentication attempts by monitoring the
 * auth-related syscalls and process lifecycle. Shows login
 * attempts, successful authentications, and session starts.
 */

proc:::exec-success
/execname == "sshd" /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: sshd exec-success ppid=%d uid=%d\n",
        execname, pid, ppid, uid);
    @sshd_execs[uid] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

proc:::exit
/execname == "sshd" /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: sshd exit uid=%d\n", execname, pid, uid);
    @sshd_exits[uid] = count();
}

syscall::accept:return
/execname == "sshd" /* @bsdinstruments-predicate-and *//
{
    printf("%s[%d]: sshd accept\n", execname, pid);
    @accepts = count();
}

dtrace:::END
{
    printf("\n--- sshd exec by uid ---\n");
    printf("%8s %8s\n", "UID", "COUNT");
    printa("%8d %@8d\n", @sshd_execs);
    printf("\n--- sshd exits by uid ---\n");
    printa("%8d %@8d\n", @sshd_exits);
    printf("\n--- sshd accepts ---\n");
    printa("%@d\n", @accepts);
}
