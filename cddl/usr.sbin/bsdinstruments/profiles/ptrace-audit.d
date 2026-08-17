/*
 * Ptrace audit — debugger attach and process control.
 *
 * Traces ptrace(2) calls for security auditing. Shows
 * which processes attach to others, read memory, or
 * inject signals. Common in debugging and exploitation.
 */

syscall::ptrace:entry
/* @bsdinstruments-predicate */
{
    printf("%s[%d]: ptrace(req=%d, pid=%d)\n",
        execname, pid, arg0, arg1);
    @ptrace_ops[execname, arg0] = count();
    /* @bsdinstruments-stack */
    /* @bsdinstruments-ustack */
}

dtrace:::END
{
    printf("\n--- Ptrace operations by process/request ---\n");
    printf("%-20s %8s %8s\n", "EXECNAME", "REQ", "COUNT");
    printa("%-20s %8d %@8d\n", @ptrace_ops);
}
