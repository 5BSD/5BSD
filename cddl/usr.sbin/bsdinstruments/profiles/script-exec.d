/* Script launch paths and interpreter exec outcomes; no argv or environments.
 * SPDX-License-Identifier: BSD-2-Clause */
#pragma D option quiet
dtrace:::BEGIN
{
    printf("SCRIPT_PROFILE_BEGIN\t1\n");
}
dtrace:::END
{
    printf("SCRIPT_PROFILE_END\t1\n");
}
syscall::execve:entry
/* @bsdinstruments-predicate */
{
    self->script_exec_path = copyinstr(arg0);
    printf("EXEC_ATTEMPT\t%llu\t%u\t%S\t%S\n", (unsigned long long)timestamp, pid,
        execname, self->script_exec_path);
}
syscall::fexecve:entry
/* @bsdinstruments-predicate */
{
    self->script_exec_path = "<fd-exec>";
    printf("EXEC_ATTEMPT\t%llu\t%u\t%S\t<fd-exec>\n", (unsigned long long)timestamp,
        pid, execname);
}
proc:::exec-success
/* @bsdinstruments-predicate */
{
    printf("EXEC_SUCCESS\t%llu\t%u\t%S\t%S\n", (unsigned long long)timestamp, pid,
        execname, self->script_exec_path);
    @execs[self->script_exec_path, execname] = count();
    self->script_exec_path = 0;
}
proc:::exec-failure
/* @bsdinstruments-predicate */
{
    printf("EXEC_FAILURE\t%llu\t%u\t%S\t%S\t%d\n", (unsigned long long)timestamp,
        pid, execname, self->script_exec_path, (int)arg0);
    self->script_exec_path = 0;
}
