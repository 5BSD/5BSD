/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "libprocstat.h"

int
main(int argc, char **argv)
{
    struct procstat *state;
    struct kinfo_proc *process;
    char **observed;
    unsigned int count = 0;
    int result = 1;

    if (argc < 1)
        return (1);
    state = procstat_open_sysctl();
    if (state == NULL)
        return (1);
    process = procstat_getprocs(state, KERN_PROC_PID, getpid(), &count);
    if (process == NULL || count != 1 || process[0].ki_pid != getpid()) {
        fprintf(stderr, "self process lookup failed (count %u)\n", count);
        goto done;
    }
    observed = procstat_getargv(state, process, 0);
    if (observed == NULL || observed[0] == NULL ||
        strcmp(observed[0], argv[0]) != 0) {
        fprintf(stderr, "self argument lookup failed\n");
        goto done;
    }
    result = 0;
done:
    if (process != NULL)
        procstat_freeprocs(state, process);
    procstat_close(state);
    return (result);
}
