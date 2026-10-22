/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DT_PROG_ERRLEN 4096ull
#define DTD_SUB_READDATA 1
#define ELFDATA2LSB 1
typedef struct { int dt_is_guest; } dtrace_hdl_t;
typedef struct { int dp_haserror; char dp_err[DT_PROG_ERRLEN]; } dtrace_prog_t;
typedef char hypertrace_errmsg_t[512];
static int open_dtraced(int subscription) { (void)subscription; return -1; }
static int dtrace_elf_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int endian,
    int fd, const char *path, hypertrace_errmsg_t errmsg)
{
    (void)dtp; (void)pgp; (void)endian; (void)fd; (void)path; (void)errmsg;
    return -1;
}
static const char *dtrace_hypertrace_errstr(int error)
{
    (void)error;
    return "error";
}
static int dtrace_send_elf(dtrace_prog_t *pgp, int fromfd, int tofd,
    const char *location, int send_ident)
{
    (void)pgp; (void)fromfd; (void)tofd; (void)location; (void)send_ident;
    return -1;
}
#include "prog-error.inc"

int
main(void)
{
    char message[5000];
    memset(message, 'x', sizeof(message) - 1);
    message[sizeof(message) - 1] = '\0';
    for (int guest = 0; guest <= 1; guest++) {
        pid_t pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
            dtrace_hdl_t handle = { .dt_is_guest = guest };
            dtrace_prog_t program = {0};
            FILE *sink = freopen("/dev/null", "w", stderr);
            assert(sink != NULL);
            dt_set_progerr(&handle, &program, "%s", message);
            _exit(77); /* Reporting an error must never return. */
        }
        int status;
        assert(waitpid(pid, &status, 0) == pid);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
    }
    puts("PASS: oversized host and guest program errors do not return");
    return 0;
}
