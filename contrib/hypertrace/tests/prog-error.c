/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/param.h>
#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* DT_PROG_ERRLEN comes from dt_program.h through the command line. */
#define DTD_SUB_READDATA 1
#define ELFDATA2LSB 1
typedef struct { int dt_is_guest; } dtrace_hdl_t;
typedef struct { int dp_haserror; char dp_err[DT_PROG_ERRLEN]; } dtrace_prog_t;
typedef char hypertrace_errmsg_t[512];

static int open_error, create_error, send_error;
static int opens, creates, sends, sock = -1;
static char created_path[MAXPATHLEN];

static int
open_dtraced(uint64_t subscription)
{
    assert(subscription == DTD_SUB_READDATA);
    opens++;
    if (open_error != 0) {
        errno = open_error;
        return -1;
    }
    sock = open("/dev/null", O_WRONLY);
    assert(sock >= 0);
    return sock;
}
static int
dtrace_elf_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int endian,
    int fd, const char *path, hypertrace_errmsg_t errmsg)
{
    assert(dtp != NULL && pgp != NULL && endian == ELFDATA2LSB && fd >= 0);
    assert(access(path, F_OK) == 0);
    creates++;
    (void)strlcpy(created_path, path, sizeof(created_path));
    assert(write(fd, "ELF", 3) == 3);
    if (create_error != 0)
        (void)strlcpy(errmsg, "no room", sizeof(hypertrace_errmsg_t));
    return create_error;
}
static const char *
dtrace_hypertrace_errstr(int error)
{
    assert(error == create_error);
    return "create error";
}
static int
dtrace_send_elf(dtrace_prog_t *pgp, int fromfd, int tofd,
    const char *location, int send_ident)
{
    char magic[3];

    assert(pgp != NULL && tofd == sock && send_ident == 0);
    assert(strcmp(location, "outbound") == 0);
    /* The program is sent from its start. */
    assert(read(fromfd, magic, sizeof(magic)) == 3 &&
        memcmp(magic, "ELF", 3) == 0);
    sends++;
    if (send_error != 0) {
        errno = send_error;
        return -1;
    }
    return 0;
}
#include "prog-error.inc"

static void
reset(dtrace_prog_t *program)
{
    memset(program, 0, sizeof(*program));
    open_error = create_error = send_error = 0;
    opens = creates = sends = 0;
    sock = -1;
    created_path[0] = '\0';
    errno = 0;
}

/* The temporary program is removed and the dtraced socket closed. */
static void
assert_released(const char *directory)
{
    struct dirent *entry;
    DIR *dir = opendir(directory);

    assert(dir != NULL);
    while ((entry = readdir(dir)) != NULL)
        assert(strncmp(entry->d_name, "ddtrace-set-prog-err.", 21) != 0);
    closedir(dir);
    if (created_path[0] != '\0')
        assert(access(created_path, F_OK) == -1 && errno == ENOENT);
    if (sock != -1)
        assert(fcntl(sock, F_GETFD) == -1 && errno == EBADF);
}

int
main(int argc, char **argv)
{
    static const char open_reason[] =
        "; failed to open dtraced: Connection refused";
    static dtrace_prog_t program;
    dtrace_hdl_t host = { .dt_is_guest = 0 }, guest = { .dt_is_guest = 1 };
    char message[DT_PROG_ERRLEN + 904], longdir[MAXPATHLEN + 1];
    size_t limit = sizeof(program.dp_err) - 1;

    assert(argc == 2);
    assert(setenv("TMPDIR", argv[1], 1) == 0);
    assert(freopen("/dev/null", "w", stderr) != NULL);
    memset(message, 'x', sizeof(message) - 1);
    message[sizeof(message) - 1] = '\0';

    /* No program: nothing to record, forward or print. */
    reset(&program);
    assert(dt_set_progerr(&guest, NULL, "%s", message) == 0 && opens == 0);

    /* A host records the error, cut to the buffer, and returns. */
    reset(&program);
    assert(dt_set_progerr(&host, &program, "%s", message) == 0);
    assert(program.dp_haserror == 1 && strlen(program.dp_err) == limit);
    assert(strspn(program.dp_err, "x") == limit && opens == 0);
    reset(&program);
    assert(dt_set_progerr(&host, &program, "bad %s %d", "probe", 7) == 0);
    assert(program.dp_haserror == 1 &&
        strcmp(program.dp_err, "bad probe 7") == 0);

    /* A guest forwards the program and releases what it used. */
    reset(&program);
    assert(dt_set_progerr(&guest, &program, "bad probe") == 0);
    assert(program.dp_haserror == 1 &&
        strcmp(program.dp_err, "bad probe") == 0);
    assert(opens == 1 && creates == 1 && sends == 1);
    assert_released(argv[1]);

    /* A failed forward keeps the error, appends the reason, sets errno. */
    reset(&program);
    open_error = ECONNREFUSED;
    assert(dt_set_progerr(&guest, &program, "bad probe") == -1);
    assert(errno == ECONNREFUSED && program.dp_haserror == 1);
    assert(strncmp(program.dp_err, "bad probe", 9) == 0 &&
        strcmp(program.dp_err + 9, open_reason) == 0);
    assert(opens == 1 && creates == 0 && sends == 0);
    assert_released(argv[1]);

    /* A full error is cut short so that the whole reason still fits. */
    reset(&program);
    open_error = ECONNREFUSED;
    assert(dt_set_progerr(&guest, &program, "%s", message) == -1);
    assert(errno == ECONNREFUSED && strlen(program.dp_err) == limit);
    assert(strspn(program.dp_err, "x") ==
        limit - (sizeof(open_reason) - 1) - 3);
    assert(strncmp(program.dp_err + strspn(program.dp_err, "x"), "...",
        3) == 0);
    assert(strcmp(program.dp_err + limit - (sizeof(open_reason) - 1),
        open_reason) == 0);

    reset(&program);
    create_error = 5;
    assert(dt_set_progerr(&guest, &program, "bad probe") == -1);
    assert(errno == EIO && strcmp(program.dp_err, "bad probe; "
        "dt_elf_create() failed: create error: no room") == 0);
    assert(opens == 1 && creates == 1 && sends == 0);
    assert_released(argv[1]);

    reset(&program);
    send_error = EPIPE;
    assert(dt_set_progerr(&guest, &program, "bad probe") == -1);
    assert(errno == EPIPE && strcmp(program.dp_err, "bad probe; "
        "dtrace_send_elf() failed: Broken pipe") == 0);
    assert(opens == 1 && creates == 1 && sends == 1);
    assert_released(argv[1]);

    /* The temporary file cannot be created: the socket is still closed. */
    reset(&program);
    assert(setenv("TMPDIR", "/nonexistent/prog-error", 1) == 0);
    assert(dt_set_progerr(&guest, &program, "bad probe") == -1);
    assert(errno == ENOENT && strcmp(program.dp_err, "bad probe; "
        "mkstemp() failed: No such file or directory") == 0);
    assert(opens == 1 && creates == 0 && sends == 0);
    assert_released(argv[1]);

    /* A name that cannot fit is refused before dtraced is opened. */
    reset(&program);
    memset(longdir, 'd', sizeof(longdir) - 1);
    longdir[0] = '/';
    longdir[sizeof(longdir) - 1] = '\0';
    assert(setenv("TMPDIR", longdir, 1) == 0);
    assert(dt_set_progerr(&guest, &program, "bad probe") == -1);
    assert(errno == ENAMETOOLONG && strcmp(program.dp_err, "bad probe; "
        "temporary file name too long") == 0);
    assert(opens == 0);

    puts("PASS: program errors are recorded and returned; a guest forwards "
        "them or reports why not");
    return 0;
}
