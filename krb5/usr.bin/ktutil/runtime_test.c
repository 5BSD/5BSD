/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static pid_t child = -1;
static char response[16384];
static void fail(const char *what)
{
    fprintf(stderr, "%s: %s\n%s\n", what, strerror(errno), response);
    if (child > 0) { kill(child, SIGKILL); waitpid(child, NULL, 0); }
    exit(1);
}
static void expect(int fd, const char *text)
{
    size_t used = 0;
    response[0] = '\0';
    while (strstr(response, text) == NULL) {
        struct pollfd p = { .fd = fd, .events = POLLIN };
        int ready = poll(&p, 1, 10000);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0 || used == sizeof(response) - 1) fail("prompt timeout/overflow");
        ssize_t n = read(fd, response + used, sizeof(response) - used - 1);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("reading terminal");
        used += n; response[used] = '\0';
    }
}
static void sendline(int fd, const char *line)
{
    size_t left = strlen(line);
    while (left != 0) {
        ssize_t n = write(fd, line, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail("writing terminal");
        line += n; left -= n;
    }
}
int main(int argc, char **argv)
{
    char program[PATH_MAX], path[PATH_MAX], work[PATH_MAX];
    const char *tmp = getenv("TEST_TMPDIR");
    if (argc < 3 || tmp == NULL || realpath(argv[1], program) == NULL) fail("test inputs");
    size_t capacity = (size_t)argc * PATH_MAX;
    char *libraries = calloc(capacity, 1);
    if (libraries == NULL) fail("allocating library path");
    for (int i = 2; i < argc; i++) {
        if (realpath(argv[i], path) == NULL) fail("runtime library");
        char *slash = strrchr(path, '/');
        if (slash == NULL) fail("library directory");
        *slash = '\0';
        if (strlcat(libraries, i == 2 ? "" : ":", capacity) >= capacity ||
            strlcat(libraries, path, capacity) >= capacity) fail("library path length");
    }
    if (snprintf(work, sizeof(work), "%s/ktutil.XXXXXX", tmp) >= (int)sizeof(work) ||
        mkdtemp(work) == NULL || chdir(work) != 0) fail("test directory");
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) fail("pty allocation");
    char *name = ptsname(master);
    int slave = name ? open(name, O_RDWR | O_NOCTTY) : -1;
    if (slave < 0) fail("pty slave");
    child = fork();
    if (child < 0) fail("fork");
    if (child == 0) {
        if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0) _exit(125);
        for (int i = 0; i < 3; i++) if (dup2(slave, i) < 0) _exit(125);
        close(slave); close(master);
        if (setenv("LD_LIBRARY_PATH", libraries, 1) || setenv("KRB5_CONFIG", "/dev/null", 1) ||
            setenv("KRB5_KDC_PROFILE", "/dev/null", 1) || setenv("LC_ALL", "C", 1) ||
            setenv("HOME", work, 1) || setenv("TERM", "dumb", 1) || setenv("PATH", "/nonexistent", 1)) _exit(125);
        execl(program, program, (char *)NULL); _exit(127);
    }
    close(slave); free(libraries);
    expect(master, "ktutil:");
    sendline(master, "addent -key -p test@EXAMPLE.TEST -k 1 -e aes256-cts-hmac-sha1-96\n");
    expect(master, "(hex):");
    sendline(master, "0000000000000000000000000000000000000000000000000000000000000000\n");
    expect(master, "ktutil:");
    sendline(master, "wkt keytab\n"); expect(master, "ktutil:");
    int file = open("keytab", O_RDONLY);
    unsigned char magic[2]; struct stat st;
    if (file < 0 || fstat(file, &st) || st.st_size <= 2 || read(file, magic, 2) != 2 ||
        magic[0] != 5 || magic[1] != 2) fail("keytab write");
    close(file);
    sendline(master, "clear\n"); expect(master, "ktutil:");
    sendline(master, "list\n"); expect(master, "ktutil:");
    if (strstr(response, "test@EXAMPLE.TEST")) fail("clear list");
    sendline(master, "rkt keytab\n"); expect(master, "ktutil:");
    sendline(master, "list\n"); expect(master, "ktutil:");
    if (!strstr(response, "test@EXAMPLE.TEST")) fail("keytab reload");
    sendline(master, "delent 1\n"); expect(master, "ktutil:");
    sendline(master, "list\n"); expect(master, "ktutil:");
    if (strstr(response, "test@EXAMPLE.TEST")) fail("delete entry");
    sendline(master, "quit\n");
    int status = 0;
    pid_t ended = 0;
    /* Keep draining the PTY while readline restores its terminal settings. */
    struct timespec deadline, now;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline)) fail("shutdown clock");
    deadline.tv_sec += 10;
    while (ended == 0) {
        struct pollfd p = { .fd = master, .events = POLLIN };
        int ready = poll(&p, 1, 100);
        if (ready > 0) {
            char discard[4096];
            (void)read(master, discard, sizeof(discard));
        }
        ended = waitpid(child, &status, WNOHANG);
        if (ended < 0 && errno == EINTR) ended = 0;
        if (ended != 0) break;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("shutdown clock");
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) break;
        /* POLLHUP can be immediate before the child's exit becomes waitable. */
        struct timespec pause = { .tv_nsec = 10000000 };
        nanosleep(&pause, NULL);
    }
    if (ended != child) fail("ktutil shutdown timeout");
    child = -1;
    if (!WIFEXITED(status) || WEXITSTATUS(status)) fail("ktutil exit");
    close(master);
    if (unlink("keytab") || chdir(tmp) || rmdir(work)) fail("test cleanup");
    return 0;
}
