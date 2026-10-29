/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void recover_probe(int);
void abort_probe(int);

static int
check(void (*probe)(int), int overflow, int aborting)
{
    int fds[2], status;
    pid_t pid, waited;
    char message[1024];
    size_t used = 0;
    ssize_t n;

    if (pipe(fds) == -1 || (pid = fork()) == -1)
        return (1);
    if (pid == 0) {
        struct rlimit limit = {0, 0};
        close(fds[0]);
        if (setrlimit(RLIMIT_CORE, &limit) == -1 ||
            dup2(fds[1], STDERR_FILENO) == -1)
            _exit(126);
        close(fds[1]);
        probe(overflow);
        _exit(0);
    }
    close(fds[1]);
    while (used < sizeof(message) - 1) {
        n = read(fds[0], message + used, sizeof(message) - 1 - used);
        if (n == -1 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    close(fds[0]);
    do { waited = waitpid(pid, &status, 0); } while (waited == -1 && errno == EINTR);
    message[used] = '\0';
    if (waited != pid || n < 0 || used == sizeof(message) - 1)
        return (1);
    if (aborting ? (!WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT) :
        (!WIFEXITED(status) || WEXITSTATUS(status) != 0))
        return (1);
    if (overflow ? strstr(message, "ubsan: add-overflow by 0x") == NULL : used != 0) {
        fprintf(stderr, "unexpected sanitizer diagnostic: %s", message);
        return (1);
    }
    return (0);
}

int
main(void)
{
    if (check(recover_probe, 0, 0) || check(recover_probe, 1, 0) ||
        check(abort_probe, 1, 1))
        return (1);
    puts("minimal UBSan clean, recovery and abort paths passed");
    return (0);
}
