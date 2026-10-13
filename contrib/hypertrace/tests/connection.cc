// SPDX-License-Identifier: BSD-2-Clause
// Exercise the real imported connection implementation using local sockets.
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include "dtraced_connection.h"

void dump_logmsg(const char *, int, const char *, ...) {}
void dump_errmsg(const char *, int, const char *, ...) {}
static bool interrupt_send, interrupt_recv, short_send;
extern "C" ssize_t __real_send(int, const void *, size_t, int);
extern "C" ssize_t __real_recv(int, void *, size_t, int);
extern "C" ssize_t __wrap_send(int fd, const void *p, size_t n, int flags) {
    if (interrupt_send) { interrupt_send = false; errno = EINTR; return -1; }
    if (short_send && n > 2) n = 2;
    return __real_send(fd, p, n, flags);
}
extern "C" ssize_t __wrap_recv(int fd, void *p, size_t n, int flags) {
    if (interrupt_recv) { interrupt_recv = false; errno = EINTR; return -1; }
    if (n > 3) n = 3;
    return __real_recv(fd, p, n, flags);
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s failed (errno %d)\n", __FILE__, __LINE__, #x, errno); return 1; } } while (0)
int main(int argc, char **argv) {
    CHECK(argc == 2);
    std::string test = argv[1];
    int sv[2]; CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    timeval timeout {1, 0};
    CHECK(setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    CHECK(setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    dtd_initmsg_t init {};
    memset(init.ident, 'x', sizeof(init.ident));
    auto *c = new dtraced::client_fd(-1, sv[0], init);
    if (test == "identifier") {
        CHECK(c->ident[sizeof(c->ident) - 1] == '\0');
        CHECK(std::string(*c).size() < sizeof(init.ident) + 20);
    } else if (test == "close-reuse") {
        int old = sv[0]; c->close();
        int replacement = open("/dev/null", O_RDONLY); CHECK(replacement >= 0);
        if (replacement != old) { CHECK(dup2(replacement, old) == old); close(replacement); }
        delete c; c = nullptr;
        CHECK(fcntl(old, F_GETFD) != -1); close(old);
    } else if (test == "send-short" || test == "send-eintr") {
        short_send = test == "send-short";
        interrupt_send = test == "send-eintr";
        char payload[] = "a complete framed message", got[sizeof(payload)];
        CHECK(c->send(payload, sizeof(payload)));
        CHECK(__real_recv(sv[1], got, sizeof(got), MSG_WAITALL) == sizeof(got));
        CHECK(memcmp(got, payload, sizeof(got)) == 0);
    } else if (test == "recv-eintr" || test == "recv-eof") {
        char payload[] = "another message", got[sizeof(payload)];
        CHECK(__real_send(sv[1], payload, sizeof(payload), 0) == sizeof(payload));
        interrupt_recv = true;
        CHECK(c->recv(got, sizeof(got))); CHECK(memcmp(got, payload, sizeof(got)) == 0);
        if (test == "recv-eof") { close(sv[1]); sv[1] = -1; CHECK(!c->recv(got, 1)); }
    } else if (test == "ack-error") {
        c->close(); CHECK(c->send_ack() == -1); CHECK(c->send_nak() == -1);
    } else if (test == "peer-closed") {
        close(sv[1]); sv[1] = -1;
        // Default SIGPIPE disposition: a correct implementation must survive.
        signal(SIGPIPE, SIG_DFL); CHECK(c->send_ack() == -1);
    } else if (test == "release-underflow") {
        pid_t child = fork(); CHECK(child >= 0);
        if (child == 0) { rlimit lim {0,0}; setrlimit(RLIMIT_CORE, &lim); c->release(); _exit(0); }
        int status; CHECK(waitpid(child, &status, 0) == child);
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
#ifdef PATCHED
    } else if (test == "reap-gates") {
        CHECK(!c->can_reap());
        c->acquire(); CHECK(!c->can_reap());
        c->cleaned_up = true; CHECK(!c->can_reap());
        c->release(); CHECK(c->can_reap());
    } else if (test == "one-response") {
        CHECK(c->respond(false)); CHECK(c->respond(true));
        unsigned char got[4];
        CHECK(__real_recv(sv[1], got, 2, MSG_WAITALL) == 2);
        CHECK(got[0] == 0 && got[1] == 1);
        CHECK(__real_recv(sv[1], got, 1, MSG_DONTWAIT) == -1);
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
#endif
    } else { fprintf(stderr, "unknown case\n"); return 1; }
    delete c; if (sv[1] != -1) close(sv[1]);
    printf("PASS %s\n", argv[1]); return 0;
}
