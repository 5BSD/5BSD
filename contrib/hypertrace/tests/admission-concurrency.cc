/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/un.h>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <pthread.h>
#include <unistd.h>
#include <vector>
#include "dtraced_io.h"
#include "dtraced_state.h"

static std::atomic_int fail_admission_after{-1};
extern "C" int __real_pthread_create(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
extern "C" int __wrap_pthread_create(pthread_t *thread,
    const pthread_attr_t *attr, void *(*start)(void *), void *arg)
{
    if (fail_admission_after.load() == 0) return EAGAIN;
    if (fail_admission_after.load() > 0) --fail_admission_after;
    return __real_pthread_create(thread, attr, start, arg);
}

namespace dtraced {
struct state_admission_test {
    static void partial_pool()
    {
        char directory[] = "/tmp/hypertrace-admission-fail.XXXXXX";
        assert(mkdtemp(directory) != nullptr);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        assert(snprintf(address.sun_path, sizeof(address.sun_path),
            "%s/sub.sock", directory) < (int)sizeof(address.sun_path));
        state s{};
        s.ctrlmachine = 1;
        s.shutdown.store(0);
        assert(sem_init(&s.socksema, 0, 0) == 0);
        s.socksema_initialized = true;
        s.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(s.sockfd >= 0);
        assert(bind(s.sockfd, (sockaddr *)&address, sizeof(address)) == 0);
        fail_admission_after.store(2);
        s.process_consumers();
        fail_admission_after.store(-1);
        assert(s.shutdown.load() == 1);
        assert(s.socket_start_done && s.socket_start_error == EAGAIN);
        assert(s.sockfds.empty());
        assert(close(s.kq_hdl) == 0);
        s.kq_hdl = -1;
        assert(sem_destroy(&s.socksema) == 0);
        close(s.sockfd);
        assert(unlink(address.sun_path) == 0);
        assert(rmdir(directory) == 0);
    }

    static void run()
    {
        char directory[] = "/tmp/hypertrace-admission.XXXXXX";
        assert(mkdtemp(directory) != nullptr);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        assert(snprintf(address.sun_path, sizeof(address.sun_path),
            "%s/sub.sock", directory) < (int)sizeof(address.sun_path));
        state s{};
        s.ctrlmachine = 1;
        s.shutdown.store(0);
        assert(sem_init(&s.socksema, 0, 0) == 0);
        s.socksema_initialized = true;
        s.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(s.sockfd >= 0);
        assert(bind(s.sockfd, (sockaddr *)&address, sizeof(address)) == 0);
        std::thread server(&state::process_consumers, &s);
        while (sem_wait(&s.socksema) == -1) assert(errno == EINTR);

        auto connect_client = [&]() {
            int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            assert(fd >= 0);
            assert(connect(fd, (sockaddr *)&address, sizeof(address)) == 0);
            dtd_initmsg_t hello{};
            size_t moved;
            assert(dtraced_io_transfer(fd, &hello, sizeof(hello), false,
                dtraced_io_milliseconds() + 1000, &moved) == 0);
            assert(hello.kind == DTRACED_KIND_DTRACED);
            return fd;
        };
        int slow = connect_client(); /* Leave its response unfinished. */
        std::mutex fast_mtx;
        std::vector<int> fast;
        std::vector<std::thread> connectors;
        for (int i = 0; i < 8; ++i)
            connectors.emplace_back([&] {
                int fd = connect_client();
                dtd_initmsg_t response{};
                response.protocol_version = DTRACED_PROTOCOL_VERSION;
                response.kind = DTRACED_KIND_CONSUMER;
                size_t moved;
                assert(dtraced_io_transfer(fd, &response,
                    sizeof(response), true,
                    dtraced_io_milliseconds() + 1000, &moved) == 0);
                std::lock_guard lock(fast_mtx);
                fast.push_back(fd);
            });
        for (std::thread &thread : connectors) thread.join();
        bool admitted = false;
        auto until = std::chrono::steady_clock::now() +
            std::chrono::milliseconds(1000);
        while (std::chrono::steady_clock::now() < until) {
            { std::lock_guard lock(s.sockfdsmtx);
              admitted = s.sockfds.size() == fast.size(); }
            if (admitted) break;
            usleep(5000);
        }
        assert(admitted); /* The slow peer still owns another worker. */
        s.shutdown.store(1);
        server.join();
        assert(s.sockfds.size() == fast.size());
        for (client_fd *client : s.sockfds) {
            assert(client->re_enable_write());
            s.client_events.remove(client->event_cookie);
            delete client;
        }
        s.sockfds.clear();
        assert(close(s.kq_hdl) == 0);
        s.kq_hdl = -1;
        close(slow);
        for (int fd : fast) close(fd);
        close(s.sockfd);
        assert(sem_destroy(&s.socksema) == 0);
        assert(unlink(address.sun_path) == 0);
        assert(rmdir(directory) == 0);
    }
};
}

int main()
{
    alarm(20);
    dtraced::state_admission_test::run();
    dtraced::state_admission_test::partial_pool();
    puts("PASS: slow handshake does not block another client; partial admission pool shuts down");
}
