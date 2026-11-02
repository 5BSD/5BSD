/* SPDX-License-Identifier: BSD-2-Clause */
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <future>
#include <sys/socket.h>
#include <sys/un.h>
#include <new>
#include <pthread.h>
#include <string>
#include <system_error>
#include <thread>
#include <unistd.h>
#include "dtraced_directory.h"
#include "dtraced_connection.h"
#include "dtraced_state.h"

static std::atomic_int fail_after{-1};
static std::atomic_int startup_gap_seen{0};
static pthread_t injection_owner;
static bool
process_startup_gap(dtraced::dir &directory, struct dirent *entry)
{
    if (strcmp(entry->d_name, "new") != 0 ||
        directory.memorized(entry->d_name))
        return true;
    startup_gap_seen++;
    return directory.memorize_file(entry);
}
extern "C" int __real_pthread_create(pthread_t *, const pthread_attr_t *,
    void *(*)(void *), void *);
extern "C" int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void *(*start)(void *), void *arg)
{
    if (!pthread_equal(pthread_self(), injection_owner))
        return __real_pthread_create(thread, attr, start, arg);
    if (fail_after.load() == 0) return EAGAIN;
    if (fail_after.load() > 0) --fail_after;
    return __real_pthread_create(thread, attr, start, arg);
}

namespace dtraced {
struct state_thread_test {
    static void run_reaper_wakeup()
    {
        state s{};
        s.shutdown.store(0);
        int kq = kqueue(), pair[2];
        assert(kq >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
        s.kq_hdl = kq;
        dtd_initmsg_t hello{};
        hello.kind = DTRACED_KIND_CONSUMER;
        auto *client = new client_fd(kq, pair[0], hello);
        client->cleaned_up = true;
        s.sockfds.insert(client);
        auto reaper = std::async(std::launch::async,
            [&] { s.close_filedescs(); });
        s.kill_socket(client);
        bool reclaimed = false;
        for (int i = 0; i < 200; ++i) {
            {
                std::lock_guard lock(s.deadfdsmtx);
                reclaimed = s.deadfds.empty();
            }
            if (reclaimed) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        assert(reclaimed); /* New retired sockets wake the reaper. */
        broadcast_shutdown(s);
        assert(reaper.wait_for(std::chrono::seconds(2)) ==
            std::future_status::ready); /* Shutdown does not sleep five seconds. */
        reaper.get();
        close(pair[1]); close(kq);
    }

    static void run_directory_gap()
    {
        char root[] = "/tmp/hypertrace-directory-gap.XXXXXX";
        assert(mkdtemp(root) != nullptr);
        state s{};
        s.shutdown.store(0);
        {
            dir directory(root, &process_startup_gap);
            directory.state = &s;
            assert(directory.populate_existing());
            int fd = openat(directory.dirfd, "new",
                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            assert(fd >= 0 && close(fd) == 0);
            std::thread listener([&] { assert(directory.listen()); });
            {
                std::unique_lock lock(s.socket_start_mtx);
                assert(s.socket_start_cv.wait_for(lock,
                    std::chrono::seconds(5), [&] {
                        return s.directory_start_done == 1;
                    }));
                assert(s.directory_start_error == 0);
            }
            assert(startup_gap_seen.load() == 1);
            broadcast_shutdown(s);
            listener.join();
            assert(unlinkat(directory.dirfd, "new", 0) == 0);
        }
        assert(rmdir(root) == 0);
    }

    static void run(int fail_at)
    {
        state s{};
        s.ctrlmachine = 1;
        s.threadpool_size = 3;
        s.shutdown.store(0);
        fail_after.store(fail_at);
        assert(!s.setup_threads());
        fail_after.store(-1);
        assert(errno == EAGAIN && s.shutdown.load() == 1);
        int started = 0;
        for (auto &worker : s.workers) {
            if (worker.joinable()) {
                worker.join();
                started++;
            }
        }
        assert(started == fail_at);
        assert(s.socksema_initialized);
        assert(sem_destroy(&s.socksema) == 0);
    }

    static void run_late(int fail_at, bool invalid_directory = false)
    {
        char root[] = "/tmp/hypertrace-threads.XXXXXX";
        assert(mkdtemp(root) != nullptr);
        std::string inbound = std::string(root) + "/inbound";
        std::string base = std::string(root) + "/base";
        std::string socket_path = std::string(root) + "/sub.sock";
        state s{};
        s.ctrlmachine = 1;
        s.threadpool_size = 3;
        s.shutdown.store(0);
        s.kq_hdl = -1;
        s.inbounddir = new dir(inbound.c_str(), &process_inbound);
        s.basedir = new dir(base.c_str(), &process_base);
        s.inbounddir->state = &s;
        s.basedir->state = &s;
        if (invalid_directory)
            s.basedir->dirfd = -1;
        s.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(s.sockfd >= 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        assert(socket_path.size() < sizeof(address.sun_path));
        strcpy(address.sun_path, socket_path.c_str());
        assert(bind(s.sockfd, (sockaddr *)&address, sizeof(address)) == 0);

        fail_after.store(fail_at);
        bool ready = s.setup_threads();
        fail_after.store(-1);
        if (invalid_directory) {
            assert(!ready && errno == EBADF && s.shutdown.load() == 1 &&
                s.directory_start_error == EBADF);
        } else if (fail_at >= 0)
            assert(!ready && errno == EAGAIN && s.shutdown.load() == 1);
        else {
            assert(ready && s.socket_start_done &&
                s.socket_start_error == 0 && s.directory_start_done == 2 &&
                s.directory_start_error == 0 && s.shutdown.load() == 0);
            broadcast_shutdown(s);
        }
        int started = 0;
        auto join = [&](std::thread &thread) {
            if (thread.joinable()) { thread.join(); started++; }
        };
        for (auto &worker : s.workers) join(worker);
        join(s.socktd);
        join(s.inboundtd);
        join(s.basetd);
        join(s.killtd);
        join(s.reaptd);
        join(s.closetd);
        join(s.jobcleantd);
        /* Three workers, four host consumer delivery workers, seven more. */
        assert(started == (fail_at >= 0 ? fail_at : 14));
        if (s.kq_hdl >= 0) assert(close(s.kq_hdl) == 0);
        s.kq_hdl = -1;
        assert(s.socksema_initialized);
        assert(sem_destroy(&s.socksema) == 0);
        assert(close(s.sockfd) == 0);
        delete s.inbounddir;
        delete s.basedir;
        assert(unlink(socket_path.c_str()) == 0);
        assert(rmdir(inbound.c_str()) == 0);
        assert(rmdir(base.c_str()) == 0);
        assert(rmdir(root) == 0);
    }

    static void run_guest_transport(int fail_at)
    {
        state s{};
        int pipefds[2];
        assert(pipe2(pipefds, O_NONBLOCK | O_CLOEXEC) == 0);
        s.ctrlmachine = 0;
        s.threadpool_size = 3;
        s.dtt_fd = pipefds[0];
        s.shutdown.store(0);
        fail_after.store(fail_at);
        assert(!s.setup_threads());
        fail_after.store(-1);
        assert(errno == EAGAIN && s.shutdown.load() == 1);
        int started = 0;
        for (auto &worker : s.workers)
            if (worker.joinable()) { worker.join(); started++; }
        if (s.dtt_listentd.joinable()) { s.dtt_listentd.join(); started++; }
        assert(!s.dtt_writetd.joinable());
        assert(started == fail_at);
        assert(sem_destroy(&s.socksema) == 0);
        close(pipefds[0]);
        close(pipefds[1]);
    }
};
}

int main()
{
    injection_owner = pthread_self();
    alarm(60);
    /* Prove that the interposition reaches libc++ before touching state. */
    fail_after.store(0);
    bool injected = false;
    try {
        std::thread probe([] {});
        probe.join();
    } catch (const std::system_error &e) {
        injected = e.code().value() == EAGAIN;
    }
    fail_after.store(-1);
    assert(injected);
    dtraced::state_thread_test::run(0);
    dtraced::state_thread_test::run(1);
    dtraced::state_thread_test::run(2);
    dtraced::state_thread_test::run(3);
    for (int failure = 4; failure <= 13; ++failure)
        dtraced::state_thread_test::run_late(failure);
    dtraced::state_thread_test::run_late(-1);
    dtraced::state_thread_test::run_late(-1, true);
    dtraced::state_thread_test::run_directory_gap();
    dtraced::state_thread_test::run_reaper_wakeup();
    dtraced::state_thread_test::run_guest_transport(3);
    dtraced::state_thread_test::run_guest_transport(4);
    puts("PASS: partial host and guest daemon thread starts shut down and join");
}
