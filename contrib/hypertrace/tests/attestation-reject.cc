/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/hypertrace.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <fcntl.h>
#include <thread>
#include <unistd.h>
#include "dtraced_io.h"
#include "dtraced_connection.h"
#include "dtraced_state.h"

static bool fake_attestation, fake_epoch_live, fake_epoch_open_fail;
static int fake_epoch_backing = -1, fake_epoch_fd = -1;

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
        if (fake_epoch_open_fail) {
            errno = EACCES;
            return -1;
        }
        assert(fake_epoch_backing >= 0);
        fake_epoch_fd = dup(fake_epoch_backing);
        return fake_epoch_fd;
    }
    return __real_open(path, flags, mode);
}

extern "C" int
__wrap_ioctl(int fd, unsigned long command, ...)
{
    va_list args;
    va_start(args, command);
    void *data = va_arg(args, void *);
    va_end(args);
    if (command == VM_GET_ATTESTATION && fake_attestation) {
        hypertrace_vm_attestation identity{};
        identity.vmid = 7;
        identity.epoch = 11;
        strcpy(identity.name, "source-vm");
        memcpy(data, &identity, sizeof(identity));
        return 0;
    }
    if (command == HYPERTRACE_IOC_EPOCH_QUERY && fd == fake_epoch_fd) {
        auto *query = static_cast<hypertrace_epoch_query *>(data);
        assert(query->vmid == 7 && query->epoch == 11 &&
            query->live == 0 && query->reserved2 == 0);
        query->live = fake_epoch_live ? 1 : 0;
        return 0;
    }
    errno = ENOTTY;
    return -1;
}

namespace dtraced {
struct state_attestation_test {
static void guest_forwarder()
{
    char directory[] = "/tmp/hypertrace-guest-admission.XXXXXX";
    assert(mkdtemp(directory) != nullptr);
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    assert(snprintf(address.sun_path, sizeof(address.sun_path),
        "%s/sub.sock", directory) < (int)sizeof(address.sun_path));
    state guest{};
    guest.ctrlmachine = 0;
    guest.kq_hdl = kqueue();
    guest.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(guest.kq_hdl >= 0 && guest.sockfd >= 0);
    assert(bind(guest.sockfd, (sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(guest.sockfd, 1) == 0);
    std::atomic_bool release{false};
    std::thread client([&] {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        assert(connect(fd, (sockaddr *)&address, sizeof(address)) == 0);
        dtd_initmsg_t hello{};
        size_t transferred;
        int64_t deadline = dtraced_io_milliseconds() + 2000;
        assert(dtraced_io_transfer(fd, &hello, sizeof(hello), false,
            deadline, &transferred) == 0);
        assert(hello.kind == DTRACED_KIND_DTRACED);
        hello = {};
        hello.kind = DTRACED_KIND_FORWARDER;
        hello.protocol_version = DTRACED_PROTOCOL_VERSION;
        hello.subs = DTD_SUB_ELFWRITE | DTD_SUB_ADMISSION_ACK;
        strcpy(hello.ident, "guest-local-transport");
        hello.session_id[0] = 0x42;
        assert(dtraced_io_transfer(fd, &hello, sizeof(hello), true,
            deadline, &transferred) == 0);
        uint8_t ack = 0;
        assert(dtraced_io_transfer(fd, &ack, sizeof(ack), false,
            deadline, &transferred) == 0 && ack == 1);
        while (!release.load()) usleep(1000);
        close(fd);
    });
    /* No host delivery ledger or VM attestation exists in the guest. */
    assert(guest.accept_new_connection());
    assert(guest.sockfds.size() == 1);
    client_fd *accepted = *guest.sockfds.begin();
    assert(accepted->kind == DTRACED_KIND_FORWARDER &&
        accepted->is_subscribed(DTD_SUB_ELFWRITE) &&
        accepted->is_subscribed(DTD_SUB_ADMISSION_ACK) &&
        accepted->session_id[0] == 0x42);
    release.store(true);
    client.join();
    guest.client_events.remove(accepted->event_cookie);
    guest.sockfds.clear();
    delete accepted;
    close(guest.kq_hdl); close(guest.sockfd);
    assert(unlink(address.sun_path) == 0);
    assert(rmdir(directory) == 0);
}

static void run()
{
    char directory[] = "/tmp/hypertrace-attestation.XXXXXX";
    sockaddr_un address{};
    state state{};
    assert(mkdtemp(directory) != nullptr);
    address.sun_family = AF_UNIX;
    assert(snprintf(address.sun_path, sizeof(address.sun_path),
        "%s/sub.sock", directory) < (int)sizeof(address.sun_path));
    state.ctrlmachine = 1;
    state.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(state.sockfd >= 0);
    assert(bind(state.sockfd, (sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(state.sockfd, 1) == 0);
    std::thread client([&] {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        assert(fd >= 0);
        assert(connect(fd, (sockaddr *)&address, sizeof(address)) == 0);
        dtd_initmsg_t hello{};
        size_t transferred;
        int64_t deadline = dtraced_io_milliseconds() + 2000;
        assert(dtraced_io_transfer(fd, &hello, sizeof(hello), false,
            deadline, &transferred) == 0);
        assert(hello.kind == DTRACED_KIND_DTRACED);
        hello = {};
        hello.kind = DTRACED_KIND_FORWARDER;
        hello.protocol_version = DTRACED_PROTOCOL_VERSION;
        hello.subs = DTD_SUB_READDATA;
        strcpy(hello.ident, "claimed-vm");
        hello.session_id[0] = 0x42;
        assert(dtraced_io_transfer(fd, &hello, sizeof(hello), true,
            deadline, &transferred) == 0);
        int counterfeit = open("/dev/null", O_RDONLY | O_CLOEXEC);
        assert(counterfeit >= 0);
        assert(dtraced_io_send_fd(fd, counterfeit, deadline) == 0);
        close(counterfeit);
        close(fd);
    });
    assert(!state.accept_new_connection());
    assert(errno == EPERM && state.sockfds.empty());
    client.join();
    close(state.sockfd);
    assert(unlink(address.sun_path) == 0);
    assert(rmdir(directory) == 0);
}

static void source_release_admission()
{
    char directory[] = "/tmp/hypertrace-release-admission.XXXXXX";
    sockaddr_un address{};
    assert(mkdtemp(directory) != nullptr);
    address.sun_family = AF_UNIX;
    assert(snprintf(address.sun_path, sizeof(address.sun_path),
        "%s/sub.sock", directory) < (int)sizeof(address.sun_path));
    state host{};
    host.ctrlmachine = 1;
    host.kq_hdl = kqueue();
    host.sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(host.kq_hdl >= 0 && host.sockfd >= 0);
    assert(bind(host.sockfd, (sockaddr *)&address, sizeof(address)) == 0);
    assert(listen(host.sockfd, 2) == 0);
    fake_epoch_backing = open("/dev/null", O_RDONLY | O_CLOEXEC);
    assert(fake_epoch_backing >= 0);
    fake_attestation = true;
    for (int attempt = 0; attempt < 3; attempt++) {
        fake_epoch_open_fail = attempt == 0;
        fake_epoch_live = attempt == 2;
        std::atomic_bool release{false};
        std::thread client([&] {
            int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            assert(fd >= 0 &&
                connect(fd, (sockaddr *)&address, sizeof(address)) == 0);
            dtd_initmsg_t hello{};
            size_t transferred;
            int64_t deadline = dtraced_io_milliseconds() + 2000;
            assert(dtraced_io_transfer(fd, &hello, sizeof(hello), false,
                deadline, &transferred) == 0);
            hello = {};
            hello.kind = DTRACED_KIND_FORWARDER;
            hello.protocol_version = DTRACED_PROTOCOL_VERSION;
            hello.subs = DTD_SUB_SOURCE_RELEASE | DTD_SUB_ADMISSION_ACK;
            strcpy(hello.ident, "source-vm");
            hello.session_id[0] = 0x42;
            assert(dtraced_io_transfer(fd, &hello, sizeof(hello), true,
                deadline, &transferred) == 0);
            int attestation = open("/dev/null", O_RDONLY | O_CLOEXEC);
            assert(attestation >= 0 &&
                dtraced_io_send_fd(fd, attestation, deadline) == 0);
            close(attestation);
            if (attempt == 2) {
                uint8_t ack = 0;
                assert(dtraced_io_transfer(fd, &ack, 1, false,
                    deadline, &transferred) == 0 && ack == 1);
                while (!release.load()) usleep(1000);
            }
            close(fd);
        });
        bool accepted = host.accept_new_connection();
        assert(accepted == (attempt == 2));
        if (accepted) {
            assert(host.sockfds.size() == 1);
            client_fd *channel = *host.sockfds.begin();
            int kernel_fd = channel->vm_epoch_query_fd;
            assert(kernel_fd >= 0 &&
                fcntl(kernel_fd, F_GETFD) >= 0);
            release.store(true);
            client.join();
            host.client_events.remove(channel->event_cookie);
            host.sockfds.clear();
            delete channel;
            assert(fcntl(kernel_fd, F_GETFD) == -1 && errno == EBADF);
        } else {
            assert(host.sockfds.empty());
            client.join();
        }
    }
    fake_attestation = false;
    fake_epoch_open_fail = false;
    close(fake_epoch_backing);
    fake_epoch_backing = -1;
    close(host.kq_hdl);
    close(host.sockfd);
    assert(unlink(address.sun_path) == 0);
    assert(rmdir(directory) == 0);
}
};
}

int main()
{
    dtraced::state_attestation_test::run();
    dtraced::state_attestation_test::guest_forwarder();
    dtraced::state_attestation_test::source_release_admission();
    puts("PASS: host attestation rejection and guest-local forwarder admission");
}
