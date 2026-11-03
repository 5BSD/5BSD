/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <sys/procdesc.h>
#include <sys/wait.h>
#include <dttransport.h>
#include <openssl/sha.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <new>
#include <poll.h>
#include <unistd.h>
#include <vector>
#include "dtraced_io.h"
#include "dtraced_child_ledger.h"
#include "dtraced_wire.h"
#include "dtraced_process.h"
#include "dtraced_protocol.h"
#include "dtraced_state.h"

namespace dtraced {
int
collector_handle_retired(const std::array<uint8_t, 24> &identity)
{
    dtrace_handle_lifetime_t query{};
    query.generation[0] = dtraced_wire_get_u64(identity.data());
    query.generation[1] = dtraced_wire_get_u64(identity.data() + 8);
    query.serial = dtraced_wire_get_u64(identity.data() + 16);
    if ((query.generation[0] | query.generation[1]) == 0 || query.serial == 0) {
        errno = EINVAL;
        return (-1);
    }
    const auto expected = query;
    int fd = open("/dev/dtrace/hypertrace", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return (-1);
    int error = ioctl(fd, HYPERTRACE_IOC_HANDLE_QUERY, &query) != 0 ? errno : 0;
    if (error == 0 && (query.generation[0] != expected.generation[0] ||
        query.generation[1] != expected.generation[1] ||
        query.serial != expected.serial || query.reserved != 0 || query.retired > 1))
        error = EPROTO;
    if (close(fd) != 0 && error == 0)
        error = errno;
    if (error != 0) {
        errno = error;
        return (-1);
    }
    return (query.retired == 1 ? 1 : 0);
}

/* Never infer process death from ESRCH, a missing PID, or a failed ioctl.
 * The expected birth must be bound to the authenticated collector before work
 * is sent; a freshly observed PID alone is not sufficient ownership evidence. */
int
collector_process_pin(pid_t peer, const pd_birth_identity &expected, int *result)
{
    if (result == nullptr || peer <= 1 || expected.pid != peer ||
        expected.reserved != 0 || expected.start_usec >= 1000000 ||
        (expected.start_sec == 0 && expected.start_usec == 0)) {
        errno = EINVAL;
        return (-1);
    }
    int fd = pdopenpid(peer, PD_DAEMON | PD_CLOEXEC);
    if (fd < 0)
        return (-1);
    pd_birth_identity found{};
    int error = ioctl(fd, PDIOC_GET_BIRTH_IDENTITY, &found) != 0 ? errno : 0;
    if (error == 0 && (found.pid != expected.pid || found.reserved != 0 ||
        found.start_sec != expected.start_sec || found.start_usec != expected.start_usec))
        error = ESTALE;
    if (error != 0) {
        (void)close(fd);
        errno = error;
        return (-1);
    }
    *result = fd;
    return (0);
}

int
collector_process_exited(int descriptor)
{
    if (descriptor < 0) {
        errno = EINVAL;
        return (-1);
    }
    struct pollfd event{descriptor, POLLIN, 0};
    int ready = poll(&event, 1, 0);
    if (ready < 0)
        return (-1);
    if ((event.revents & (POLLNVAL | POLLERR)) != 0) {
        errno = (event.revents & POLLNVAL) != 0 ? EBADF : EIO;
        return (-1);
    }
    if (ready == 0 && event.revents == 0)
        return (0);
    if (ready != 1 || event.revents != POLLHUP) {
        errno = EPROTO;
        return (-1);
    }
    return (1);
}

/* Query only a descriptor already pinned against authenticated process birth.
 * An empty non-reaper is not evidence; neither is a live reaper. This snapshot
 * cannot establish that descendants surviving the parent's exit later stopped. */
int
collector_process_reaper_empty(int descriptor)
{
    if (descriptor < 0) {
        errno = EINVAL;
        return (-1);
    }
    pd_reaper_exit snapshot{};
    if (ioctl(descriptor, PDIOC_GET_REAPER_EXIT, &snapshot) != 0)
        return (-1);
    constexpr uint32_t complete = PD_REAPER_EXITED | PD_REAPER_OWNED | PD_REAPER_EMPTY;
    if (snapshot.reserved != 0 || (snapshot.flags & ~complete) != 0 ||
        ((snapshot.flags & PD_REAPER_OWNED) != 0 &&
        (snapshot.flags & PD_REAPER_EXITED) == 0) ||
        ((snapshot.flags & PD_REAPER_EMPTY) != 0 &&
        (snapshot.flags & (PD_REAPER_EXITED | PD_REAPER_OWNED)) !=
        (PD_REAPER_EXITED | PD_REAPER_OWNED))) {
        errno = EPROTO;
        return (-1);
    }
    return (snapshot.flags == complete ? 1 : 0);
}

durable_delivery
guest_delivery_record(const guest_delivery &delivery)
{
    durable_delivery record{};
    uint8_t input[43]{};
    input[0] = 'G';
    input[1] = (uint8_t)delivery.vmid;
    input[2] = (uint8_t)(delivery.vmid >> 8);
    for (unsigned i = 0; i < 8; i++)
        input[3 + i] = (uint8_t)(delivery.epoch >> (8 * i));
    memcpy(input + 11, delivery.program_id.data(), 16);
    memcpy(input + 27, delivery.source_id.data(), 16);
    uint8_t digest[SHA256_DIGEST_LENGTH];
    (void)SHA256(input, sizeof(input), digest);
    memcpy(record.session_id.data(), digest, 16);
    if (delivery.journal_session_id != std::array<uint8_t, 16>{})
        record.session_id = delivery.journal_session_id;
    record.delivery_id = delivery.delivery_id;
    record.vmid = delivery.vmid;
    record.epoch = delivery.epoch;
    record.program_id = delivery.program_id;
    record.source_id = delivery.source_id;
    record.scope = 1;
    record.journal_version = delivery.journal_version;
    record.payload_digest = delivery.payload_digest;
    return record;
}
namespace {
std::mutex forkmtx;
struct owned_fd {
    int fd = -1;
    ~owned_fd() { if (fd >= 0) close(fd); }
};
struct owned_child {
    pid_t pid = -1;
    int procfd = -1;
    int ledger_directory = -1;
    ~owned_child() {
        int saved = errno, status;
        if (procfd >= 0) {
            (void)pdkill(procfd, SIGKILL);
            int result;
            do { result = pdwait(procfd, &status, WEXITED, nullptr, nullptr); }
            while (result < 0 && errno == EINTR);
            if (ledger_directory >= 0 && (result == 0 || errno == ESRCH))
                (void)retire_guest_child(ledger_directory, pid);
            if (pid > 1)
                while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            close(procfd);
        } else if (pid > 1)
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        errno = saved;
    }
};

bool
move_above_stdio(owned_fd &fd)
{
    if (fd.fd > STDERR_FILENO) return true;
    int moved = fcntl(fd.fd, F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    if (moved < 0) return false;
    close(fd.fd); fd.fd = moved;
    return true;
}

bool
exec_succeeded(int fd)
{
    int error = 0;
    size_t received = 0;
    int64_t deadline = dtraced_io_deadline_after(10000);
    if (deadline < 0) return false;
    while (received < sizeof(error)) {
        int64_t now = dtraced_io_milliseconds();
        if (now < 0) return false;
        int64_t remaining = deadline - now;
        if (remaining <= 0) { errno = ETIMEDOUT; return false; }
        struct pollfd watch{fd, POLLIN, 0};
        int ready = poll(&watch, 1, remaining > INT_MAX ? INT_MAX : int(remaining));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) { if (ready == 0) errno = ETIMEDOUT; return false; }
        ssize_t n = read(fd, reinterpret_cast<char *>(&error) + received,
            sizeof(error) - received);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) {
            if (received == 0) return true;
            errno = EPROTO; return false;
        }
        received += size_t(n);
    }
    errno = error != 0 ? error : EPROTO;
    return false;
}

}

/* Canonical spool names bind a delivery artifact to its revocable source. */
bool
spool_identity_from_path(const std::string &path,
    std::array<uint8_t, 16> &program, std::array<uint8_t, 16> &source)
{
    size_t slash = path.rfind('/');
    const char *name = path.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    if (strlen(name) != 69 || strncmp(name, "elf.", 4) != 0 || name[36] != '.')
        return false;
    auto decode = [](const char *digits, std::array<uint8_t, 16> &id) {
        for (size_t i = 0; i < id.size(); ++i) {
            unsigned value = 0;
            for (size_t digit = 0; digit < 2; ++digit) {
                char c = digits[i * 2 + digit];
                if (c >= '0' && c <= '9') value = value * 16 + unsigned(c - '0');
                else if (c >= 'a' && c <= 'f') value = value * 16 + unsigned(c - 'a' + 10);
                else return false;
            }
            id[i] = uint8_t(value);
        }
        return std::any_of(id.begin(), id.end(),
            [](uint8_t value) { return value != 0; });
    };
    return decode(name + 4, program) && decode(name + 37, source);
}

bool
find_guest_delivery(state &s, const std::string &path,
    guest_delivery &delivery)
{
    std::array<uint8_t, 16> program{}, source{};
    if (!spool_identity_from_path(path, program, source)) {
        errno = EPROTO;
        return false;
    }
    std::lock_guard lock(s.deliverymtx);
    for (const guest_delivery &candidate : s.guest_deliveries)
        if (candidate.authorized_current &&
            candidate.program_id == program &&
            candidate.source_id == source) {
            delivery = candidate;
            return true;
        }
    errno = ENOENT;
    return false;
}

static bool
send_lifecycle_observation(int fd, const guest_delivery &delivery,
    uint8_t kind, uint64_t query_id = 0)
{
    if (fd < 0 || delivery.delivery_id == 0 || delivery.vmid == 0 ||
        delivery.epoch == 0 ||
        (kind == DTT_STATUS ? query_id == 0 : query_id != 0)) {
        errno = EINVAL;
        return false;
    }
    dtt_entry_t entry{};
    entry.event_kind = kind;
    entry.u.installed.delivery_id = delivery.delivery_id;
    entry.u.installed.vmid = delivery.vmid;
    entry.u.installed.epoch = delivery.epoch;
    memcpy(entry.u.installed.program_id, delivery.program_id.data(),
        delivery.program_id.size());
    memcpy(entry.u.installed.source_id, delivery.source_id.data(),
        delivery.source_id.size());
    entry.u.installed.query_id = query_id;
    ssize_t written;
    do {
        written = write(fd, &entry, sizeof(entry));
    } while (written < 0 && errno == EINTR);
    if (written != (ssize_t)sizeof(entry)) {
        if (written >= 0) errno = EIO;
        return false;
    }
    return true;
}

bool
send_install_observation(int fd, const guest_delivery &delivery)
{
    return send_lifecycle_observation(fd, delivery, DTT_INSTALLED);
}

bool
send_uninstall_observation(int fd, const guest_delivery &delivery)
{
    return send_lifecycle_observation(fd, delivery, DTT_UNINSTALLED);
}

bool
send_status_query(int fd, const guest_delivery &delivery, uint64_t query_id)
{
    return send_lifecycle_observation(fd, delivery, DTT_STATUS, query_id);
}

void
retire_guest_delivery(state &s, const guest_delivery &delivery)
{
    std::lock_guard lock(s.deliverymtx);
    auto &pending = s.guest_deliveries;
    pending.erase(std::remove_if(pending.begin(), pending.end(),
        [&](const guest_delivery &item) {
            return item.delivery_id == delivery.delivery_id &&
                item.vmid == delivery.vmid && item.epoch == delivery.epoch &&
                item.program_id == delivery.program_id &&
                item.source_id == delivery.source_id;
        }), pending.end());
}

bool
finish_guest_delivery(state &s, const guest_delivery &delivery)
{
    std::lock_guard lock(s.deliverymtx);
    auto known = std::find_if(s.guest_deliveries.begin(),
        s.guest_deliveries.end(), [&](const guest_delivery &item) {
            return item.delivery_id == delivery.delivery_id &&
                item.vmid == delivery.vmid && item.epoch == delivery.epoch &&
                item.program_id == delivery.program_id &&
                item.source_id == delivery.source_id;
        });
    if (known != s.guest_deliveries.end() &&
        (s.inbounddir == nullptr ||
        !s.inbounddir->record_delivery(guest_delivery_record(delivery),
            delivery_phase::exited)))
        return false;
    if (!send_uninstall_observation(s.dtt_fd, delivery))
        return false;
    if (known != s.guest_deliveries.end())
        known->terminal_sent = true;
    /* Keep the context until the host accepts the matching terminal report. */
    return true;
}

bool
handle_host_observation(state &s, const dtt_entry_t &entry)
{
    if (entry.event_kind != DTT_HOST_INSTALLED &&
        entry.event_kind != DTT_HOST_UNINSTALLED) {
        errno = EINVAL;
        return false;
    }
    const auto &reported = entry.u.installed;
    const uint8_t zero_id[16] = {};
    const uint8_t zero_digest[32] = {};
    if (reported.delivery_id == 0 || reported.vmid == 0 ||
        reported.vmid >= HYPERTRACE_MAX_VMS || reported.epoch == 0 ||
        memcmp(reported.program_id, zero_id, 16) == 0 ||
        memcmp(reported.source_id, zero_id, 16) == 0 ||
        reported.phase != 0 || reported.revoked != 0 ||
        reported.replay != 0 ||
        reported.query_id != 0 ||
        memcmp(reported.digest, zero_digest, 32) != 0) {
        errno = EPROTO;
        return false;
    }
    std::lock_guard lock(s.deliverymtx);
    auto &pending = s.guest_deliveries;
    auto known = std::find_if(pending.begin(), pending.end(),
        [&](const guest_delivery &item) {
            return item.delivery_id == reported.delivery_id &&
                item.vmid == reported.vmid && item.epoch == reported.epoch &&
                memcmp(item.program_id.data(), reported.program_id, 16) == 0 &&
                memcmp(item.source_id.data(), reported.source_id, 16) == 0;
        });
    if (known != pending.end() &&
        entry.event_kind == DTT_HOST_UNINSTALLED &&
        !known->terminal_sent) {
        errno = EPROTO;
        return false;
    }
    durable_delivery record{};
    if (known != pending.end())
        record = guest_delivery_record(*known);
    if (known != pending.end() &&
        (s.inbounddir == nullptr ||
        !s.inbounddir->record_delivery(record,
            entry.event_kind == DTT_HOST_INSTALLED ?
            delivery_phase::installed : delivery_phase::terminal)))
        return false;
    /* Revocation or reset may have retired an in-flight observation. */
    if (known != pending.end() && entry.event_kind == DTT_HOST_UNINSTALLED) {
        pending.erase(known);
        /* The host persisted terminal before sending this receipt.  A failed
         * unlink is safe to retry during the next startup scan. */
        (void)s.inbounddir->retire_terminal_delivery(record);
    }
    return true;
}

bool
handle_host_status(state &s, const dtt_entry_t &entry)
{
    if (entry.event_kind != DTT_HOST_STATUS) {
        errno = EINVAL;
        return false;
    }
    const auto &reported = entry.u.installed;
    const uint8_t zero_id[16] = {};
    const uint8_t zero_digest[32] = {};
    if (reported.delivery_id == 0 || reported.vmid == 0 ||
        reported.vmid >= HYPERTRACE_MAX_VMS || reported.epoch == 0 ||
        memcmp(reported.program_id, zero_id, 16) == 0 ||
        memcmp(reported.source_id, zero_id, 16) == 0 ||
        (reported.phase != 0 && reported.phase != 'p' &&
        reported.phase != 'a' && reported.phase != 'i' &&
        reported.phase != 't') || reported.revoked > 1 ||
        reported.replay > 1 ||
        (reported.replay != 0 &&
        (reported.revoked != 0 ||
        (reported.phase != 'a' && reported.phase != 'i'))) ||
        (reported.replay == 0 &&
        memcmp(reported.digest, zero_digest, 32) != 0) ||
        reported.query_id == 0) {
        errno = EPROTO;
        return false;
    }
    std::lock_guard lock(s.deliverymtx);
    auto &pending = s.guest_deliveries;
    auto known = std::find_if(pending.begin(), pending.end(),
        [&](const guest_delivery &item) {
            return item.delivery_id == reported.delivery_id &&
                item.vmid == reported.vmid && item.epoch == reported.epoch &&
                memcmp(item.program_id.data(), reported.program_id, 16) == 0 &&
                memcmp(item.source_id.data(), reported.source_id, 16) == 0;
        });
    if (known == pending.end())
        return true; /* A receipt may have retired the query meanwhile. */
    if (known->authorized_current || s.inbounddir == nullptr ||
        (reported.phase == 0 && reported.revoked == 0)) {
        errno = EPROTO;
        return false;
    }
    durable_delivery record = guest_delivery_record(*known);
    if (reported.replay != 0 && !known->terminal_sent) {
        int local_revoked = s.inbounddir->source_revoked(
            known->source_id.data());
        int local_phase = s.inbounddir->delivery_status(record);
        if (local_revoked < 0 || local_phase < 0)
            return false;
        if (local_revoked == 0 &&
            (local_phase == (int)delivery_phase::pending ||
            local_phase == (int)delivery_phase::accepted ||
            local_phase == (int)delivery_phase::installed)) {
            known->authorized_current = true;
            known->replay_granted = true;
            memcpy(known->replay_digest.data(), reported.digest, 32);
            if (s.inbounddir->request_reprocess(known->program_id.data(),
                known->source_id.data(), reported.digest))
                return true;
            known->authorized_current = false;
            known->replay_granted = false;
            known->replay_digest.fill(0);
            if (errno != ENOENT)
                return false;
            /* Missing bytes cannot be replayed; terminate this token. */
        }
    }
    if (reported.phase == 't' || reported.phase == 0) {
        if (!s.inbounddir->record_delivery(record,
            delivery_phase::terminal))
            return false;
        pending.erase(known);
        (void)s.inbounddir->retire_terminal_delivery(record);
        return true;
    }
    if (!s.inbounddir->record_delivery(record, delivery_phase::exited) ||
        !send_uninstall_observation(s.dtt_fd, *known))
        return false;
    known->terminal_sent = true;
    return true;
}

/* No allocator, stdio or C++ lock operations run in a post-fork child. */
bool
launch_program(state &s, const std::string &path, bool host,
    const char *executable, bool *installed, pid_t *registered_pid,
    bool require_report) try
{
    std::shared_lock admission(s.launch_gate);
    if (s.cleanup_in_progress.load()) {
        errno = ECANCELED;
        return false;
    }
    if (installed != nullptr)
        *installed = false;
    if (registered_pid != nullptr)
        *registered_pid = -1;
    std::array<uint8_t, 16> program{}, source{};
    bool sourced = !host &&
        spool_identity_from_path(path, program, source);
    size_t slash = path.rfind('/');
    const char *name = path.c_str() + (slash == std::string::npos ? 0 : slash + 1);
    if (!host && strncmp(name, "elf.", 4) == 0 && !sourced) {
        errno = EPROTO;
        return false;
    }
    if (sourced) {
        int persisted = s.inbounddir == nullptr ? 0 :
            s.inbounddir->source_revoked(source.data());
        if (persisted != 0) {
            errno = persisted > 0 ? ECANCELED : errno;
            return false;
        }
        std::lock_guard children(s.pidlistmtx);
        if (s.revoked_sources.find(source) != s.revoked_sources.end()) {
            errno = ECANCELED;
            return false;
        }
    }
    std::vector<std::array<char, DTRACED_PROGIDENTLEN>> identifiers;
    if (!host) {
        std::lock_guard lock(s.identlistmtx);
        if (s.identlist.size() > max_request_bytes / DTRACED_PROGIDENTLEN) {
            errno = E2BIG; return false;
        }
        for (const auto &listed : s.identlist)
            identifiers.push_back(listed.ident);
    }
    /* dtrace -Y FILE,guest,SOURCE uploads the linked program under the
     * source this delivery was spooled with, the one its KILL revokes. */
    std::string input = path + (host ? ",host" : "");
    if (sourced) {
        static const char digits[] = "0123456789abcdef";
        input += ",guest,";
        for (uint8_t byte : source) {
            input += digits[byte >> 4];
            input += digits[byte & 0xf];
        }
    }
    bool has_identifiers = !identifiers.empty();
    if (require_report && !has_identifiers) {
        errno = EAGAIN;
        return false;
    }
    char *args[] = { const_cast<char *>(executable), const_cast<char *>("-q"),
        const_cast<char *>("-Y"), input.data(),
        has_identifiers ? const_cast<char *>("-N") : nullptr, nullptr };
    char report_env[] = "HYPERTRACE_LAUNCH_REPORT=1";
    char *environment[] = { has_identifiers ? report_env : nullptr, nullptr };
    owned_fd parent, child, null_input, null_output, status_read, status_write;
    owned_fd gate_read, gate_write;
    if (has_identifiers) {
        int pair[2];
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0)
            return false;
        parent.fd = pair[0]; child.fd = pair[1];
        if (!move_above_stdio(parent) || !move_above_stdio(child))
            return false;
    } else if (!host) {
        null_input.fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        null_output.fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_input.fd < 0 || null_output.fd < 0 ||
            !move_above_stdio(null_input) || !move_above_stdio(null_output))
            return false;
    }
    owned_child process;
    {
      std::lock_guard fork_lock(forkmtx);
      int pipefd[2];
      if (pipe2(pipefd, O_CLOEXEC) != 0)
          return false;
      status_read.fd = pipefd[0]; status_write.fd = pipefd[1];
      if (!move_above_stdio(status_read) || !move_above_stdio(status_write))
          return false;
      if (!host) {
          if (pipe2(pipefd, O_CLOEXEC) != 0)
              return false;
          gate_read.fd = pipefd[0]; gate_write.fd = pipefd[1];
          if (!move_above_stdio(gate_read) || !move_above_stdio(gate_write))
              return false;
      }
      int pdflags = PD_CLOEXEC;
#if defined(PD_NOWAITPID) && !defined(DTRACED_NATIVE_TEST)
      pdflags |= PD_NOWAITPID;
#endif
      process.pid = pdfork(&process.procfd, pdflags);
      if (process.pid < 0) { process.procfd = -1; return false; }
      if (process.pid == 0) {
        /* Only raw syscalls and exec run after fork in this threaded daemon. */
        sigset_t mask;
        const int signals[] = {SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGPIPE, SIGCHLD};
        struct sigaction action{};
        int child_errno;
        if (status_read.fd >= 0) close(status_read.fd);
        if (!host) {
            char release;
            ssize_t received;
            close(gate_write.fd);
            do { received = read(gate_read.fd, &release, 1); }
            while (received < 0 && errno == EINTR);
            if (received != 1 || release != 'R') _exit(127);
            close(gate_read.fd);
        }
        if (has_identifiers) {
            if (dup2(child.fd, STDIN_FILENO) < 0 ||
                dup2(child.fd, STDOUT_FILENO) < 0)
                goto child_error;
        } else if (!host) {
            if (dup2(null_input.fd, STDIN_FILENO) < 0 ||
                dup2(null_output.fd, STDOUT_FILENO) < 0)
                goto child_error;
        }
        sigemptyset(&mask);
        if (sigprocmask(SIG_SETMASK, &mask, nullptr) != 0)
            goto child_error;
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        for (int signal : signals)
            if (sigaction(signal, &action, nullptr) != 0)
                goto child_error;
        execve(executable, args, environment);
child_error:
        child_errno = errno;
        (void)write(status_write.fd, &child_errno, sizeof(child_errno));
        _exit(127);
      }
      int flags = fcntl(process.procfd, F_GETFD);
      if (flags < 0 || fcntl(process.procfd, F_SETFD,
          flags | FD_CLOEXEC | FD_CLOFORK) != 0)
          return false;
      close(status_write.fd); status_write.fd = -1;
    }
    if (!host) {
        if (s.inbounddir == nullptr ||
            !record_guest_child(s.inbounddir->dirfd, process.procfd,
            process.pid))
            return false;
        process.ledger_directory = s.inbounddir->dirfd;
        close(gate_read.fd); gate_read.fd = -1;
        char release = 'R';
        ssize_t sent;
        do { sent = write(gate_write.fd, &release, 1); }
        while (sent < 0 && errno == EINTR);
        if (sent != 1) { if (sent >= 0) errno = EIO; return false; }
        close(gate_write.fd); gate_write.fd = -1;
    }
    if (!exec_succeeded(status_read.fd))
        return false;
    if (child.fd >= 0) { close(child.fd); child.fd = -1; }
    std::array<char, DTRACED_PROGIDENTLEN> selected{};
    bool launch_installed = false;
    if (has_identifiers) {
        size_t count = identifiers.size(), transferred;
        /* Compilation and the daemon's own bounded ELF send precede status. */
        int64_t deadline = dtraced_io_deadline_after(60000);
        if (deadline < 0) return false;
        if (dtraced_io_write_size(parent.fd, count,
            deadline, &transferred) != 0)
            return false;
        for (auto &id : identifiers)
            if (dtraced_io_transfer(parent.fd, id.data(), id.size(), true, deadline, &transferred) != 0)
                return false;
        char reply[sizeof("DEL ident")];
        if (dtraced_io_transfer(parent.fd, reply, sizeof(reply), false, deadline, &transferred) != 0)
            return false;
        if (memcmp(reply, "FAIL FAIL", sizeof(reply)) == 0)
            return true; /* The owned child is stopped and reaped on exit. */
        /* A program compiled on the host (no srcident) is none of the
         * listed ones: acknowledged with no identifier, never installed. */
        const std::array<char, DTRACED_PROGIDENTLEN> no_ident{};
        if (memcmp(reply, "DEL ident", sizeof(reply)) != 0 ||
            dtraced_io_transfer(parent.fd, selected.data(), selected.size(), false, deadline, &transferred) != 0 ||
            (selected != no_ident &&
            std::find(identifiers.begin(), identifiers.end(), selected) == identifiers.end())) {
            errno = EPROTO; return false;
        }
		dtraced_launch_result_t result{};
		unsigned char result_wire[DTRACED_LAUNCH_WIRE_SIZE];
		if (dtraced_io_transfer(parent.fd, result_wire,
		    sizeof(result_wire), false, deadline, &transferred) != 0 ||
		    dtraced_wire_decode_launch(&result, result_wire) != 0)
			return false;
		const uint8_t zero_reserved[sizeof(result.reserved)] = {};
		if (result.magic != DTRACED_LAUNCH_MAGIC ||
		    result.installed > (selected != no_ident) ||
		    memcmp(result.reserved, zero_reserved,
		    sizeof(result.reserved)) != 0 ||
		    memcmp(result.source_ident, selected.data(),
		    selected.size()) != 0) {
			errno = EPROTO;
			return false;
		}
        launch_installed = result.installed != 0;
    }
    if (require_report && !launch_installed)
        return true; /* The owned child dies; no unconfirmed replay lives. */
    {
        std::lock_guard lock(s.pidlistmtx);
        int persisted = sourced && s.inbounddir != nullptr ?
            s.inbounddir->source_revoked(source.data()) : 0;
        if (persisted != 0) {
            errno = persisted > 0 ? ECANCELED : errno;
            return false;
        }
        if (sourced && s.revoked_sources.find(source) != s.revoked_sources.end()) {
            errno = ECANCELED;
            return false; /* owned_child terminates the in-flight launch. */
        }
        if (!s.pidfds.emplace(process.pid, process.procfd).second) {
            errno = EEXIST;
            return false;
        }
        try {
            if (sourced && !s.pid_sources.emplace(process.pid, source).second) {
                errno = EEXIST;
                s.pidfds.erase(process.pid);
                return false;
            }
            if (!s.pidlist.insert(process.pid).second) {
                errno = EEXIST;
                s.pidfds.erase(process.pid);
                s.pid_sources.erase(process.pid);
                return false;
            }
        } catch (...) {
            s.pidfds.erase(process.pid);
            s.pid_sources.erase(process.pid);
            throw;
        }
        process.procfd = -1;
        process.ledger_directory = -1;
        if (registered_pid != nullptr)
            *registered_pid = process.pid;
        process.pid = -1;
    }
    if (has_identifiers) {
        std::lock_guard lock(s.identlistmtx);
        auto found = std::find_if(s.identlist.begin(), s.identlist.end(),
            [&](const state::listed_ident &listed) { return listed.ident == selected; });
        if (found != s.identlist.end()) s.identlist.erase(found);
    }
    if (installed != nullptr)
        *installed = launch_installed;
    return true;
} catch (const std::bad_alloc &) {
    errno = ENOMEM; return false;
}
}
