/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef DTRACED_SOCKET_H
#define DTRACED_SOCKET_H
#include <sys/socket.h>
#include <poll.h>
#include <cerrno>
#include <chrono>
#include <climits>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdlib.h>
#include "dtraced.h"
namespace dtraced {
/* Absolute deadline, including EINTR and partial progress. No global fd flags. */
inline bool socket_transfer(int fd, void *data, size_t size, bool writing,
    std::chrono::milliseconds budget = std::chrono::seconds(10))
{
    using clock = std::chrono::steady_clock;
    if (budget <= std::chrono::milliseconds::zero()) {
        errno = EINVAL;
        return false;
    }
    auto started = clock::now();
    auto available = std::chrono::duration_cast<std::chrono::milliseconds>(
        clock::time_point::max() - started);
    if (budget > available) {
        errno = EOVERFLOW;
        return false;
    }
    auto deadline = started + budget;
    auto *p = static_cast<char *>(data);
    while (size != 0) {
        auto now = clock::now();
        if (now >= deadline) { errno = ETIMEDOUT; return false; }
        ssize_t n = writing ? ::send(fd, p, size, MSG_DONTWAIT | MSG_NOSIGNAL) :
            ::recv(fd, p, size, MSG_DONTWAIT);
        if (n > 0) { p += n; size -= n; continue; }
        if (n == 0) { errno = writing ? EPIPE : ECONNRESET; return false; }
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return false;
        auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - clock::now());
        if (left.count() <= 0) { errno = ETIMEDOUT; return false; }
        pollfd event {fd, static_cast<short>(writing ? POLLOUT : POLLIN), 0};
        int timeout = left.count() > INT_MAX ? INT_MAX :
            static_cast<int>(left.count());
        int status = poll(&event, 1, timeout);
        if (status < 0 && errno != EINTR) return false;
        if (status == 0) continue;
        if (status > 0 && (event.revents & POLLNVAL)) { errno = EBADF; return false; }
    }
    return true;
}
/* A process-local nonce accompanies the stable consumer session. It is
 * deliberately carried in the canonical text field until receipt storage
 * can bind it to pending work. */
inline bool parse_consumer_birth(const char *ident, uint32_t &pid,
    std::array<uint8_t, 16> &birth)
{
    size_t length = ::strnlen(ident, DTRACED_FDIDENTLEN);
    if (length == DTRACED_FDIDENTLEN)
        return false;
    if (std::strncmp(ident, "dtrace-", 7) != 0)
        return false;
    const char *p = ident + 7;
    if (*p < '1' || *p > '9')
        return false;
    uint32_t parsed = 0;
    while (*p >= '0' && *p <= '9') {
        unsigned digit = (unsigned)(*p++ - '0');
        if (parsed > ((uint32_t)INT_MAX - digit) / 10)
            return false;
        parsed = parsed * 10 + digit;
    }
    if (parsed <= 1 || *p++ != '-')
        return false;
    if ((size_t)(ident + length - p) != 32)
        return false;
    std::array<uint8_t, 16> bytes{};
    for (unsigned i = 0; i < bytes.size(); i++) {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; j++) {
            char ch = *p++;
            unsigned digit;
            if (ch >= '0' && ch <= '9') digit = (unsigned)(ch - '0');
            else if (ch >= 'a' && ch <= 'f') digit = (unsigned)(ch - 'a' + 10);
            else return false;
            value = value * 16 + digit;
        }
        bytes[i] = (uint8_t)value;
    }
    if (*p != '\0' || bytes == std::array<uint8_t, 16>{})
        return false;
    pid = parsed;
    birth = bytes;
    return true;
}

inline bool valid_initmsg(const dtd_initmsg_t &msg)
{
    constexpr auto allowed = DTD_SUB_READDATA | DTD_SUB_ELFWRITE | DTD_SUB_KILL |
        DTD_SUB_CLEANUP | DTD_SUB_INFO | DTD_SUB_ADMISSION_ACK |
        DTD_SUB_REPLAY_MANIFEST | DTD_SUB_SOURCE_RELEASE |
        DTD_SUB_RELEASE_RECOVERY;
    const char *terminator = static_cast<const char *>(
        std::memchr(msg.ident, '\0', sizeof(msg.ident)));
    if (terminator == nullptr) return false;
    for (const char *tail = terminator + 1;
         tail < msg.ident + sizeof(msg.ident); ++tail)
        if (*tail != '\0') return false;
    bool has_session = false;
    for (uint8_t byte : msg.session_id)
        has_session |= byte != 0;
    uint32_t claimed_pid = 0;
    std::array<uint8_t, 16> birth{};
    return msg.protocol_version == DTRACED_PROTOCOL_VERSION &&
        (msg.kind == DTRACED_KIND_CONSUMER ||
        msg.kind == DTRACED_KIND_FORWARDER ||
        msg.kind == DTRACED_KIND_RELEASE_RECOVERY) &&
        (has_session || (msg.kind == DTRACED_KIND_CONSUMER &&
        (msg.subs & DTD_SUB_ELFWRITE) == 0) ||
        msg.kind == DTRACED_KIND_RELEASE_RECOVERY) &&
        (msg.kind != DTRACED_KIND_CONSUMER ||
        (msg.subs & DTD_SUB_ELFWRITE) == 0 ||
        parse_consumer_birth(msg.ident, claimed_pid, birth)) &&
        (msg.kind != DTRACED_KIND_FORWARDER ||
        msg.ident[0] != '\0') &&
        ((msg.subs & DTD_SUB_ADMISSION_ACK) == 0 ||
        msg.kind == DTRACED_KIND_FORWARDER) &&
        ((msg.subs & DTD_SUB_REPLAY_MANIFEST) == 0 ||
        (msg.kind == DTRACED_KIND_FORWARDER &&
        (msg.subs & (DTD_SUB_ELFWRITE | DTD_SUB_KILL |
        DTD_SUB_ADMISSION_ACK)) ==
        (DTD_SUB_ELFWRITE | DTD_SUB_KILL |
        DTD_SUB_ADMISSION_ACK) &&
        (msg.subs & DTD_SUB_READDATA) == 0)) &&
        (msg.subs & ~allowed) == 0 &&
        ((msg.subs & DTD_SUB_RELEASE_RECOVERY) == 0 ||
        msg.kind == DTRACED_KIND_RELEASE_RECOVERY) &&
        (msg.kind != DTRACED_KIND_RELEASE_RECOVERY ||
        (msg.subs == DTD_SUB_RELEASE_RECOVERY && !has_session &&
        std::strcmp(msg.ident, "hypertrace-release-recovery") == 0)) &&
        ((msg.subs & DTD_SUB_SOURCE_RELEASE) == 0 ||
        (msg.kind == DTRACED_KIND_FORWARDER &&
        msg.subs == (DTD_SUB_SOURCE_RELEASE | DTD_SUB_ADMISSION_ACK))) &&
        /* A forwarder channel that must read the peer's 8-byte ACK of an
         * ELF or CLEANUP frame cannot also carry READDATA requests: the
         * READ_DATA job would consume the ACK as a frame header. bhyve
         * never combines them (ht_connect: rx = ELFWRITE|KILL|CLEANUP|...,
         * wx = READDATA|ADMISSION_ACK). */
        !(msg.kind == DTRACED_KIND_FORWARDER &&
        (msg.subs & DTD_SUB_READDATA) != 0 &&
        (msg.subs & (DTD_SUB_ELFWRITE | DTD_SUB_CLEANUP)) != 0);
}
inline dtd_initmsg_t guest_forwarder_initmsg(int pid)
{
    dtd_initmsg_t msg{};
    const uint8_t zero_session[16] = {};
    msg.protocol_version = DTRACED_PROTOCOL_VERSION;
    msg.kind = DTRACED_KIND_FORWARDER;
    msg.subs = DTD_SUB_ELFWRITE;
    std::snprintf(msg.ident, sizeof(msg.ident),
        "dtraced-dttransport-%d", pid);
    do {
        arc4random_buf(msg.session_id, sizeof(msg.session_id));
    } while (std::memcmp(msg.session_id, zero_session,
        sizeof(msg.session_id)) == 0);
    return msg;
}
}
#endif
