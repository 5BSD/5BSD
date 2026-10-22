// SPDX-License-Identifier: BSD-2-Clause
#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>
#include "dtraced_wire.h"

class client_fd {
public:
    int kind = DTRACED_KIND_CONSUMER;
    std::atomic_bool retired{false};
    std::array<uint8_t, 16> session_id{};
    std::mutex output_mtx;
    std::vector<uint8_t> sent;
    bool stopped = false;
    bool fail_send = false;
    bool fail_recv = false;
    bool corrupt_token = false;
    bool corrupt_padding = false;
    bool refuse = false;
    bool is_subscribed(uint64_t value) const { return value == DTD_SUB_ELFWRITE; }
    bool send(void *data, size_t size, int64_t) {
        if (fail_send) return false;
        const auto *bytes = static_cast<const uint8_t *>(data);
        sent.insert(sent.end(), bytes, bytes + size);
        return true;
    }
    bool recv(void *data, size_t size, int64_t) {
        if (fail_recv) return false;
        assert(sent.size() == DTRACED_MSGHDRSIZE +
            DTRACED_CONSUMER_DRAIN_WIRE_SIZE);
        dtraced_consumer_drain_t request{};
        assert(dtraced_wire_decode_consumer_drain(&request,
            sent.data() + DTRACED_MSGHDRSIZE) == 0);
        request.result = refuse ? 0 : 1;
        unsigned char wire[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
        dtraced_wire_encode_consumer_drain_ack(wire, &request);
        if (corrupt_token) wire[0] ^= 1;
        if (corrupt_padding) wire[97] = 1;
        assert(size == sizeof(wire));
        std::memcpy(data, wire, sizeof(wire));
        return true;
    }
    void shutdown() { stopped = true; }
    bool request_consumer_drain(const dtraced_consumer_drain_t &);
};

#include "consumer-drain-sender.inc"

static dtraced_consumer_drain_t
challenge()
{
    dtraced_consumer_drain_t value{};
    value.token[0] = 1;
    value.source_session[0] = 2;
    value.consumer_session[0] = 3;
    value.program_digest[0] = 4;
    value.vmid = 7;
    value.epoch = 9;
    return value;
}

int main()
{
    auto request = challenge();
    client_fd good;
    good.session_id[0] = 3;
    assert(good.request_consumer_drain(request));
    dtraced_hdr_t header{};
    assert(dtraced_wire_decode_header(&header, good.sent.data()) == 0 &&
        header.msg_type == DTRACED_MSG_CONSUMER_DRAIN &&
        header.elf.len == DTRACED_CONSUMER_DRAIN_WIRE_SIZE);

    client_fd wrong_session;
    assert(!wrong_session.request_consumer_drain(request) &&
        errno == EPROTO && wrong_session.sent.empty());
    client_fd refused;
    refused.session_id[0] = 3;
    refused.refuse = true;
    assert(!refused.request_consumer_drain(request) &&
        errno == EOPNOTSUPP && !refused.stopped);
    client_fd changed;
    changed.session_id[0] = 3;
    changed.corrupt_token = true;
    assert(!changed.request_consumer_drain(request) &&
        errno == EPROTO && changed.stopped);
    client_fd malformed;
    malformed.session_id[0] = 3;
    malformed.corrupt_padding = true;
    assert(!malformed.request_consumer_drain(request) &&
        errno == EPROTO && malformed.stopped);
    client_fd lost;
    lost.session_id[0] = 3;
    lost.fail_recv = true;
    assert(!lost.request_consumer_drain(request));
    return 0;
}
