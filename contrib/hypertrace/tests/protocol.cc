// SPDX-License-Identifier: BSD-2-Clause
#include "dtraced_protocol.h"
#include "dtraced_wire.h"
#include "dtraced_rebind_wire.h"
#include <sys/hypertrace_wire.h>
#include <cassert>
#include <cstring>
#include <limits>
#include <utility>
#include <sys/socket.h>
#include <unistd.h>
using namespace dtraced;
static void append(std::vector<unsigned char> &b, const char *p, size_t n) {
    unsigned char length[8];
    dtraced_wire_put_u64(length, n);
    b.insert(b.end(), length, length + sizeof(length));
    b.insert(b.end(), p, p + n);
}
int main() {
    static_assert(sizeof(dtraced_hdr_t) == DTRACED_MSGHDRSIZE);
    {
        unsigned char body[DTRACED_SESSION_STOP_WIRE_SIZE];
        uint8_t token[16] = {0x37}, decoded[16] = {};
        dtraced_wire_encode_session_stop(body, token);
        assert(dtraced_wire_decode_session_stop(decoded, body) == 0 &&
            memcmp(token, decoded, 16) == 0);
        assert(dtraced_wire_decode_session_release(decoded, body) == -1);
        dtraced_wire_encode_session_release(body, token);
        assert(dtraced_wire_decode_session_release(decoded, body) == 0 &&
            memcmp(token, decoded, 16) == 0);
        assert(dtraced_wire_decode_session_stop(decoded, body) == -1);
        body[4] = 1;
        assert(dtraced_wire_decode_session_release(decoded, body) == -1);
        body[4] = 0;
        memset(body + 8, 0, 16);
        assert(dtraced_wire_decode_session_release(decoded, body) == -1);
        dtraced_wire_encode_session_stop(body, token);
        for (size_t i = 0; i < 8; ++i) {
            body[i] ^= 1;
            assert(dtraced_wire_decode_session_stop(decoded, body) == -1);
            body[i] ^= 1;
        }
        memset(body + 8, 0, 16);
        assert(dtraced_wire_decode_session_stop(decoded, body) == -1);
        dtraced_hdr_t header{}, result{};
        unsigned char wire[DTRACED_MSGHDRSIZE];
        header.msg_type = DTRACED_MSG_SESSION_STOP;
        dtraced_wire_encode_header(wire, &header);
        assert(dtraced_wire_decode_header(&result, wire) == 0);
        wire[8] = 1;
        assert(dtraced_wire_decode_header(&result, wire) == -1);
    }
    hypertrace_vm_envelope envelope{};
    hypertrace_vm_envelope envelope_decoded{};
    unsigned char envelope_wire[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE];
    const unsigned char envelope_golden[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE] = {
        'H', 'T', 'V', '2', 2, 0, 0x34, 0x12,
        8, 7, 6, 5, 4, 3, 2, 1,
        0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a
    };
    envelope.magic = HYPERTRACE_ENVELOPE_MAGIC;
    envelope.version = HYPERTRACE_ENVELOPE_VERSION;
    envelope.vmid = 0x1234;
    envelope.epoch = UINT64_C(0x0102030405060708);
    envelope.name_length = UINT64_C(0x0a0b0c0d0e0f1011);
    hypertrace_envelope_encode(envelope_wire, &envelope);
    assert(std::memcmp(envelope_wire, envelope_golden,
        sizeof(envelope_wire)) == 0);
    hypertrace_envelope_decode(&envelope_decoded, envelope_golden);
    assert(envelope_decoded.magic == envelope.magic &&
        envelope_decoded.version == envelope.version &&
        envelope_decoded.vmid == envelope.vmid &&
        envelope_decoded.epoch == envelope.epoch &&
        envelope_decoded.name_length == envelope.name_length);
    hypertrace_vm_envelope bounded{};
    bounded.magic = HYPERTRACE_ENVELOPE_MAGIC;
    bounded.version = HYPERTRACE_ENVELOPE_VERSION;
    bounded.vmid = 7;
    bounded.epoch = 9;
    bounded.name_length = 2;
    std::vector<unsigned char> bounded_wire(
        HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 2 + 4);
    hypertrace_envelope_encode(bounded_wire.data(), &bounded);
    std::memcpy(bounded_wire.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
        "vm\177ELF", 6);
    size_t elf_offset = 0;
    assert(parse_guest_elf_envelope(bounded_wire.data(),
        bounded_wire.size(), 7, 9, "vm", elf_offset) &&
        elf_offset == HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 2);
    char unterminated[HYPERTRACE_VM_ATTEST_NAME_LEN];
    std::memset(unterminated, 'x', sizeof(unterminated));
    elf_offset = 0;
    assert(!parse_guest_elf_envelope(bounded_wire.data(),
        bounded_wire.size(), 7, 9, unterminated, elf_offset) &&
        errno == EPROTO && elf_offset == 0);
    unsigned char wire[8];
    constexpr unsigned char golden[8] = {8, 7, 6, 5, 4, 3, 2, 1};
    dtraced_wire_put_u64(wire, UINT64_C(0x0102030405060708));
    assert(std::memcmp(wire, golden, sizeof(wire)) == 0);
    assert(dtraced_wire_get_u64(golden) == UINT64_C(0x0102030405060708));
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    int64_t deadline = dtraced_io_deadline_after(1000);
    size_t transferred, value = 0;
    assert(dtraced_io_write_size(sockets[0], 0x0102030405060708ULL,
        deadline, &transferred) == 0);
    assert(recv(sockets[1], wire, sizeof(wire), MSG_WAITALL) == 8);
    assert(std::memcmp(wire, golden, sizeof(wire)) == 0);
    assert(send(sockets[1], golden, sizeof(golden), 0) == 8);
    assert(dtraced_io_read_size(sockets[0], &value, deadline,
        &transferred) == 0);
    assert(value == 0x0102030405060708ULL);
    close(sockets[0]); close(sockets[1]);
    dtd_initmsg_t init{};
    dtd_initmsg_t init_decoded{};
    unsigned char init_wire[DTRACED_INIT_WIRE_SIZE];
    init.kind = DTRACED_KIND_FORWARDER;
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
    init.subs = UINT64_C(0x0102030405060708);
    init.ident[0] = 'g';
    init.session_id[0] = 0xa5;
    dtraced_wire_encode_init(init_wire, &init);
    assert(init_wire[0] == DTRACED_KIND_FORWARDER &&
        init_wire[4] == DTRACED_PROTOCOL_VERSION &&
        std::memcmp(init_wire + 8, golden, 8) == 0 &&
        init_wire[16] == 'g' && init_wire[144] == 0xa5);
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(init_decoded.kind == init.kind &&
        init_decoded.protocol_version == init.protocol_version &&
        init_decoded.subs == init.subs &&
        init_decoded.ident[0] == init.ident[0] &&
        init_decoded.session_id[0] == init.session_id[0]);
    init = {};
    init.kind = DTRACED_KIND_DTRACED;
    init.protocol_version = DTRACED_PROTOCOL_VERSION;
    dtraced_wire_encode_init(init_wire, &init);
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(dtraced_wire_valid_server_init(&init_decoded));
    init_wire[8] = 1;
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(!dtraced_wire_valid_server_init(&init_decoded));
    init_wire[8] = 0; init_wire[16] = 'x';
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(!dtraced_wire_valid_server_init(&init_decoded));
    init_wire[16] = 0; init_wire[144] = 1;
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(!dtraced_wire_valid_server_init(&init_decoded));
    init_wire[144] = 0;
    dtraced_wire_put_u32(init_wire + 4, DTRACED_PROTOCOL_VERSION - 1);
    dtraced_wire_decode_init(&init_decoded, init_wire);
    assert(!dtraced_wire_valid_server_init(&init_decoded));
    dtraced_replay_kill_t replay{123, 0x0234,
        UINT64_C(0x0102030405060708), {0xa5}};
    dtraced_replay_kill_t replay_decoded{};
    unsigned char replay_wire[DTRACED_REPLAY_KILL_WIRE_SIZE];
    dtraced_wire_encode_replay_kill(replay_wire, &replay);
    assert(replay_wire[0] == 123 && replay_wire[4] == 0x34 &&
        replay_wire[5] == 0x02 && replay_wire[6] == 0 &&
        replay_wire[7] == 0 &&
        std::memcmp(replay_wire + 8, golden, 8) == 0 &&
        replay_wire[16] == 0xa5);
    assert(dtraced_wire_decode_replay_kill(&replay_decoded,
        replay_wire) == 0 && replay_decoded.pid == replay.pid &&
        replay_decoded.vmid == replay.vmid &&
        replay_decoded.epoch == replay.epoch &&
        replay_decoded.source_id[0] == replay.source_id[0]);
    replay_wire[6] = 1;
    assert(dtraced_wire_decode_replay_kill(&replay_decoded,
        replay_wire) == -1 && errno == EPROTO);
    replay_wire[6] = 0;
    replay_decoded.pid = 777;
    dtraced_wire_put_u16(replay_wire + 4, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_replay_kill(&replay_decoded,
        replay_wire) == -1 && errno == EPROTO &&
        replay_decoded.pid == 777);
    dtraced_hdr_t header{};
    dtraced_hdr_t decoded{};
    unsigned char header_wire[DTRACED_MSGHDRSIZE];
    header.msg_type = DTRACED_MSG_ELF;
    header.elf.len = UINT64_C(0x0102030405060708);
    header.elf.vmid = 0x0234;
    header.elf.epoch = UINT64_C(0x8877665544332211);
    header.installed.delivery_id = 29;
    header.installed.vmid = 17;
    header.installed.epoch = 88;
    header.installed.program_id[0] = 1;
    header.installed.source_id[0] = 2;
    header.installed.name[0] = 'v';
    dtraced_wire_encode_header(header_wire, &header);
    assert(std::memcmp(header_wire + 8, golden, 8) == 0);
    assert(header_wire[64] == 0x34 && header_wire[65] == 0x02);
    assert(header_wire[66] == 0 && header_wire[278] == 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    assert(decoded.msg_type == header.msg_type &&
        decoded.elf.len == header.elf.len &&
        decoded.elf.vmid == header.elf.vmid &&
        decoded.elf.epoch == header.elf.epoch &&
        decoded.installed.delivery_id == header.installed.delivery_id &&
        decoded.installed.name[0] == 'v');
    dtraced_wire_put_u16(header_wire + 64, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.elf.vmid == header.elf.vmid);
    dtraced_wire_put_u16(header_wire + 64, header.elf.vmid);
    dtraced_wire_put_u16(header_wire + 344, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.installed.vmid == header.installed.vmid);
    dtraced_wire_put_u16(header_wire + 344, header.installed.vmid);
    dtraced_wire_put_u32(header_wire + 56, 2);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_put_u32(header_wire + 56, 0);
    dtraced_wire_put_u32(header_wire + 60, 2);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_put_u32(header_wire + 60, 0);
    header_wire[144] = 'p';
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_put_u32(header_wire + 56, 1);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    /* The program identity is 128 opaque bytes (libdtrace dp_ident comes
     * from arc4random_buf): bytes after a NUL, no NUL at all, and arbitrary
     * binary values are carried exactly. */
    header_wire[146] = 'x';
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.elf.ident[0] == 'p' && decoded.elf.ident[1] == 0 &&
        decoded.elf.ident[2] == 'x');
    header_wire[146] = 0;
    memset(header_wire + 144, 'x', DTRACED_PROGIDENTLEN);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        memcmp(decoded.elf.ident, header_wire + 144, DTRACED_PROGIDENTLEN) == 0);
    for (unsigned i = 0; i < DTRACED_PROGIDENTLEN; ++i)
        header_wire[144 + i] = (unsigned char)(i * 37 + 0x80);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        memcmp(decoded.elf.ident, header_wire + 144, DTRACED_PROGIDENTLEN) == 0);
    {
        unsigned char again[DTRACED_MSGHDRSIZE];
        dtraced_wire_encode_header(again, &decoded);
        assert(memcmp(again, header_wire, DTRACED_MSGHDRSIZE) == 0);
    }
    /* An absent identity must still be all zero. */
    dtraced_wire_put_u32(header_wire + 56, 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_put_u32(header_wire + 56, 1);
    memset(header_wire + 144, 0, DTRACED_PROGIDENTLEN);
    header_wire[144] = 'p';
    dtraced_wire_put_u32(header_wire + 56, 0);
    header_wire[144] = 0;
    header_wire[81] = 'x'; /* Hidden bytes after an empty location. */
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[81] = 0;
    header_wire[392] = 0;
    header_wire[393] = 0xa5; /* A derived parent slot is binary. */
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    header_wire[408] = 1; /* Only the first 16 bytes carry a session. */
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[408] = 0;
    header_wire[360] = 0; /* Partial parent identity is not canonical. */
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[360] = 1;
    header_wire[392] = 'v';
    header_wire[393] = 0;
    header_wire[66] = 1;
    decoded.msg_type = 99;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.msg_type == 99);
    header_wire[66] = 0;
    header_wire[272] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.msg_type == 99);
    header = {};
    header.msg_type = DTRACED_MSG_KILL;
    header.kill.pid = 7;
    header.kill.vmid = 3;
    header.kill.epoch = 17;
    header.kill.source_id[0] = 0xa5;
    dtraced_wire_encode_header(header_wire, &header);
    assert(header_wire[272] == 7 && header_wire[275] == 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.kill.pid == 7 && decoded.kill.epoch == 17);
    dtraced_wire_put_u32(header_wire + 272, (uint32_t)-7);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u32(header_wire + 272, 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u32(header_wire + 272, 1);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u32(header_wire + 272, 7);
    dtraced_wire_put_u16(header_wire + 276, 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u16(header_wire + 276, header.kill.vmid);
    dtraced_wire_put_u64(header_wire + 280, 0);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u64(header_wire + 280, header.kill.epoch);
    header_wire[288] = 0;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    header_wire[288] = 0xa5;
    dtraced_wire_put_u16(header_wire + 276, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    dtraced_wire_put_u16(header_wire + 276, header.kill.vmid);
    header_wire[8] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[8] = 0;
    header_wire[0] = DTRACED_MSG_KILL_APPLIED;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.kill.pid == 7);
    header_wire[288] = 0;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.kill.pid == 7);
    header = {};
    header.msg_type = DTRACED_MSG_CLEANUP;
    header.cleanup.num_entries = 19;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.cleanup.num_entries == 19);
    header.cleanup.vmid = 7;
    header.cleanup.epoch = 23;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(header) = 0x1234;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.cleanup.vmid == 7 && decoded.cleanup.epoch == 23 &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(decoded) == 0x1234);
    dtraced_wire_put_u16(header_wire + 312, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.cleanup.vmid == 7);
    dtraced_wire_put_u16(header_wire + 312, header.cleanup.vmid);
    header_wire[320] = 0;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[320] = 23;
    header_wire[312] = 0;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_encode_header(header_wire, &header);
    header_wire[328] ^= 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(decoded) !=
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(header));
    header = {};
    header.msg_type = DTRACED_MSG_CLEANUP_APPLIED;
    header.cleanup.vmid = 7;
    header.cleanup.epoch = 23;
    DTRACED_MSG_CLEANUP_DELIVERY_ID(header) = 0x1234;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.cleanup.vmid == 7 && decoded.cleanup.epoch == 23 &&
        DTRACED_MSG_CLEANUP_DELIVERY_ID(decoded) == 0x1234);
    header_wire[304] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[304] = 0;
    std::memset(header_wire + 328, 0, 8);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header = {};
    header.msg_type = DTRACED_MSG_STATS;
    header.cleanup.num_entries = 2;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.cleanup.num_entries == 2);
    header_wire[312] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[312] = 0;
    header_wire[320] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[320] = 0;
    header_wire[328] = 1;
    decoded.cleanup.num_entries = 77;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO && decoded.cleanup.num_entries == 77);
    header = {};
    header.msg_type = DTRACED_MSG_INFO;
    header.info.count = 23;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.info.count == 23);
    header_wire[304] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header = {};
    header.msg_type = DTRACED_MSG_STATUS;
    header.installed.delivery_id = 29;
    memcpy(header.installed.name, "vm", 3);
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.installed.delivery_id == 29);
    header_wire[395] = 'x';
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[395] = 0;
    memset(header_wire + 392, 'x', DTRACED_FDIDENTLEN);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_encode_header(header_wire, &header);
    header_wire[272] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header = {};
    header.msg_type = DTRACED_MSG_HANDOFF;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    header_wire[336] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[336] = 0;
    header = {};
    header.msg_type = DTRACED_MSG_ELF;
    header.elf.len = 4;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    header_wire[392] = 1; /* A session alone is not a parent identity. */
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[392] = 0;
    header = {};
    header.msg_type = DTRACED_MSG_CONSUMER_EXECUTION;
    header.elf.len = DTRACED_CONSUMER_EXECUTION_WIRE_SIZE;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.elf.len == DTRACED_CONSUMER_EXECUTION_WIRE_SIZE);
    header_wire[16] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[16] = 0;
    header_wire[8]--;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_wire_encode_header(header_wire, &header);
    header_wire[336] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header = {};
    header.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
    header.elf.len = 32;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0 &&
        decoded.elf.len == 32);
    header_wire[24] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[24] = 0;
    header_wire[8]--;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header = {};
    header.msg_type = DTRACED_MSG_CONSUMER_DRAIN;
    header.elf.len = DTRACED_CONSUMER_DRAIN_WIRE_SIZE;
    dtraced_wire_encode_header(header_wire, &header);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == 0);
    header_wire[16] = 1;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    header_wire[16] = 0;
    header_wire[8]--;
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_consumer_drain_t drain{};
    dtraced_consumer_drain_t drain_decoded{};
    unsigned char drain_wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
    unsigned char drain_ack_wire[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
    drain.token[0] = 1;
    drain.source_session[0] = 2;
    drain.consumer_session[0] = 3;
    drain.program_digest[0] = 4;
    drain.vmid = 513;
    drain.epoch = UINT64_C(0x0102030405060708);
    drain.result = 1;
    dtraced_wire_encode_consumer_drain(drain_wire, &drain);
    assert(drain_wire[80] == 1 && drain_wire[81] == 2 &&
        drain_wire[82] == 0 && drain_wire[88] == 8 &&
        drain_wire[95] == 1);
    assert(dtraced_wire_decode_consumer_drain(&drain_decoded,
        drain_wire) == 0 && drain_decoded.vmid == drain.vmid &&
        drain_decoded.epoch == drain.epoch &&
        drain_decoded.result == 0);
    drain_wire[82] = 1;
    assert(dtraced_wire_decode_consumer_drain(&drain_decoded,
        drain_wire) == -1 && errno == EPROTO &&
        drain_decoded.vmid == drain.vmid);
    drain_wire[82] = 0;
    dtraced_wire_put_u16(drain_wire + 80, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_consumer_drain(&drain_decoded,
        drain_wire) == -1 && errno == EPROTO);
    dtraced_wire_encode_consumer_drain_ack(drain_ack_wire, &drain);
    assert(dtraced_wire_decode_consumer_drain_ack(&drain_decoded,
        drain_ack_wire) == 0 && drain_decoded.result == 1 &&
        drain_decoded.consumer_session[0] == 3);
    drain_ack_wire[97] = 1;
    assert(dtraced_wire_decode_consumer_drain_ack(&drain_decoded,
        drain_ack_wire) == -1 && errno == EPROTO &&
        drain_decoded.result == 1);
    drain_ack_wire[97] = 0;
    drain_ack_wire[96] = 2;
    assert(dtraced_wire_decode_consumer_drain_ack(&drain_decoded,
        drain_ack_wire) == -1 && errno == EPROTO);
    dtraced_wire_put_u64(header_wire, DTRACED_MSG_LAST + 1);
    assert(dtraced_wire_decode_header(&decoded, header_wire) == -1 &&
        errno == EPROTO);
    dtraced_delivery_status_t status{};
    dtraced_delivery_status_t status_decoded{};
    unsigned char status_wire[DTRACED_STATUS_WIRE_SIZE];
    status.delivery_id = UINT64_C(0x0102030405060708);
    status.phase = 'a'; status.revoked = 1;
    status.digest[0] = 0xa5;
    dtraced_wire_encode_status(status_wire, &status);
    assert(std::memcmp(status_wire, golden, 8) == 0 &&
        status_wire[8] == 'a' && status_wire[9] == 1 &&
        status_wire[16] == 0xa5);
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == 0 &&
        status_decoded.delivery_id == status.delivery_id &&
        status_decoded.phase == status.phase &&
        status_decoded.digest[0] == 0xa5);
    status_wire[11] = 1;
    status_decoded.delivery_id = 99;
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == -1 &&
        errno == EPROTO && status_decoded.delivery_id == 99);
    status_wire[11] = 0;
    status_wire[9] = 2;
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == -1 &&
        errno == EPROTO && status_decoded.delivery_id == 99);
    status_wire[9] = 1;
    status_wire[10] = 2;
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == -1 &&
        errno == EPROTO && status_decoded.delivery_id == 99);
    status_wire[10] = 0;
    status_wire[8] = 'z';
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == -1 &&
        errno == EPROTO && status_decoded.delivery_id == 99);
    status_wire[8] = 0;
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == 0);
    status_wire[8] = 'u';
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == 0);
    status_wire[8] = 'g';
    assert(dtraced_wire_decode_status(&status_decoded, status_wire) == 0);
    dtraced_stats_t stats{};
    dtraced_stats_t stats_decoded{};
    unsigned char stats_wire[DTRACED_STATS_WIRE_SIZE];
    stats.forwarder_channels = UINT64_C(0x0102030405060708);
    stats.outbound_deliveries = 3;
    stats.installed_deliveries = 5;
    stats.revoked_deliveries = 7;
    dtraced_wire_encode_stats(stats_wire, &stats);
    assert(std::memcmp(stats_wire, golden, 8) == 0);
    dtraced_wire_decode_stats(&stats_decoded, stats_wire);
    assert(stats_decoded.forwarder_channels == stats.forwarder_channels &&
        stats_decoded.outbound_deliveries == 3 &&
        stats_decoded.installed_deliveries == 5 &&
        stats_decoded.revoked_deliveries == 7);
    dtraced_delivery_ack_t delivery_ack{};
    dtraced_delivery_ack_t delivery_ack_decoded{};
    unsigned char ack_wire[DTRACED_ACK_WIRE_SIZE];
    delivery_ack.delivery_id = UINT64_C(0x0102030405060708);
    dtraced_wire_encode_ack(ack_wire, &delivery_ack);
    assert(std::memcmp(ack_wire, golden, 8) == 0);
    dtraced_wire_decode_ack(&delivery_ack_decoded, ack_wire);
    assert(delivery_ack_decoded.delivery_id == delivery_ack.delivery_id);
    dtraced_consumer_ack_t consumer_ack{};
    dtraced_consumer_ack_t consumer_ack_decoded{};
    unsigned char consumer_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
    consumer_ack.delivery_id = UINT64_C(0x0102030405060708);
    consumer_ack.program_id[0] = 0xa1;
    consumer_ack.source_id[0] = 0xb2;
    consumer_ack.vmid = 0x0234;
    consumer_ack.outcome = DTRACED_CONSUMER_ACK_NO_DERIVED;
    consumer_ack.epoch = UINT64_C(0x0102030405060708);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    assert(sizeof(consumer_wire) == 56 &&
        std::memcmp(consumer_wire, golden, 8) == 0 &&
        consumer_wire[8] == 0xa1 && consumer_wire[24] == 0xb2 &&
        consumer_wire[40] == 0x34 && consumer_wire[41] == 0x02 &&
        consumer_wire[42] == 1 && consumer_wire[43] == 0 &&
        std::memcmp(consumer_wire + 48, golden, 8) == 0);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == 0 &&
        consumer_ack_decoded.delivery_id == consumer_ack.delivery_id &&
        consumer_ack_decoded.program_id[0] == 0xa1 &&
        consumer_ack_decoded.source_id[0] == 0xb2 &&
        consumer_ack_decoded.vmid == 0x0234 &&
        consumer_ack_decoded.outcome == DTRACED_CONSUMER_ACK_NO_DERIVED &&
        consumer_ack_decoded.epoch == consumer_ack.epoch);
    dtraced_wire_put_u64(consumer_wire, 0);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.delivery_id == consumer_ack.delivery_id);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    std::memset(consumer_wire + 8, 0, 16);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.program_id[0] == 0xa1);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    std::memset(consumer_wire + 24, 0, 16);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.source_id[0] == 0xb2);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    consumer_wire[42] = 0;
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.outcome == DTRACED_CONSUMER_ACK_NO_DERIVED);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    dtraced_wire_put_u64(consumer_wire + 48, 0);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.epoch == consumer_ack.epoch);
    dtraced_wire_encode_consumer_ack(consumer_wire, &consumer_ack);
    consumer_wire[43] = 1;
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO);
    consumer_wire[43] = 0;
    consumer_wire[40] = consumer_wire[41] = 0;
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO);
    dtraced_wire_put_u16(consumer_wire + 40, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO);
    dtraced_wire_put_u16(consumer_wire + 40, DTRACED_WIRE_MAX_VMS - 1);
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == 0);
    dtraced_wire_put_u16(consumer_wire + 40, consumer_ack.vmid);
    unsigned char execution_wire[DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
    consumer_ack.ingress_session[0] = 0x91;
    dtraced_wire_encode_consumer_execution(execution_wire, &consumer_ack);
    assert(dtraced_wire_decode_consumer_execution(&consumer_ack_decoded,
        execution_wire) == 0 &&
        consumer_ack_decoded.ingress_session[0] == 0x91);
    dtraced_wire_put_u64(execution_wire + 48, 0);
    assert(dtraced_wire_decode_consumer_execution(&consumer_ack_decoded,
        execution_wire) == -1 && errno == EPROTO &&
        consumer_ack_decoded.epoch == consumer_ack.epoch);
    dtraced_wire_put_u64(execution_wire + 48, consumer_ack.epoch);
    dtraced_wire_put_u16(execution_wire + 40, DTRACED_WIRE_MAX_VMS);
    assert(dtraced_wire_decode_consumer_execution(&consumer_ack_decoded,
        execution_wire) == -1 && errno == EPROTO);
    dtraced_wire_put_u16(execution_wire + 40, consumer_ack.vmid);
    execution_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE] = 0;
    assert(dtraced_wire_decode_consumer_execution(&consumer_ack_decoded,
        execution_wire) == -1 && errno == EPROTO);
    consumer_wire[42] = 2;
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == 0 &&
        consumer_ack_decoded.outcome == DTRACED_CONSUMER_ACK_DERIVED);
    consumer_wire[42] = 3;
    assert(dtraced_wire_decode_consumer_ack(&consumer_ack_decoded,
        consumer_wire) == -1 && errno == EPROTO);
    dtraced_infomsg_t info{};
    dtraced_infomsg_t info_decoded{};
    unsigned char info_wire[DTRACED_INFO_WIRE_SIZE];
    info.client_kind = DTRACED_KIND_FORWARDER;
    info.client_name[0] = 'v';
    dtraced_wire_encode_info(info_wire, &info);
    assert(info_wire[0] == DTRACED_KIND_FORWARDER &&
        info_wire[1] == 0 && info_wire[4] == 'v');
    assert(dtraced_wire_decode_info(&info_decoded, info_wire) == 0);
    assert(info_decoded.client_kind == info.client_kind &&
        info_decoded.client_name[0] == 'v');
    info_wire[0] = DTRACED_KIND_CONSUMER;
    info_wire[4] = 0; /* Empty consumer names remain valid on protocol 40. */
    assert(dtraced_wire_decode_info(&info_decoded, info_wire) == 0 &&
        info_decoded.client_kind == DTRACED_KIND_CONSUMER &&
        info_decoded.client_name[0] == 0);
    info_wire[0] = DTRACED_KIND_FORWARDER;
    info_wire[4] = 'v';
    info_wire[0] = DTRACED_KIND_UNKNOWN;
    assert(dtraced_wire_decode_info(&info_decoded, info_wire) == -1 &&
        errno == EPROTO);
    info_wire[0] = DTRACED_KIND_FORWARDER;
    info_wire[6] = 'x';
    assert(dtraced_wire_decode_info(&info_decoded, info_wire) == -1 &&
        errno == EPROTO);
    info_wire[6] = 0;
    memset(info_wire + 4, 'x', DTRACED_FDIDENTLEN);
    assert(dtraced_wire_decode_info(&info_decoded, info_wire) == -1 &&
        errno == EPROTO);
    dtraced_handoff_request_t handoff{};
    dtraced_handoff_request_t handoff_decoded{};
    unsigned char handoff_wire[DTRACED_HANDOFF_WIRE_SIZE];
    handoff.op = DTRACED_HANDOFF_COMMIT;
    for (unsigned i = 0; i < 16; i++)
        handoff.token[i] = (unsigned char)(0xa0 + i);
    for (unsigned i = 0; i < 32; i++)
        handoff.digest[i] = (unsigned char)(0xb0 + i);
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(sizeof(handoff_wire) == 49 &&
        handoff_wire[0] == DTRACED_HANDOFF_COMMIT &&
        std::memcmp(handoff_wire + 1, handoff.token, 16) == 0 &&
        std::memcmp(handoff_wire + 17, handoff.digest, 32) == 0);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op &&
        std::memcmp(handoff_decoded.token, handoff.token, 16) == 0 &&
        std::memcmp(handoff_decoded.digest, handoff.digest, 32) == 0);
    handoff.op = DTRACED_HANDOFF_REKEY_APPLIED;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_PROMOTE_IMPORT;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_ACTIVATE_IMPORT;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REPLAY_READY;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_EXECUTION_START;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REBIND_BEGIN;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_RESET_MUTATION;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REBIND_STAGE;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REBIND_PENDING;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_REBIND_CANCEL_PENDING;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_SOURCE_RELEASE;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_RELEASE_RECOVER;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_SOURCE_GATE_BEGIN;
    std::memset(handoff.digest, 0, sizeof(handoff.digest));
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.op = DTRACED_HANDOFF_SOURCE_GATE_ABORT;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    handoff.digest[0] = 1;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == -1 && errno == EPROTO);
	/* A drain step carries the exact HTX1 digest, unlike gate begin/abort. */
	handoff.op = DTRACED_HANDOFF_SOURCE_DRAIN_STEP;
	dtraced_wire_encode_handoff(handoff_wire, &handoff);
	assert(dtraced_wire_decode_handoff(&handoff_decoded,
	    handoff_wire) == 0 && handoff_decoded.op == handoff.op);
	handoff.digest[0] = 0;
	dtraced_wire_encode_handoff(handoff_wire, &handoff);
	assert(dtraced_wire_decode_handoff(&handoff_decoded,
	    handoff_wire) == -1 && errno == EPROTO);
    handoff.op = DTRACED_HANDOFF_SOURCE_GATE_ABORT;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    std::memset(handoff_wire + 17, 0, 32);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0);
    handoff.op = DTRACED_HANDOFF_SOURCE_RELEASE;
    for (unsigned i = 0; i < 32; i++)
        handoff.digest[i] = (unsigned char)(0xb0 + i);
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    handoff.op = DTRACED_HANDOFF_COMMIT;
    handoff_wire[0] = 99;
    handoff_decoded.op = 42;
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == -1 && errno == EPROTO &&
        handoff_decoded.op == 42);
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    std::memset(handoff_wire + 1, 0, 16);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == -1 && errno == EPROTO);
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    std::memset(handoff_wire + 17, 0, 32);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == -1 && errno == EPROTO);
    handoff.op = DTRACED_HANDOFF_PREPARE;
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == 0 && handoff_decoded.op == handoff.op);
    std::memset(handoff.digest, 0, sizeof(handoff.digest));
    dtraced_wire_encode_handoff(handoff_wire, &handoff);
    assert(dtraced_wire_decode_handoff(&handoff_decoded,
        handoff_wire) == -1 && errno == EPROTO);
    dtraced_handoff_delivery_request_t delivery{};
    dtraced_handoff_delivery_request_t delivery_decoded{};
    unsigned char delivery_wire[DTRACED_HANDOFF_DELIVERY_WIRE_SIZE];
    delivery.token[0] = 0xa1;
    delivery.digest[0] = 0xb2;
    delivery.delivery_id = UINT64_C(0x0102030405060708);
    delivery.program_id[0] = 0xc3;
    delivery.source_id[0] = 0xd4;
    delivery.scope = 3;
    dtraced_wire_encode_handoff_delivery(delivery_wire, &delivery);
    assert(delivery_wire[0] == 0xa1 && delivery_wire[16] == 0xb2 &&
        std::memcmp(delivery_wire + 48, golden, 8) == 0 &&
        delivery_wire[56] == 0xc3 && delivery_wire[72] == 0xd4 &&
        delivery_wire[88] == 3 && delivery_wire[89] == 0);
    assert(dtraced_wire_decode_handoff_delivery(&delivery_decoded,
        delivery_wire) == 0 &&
        delivery_decoded.delivery_id == delivery.delivery_id &&
        delivery_decoded.scope == delivery.scope);
    delivery_wire[95] = 1;
    delivery_decoded.delivery_id = 99;
    assert(dtraced_wire_decode_handoff_delivery(&delivery_decoded,
        delivery_wire) == -1 && errno == EPROTO &&
        delivery_decoded.delivery_id == 99);
    for (const auto &[offset, length] : {
        std::pair<size_t, size_t>{0, 16}, {16, 32}, {48, 8},
        {56, 16}, {72, 16}}) {
        dtraced_wire_encode_handoff_delivery(delivery_wire, &delivery);
        std::memset(delivery_wire + offset, 0, length);
        delivery_decoded.delivery_id = 99;
        assert(dtraced_wire_decode_handoff_delivery(&delivery_decoded,
            delivery_wire) == -1 && errno == EPROTO &&
            delivery_decoded.delivery_id == 99);
    }
    dtraced_wire_encode_handoff_delivery(delivery_wire, &delivery);
    delivery_wire[88] = 4;
    assert(dtraced_wire_decode_handoff_delivery(&delivery_decoded,
        delivery_wire) == -1 && errno == EPROTO);
    dtraced_handoff_bind_delivery_request_t bound_delivery{};
    dtraced_handoff_bind_delivery_request_t bound_decoded{};
    unsigned char bound_wire[DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE];
    delivery.scope = 0;
    bound_delivery.delivery = delivery;
    bound_delivery.payload_digest[0] = 0xe5;
    dtraced_wire_encode_handoff_bind_delivery(bound_wire,
        &bound_delivery);
    assert(bound_wire[96] == 0xe5 &&
        dtraced_wire_decode_handoff_bind_delivery(&bound_decoded,
        bound_wire) == 0 &&
        bound_decoded.delivery.delivery_id == delivery.delivery_id &&
        bound_decoded.payload_digest[0] == 0xe5);
    std::memset(bound_wire + 96, 0, 32);
    bound_decoded.delivery.delivery_id = 99;
    assert(dtraced_wire_decode_handoff_bind_delivery(&bound_decoded,
        bound_wire) == -1 && errno == EPROTO &&
        bound_decoded.delivery.delivery_id == 99);
    bound_delivery.delivery.scope = 3;
    dtraced_wire_encode_handoff_bind_delivery(bound_wire,
        &bound_delivery);
    assert(dtraced_wire_decode_handoff_bind_delivery(&bound_decoded,
        bound_wire) == -1 && errno == EPROTO);
    dtraced_handoff_kill_request_t kill{};
    dtraced_handoff_kill_request_t kill_decoded{};
    unsigned char kill_wire[DTRACED_HANDOFF_KILL_WIRE_SIZE];
    kill.token[0] = 0xa1;
    kill.digest[0] = 0xb2;
    kill.pid = 0x01020304;
    kill.source_id[0] = 0xc3;
    dtraced_wire_encode_handoff_kill(kill_wire, &kill);
    assert(kill_wire[0] == 0xa1 && kill_wire[16] == 0xb2 &&
        kill_wire[48] == 4 && kill_wire[49] == 3 &&
        kill_wire[50] == 2 && kill_wire[51] == 1 &&
        kill_wire[52] == 0xc3 && kill_wire[68] == 0);
    assert(dtraced_wire_decode_handoff_kill(&kill_decoded,
        kill_wire) == 0 && kill_decoded.pid == kill.pid &&
        kill_decoded.source_id[0] == kill.source_id[0]);
    kill_wire[71] = 1;
    kill_decoded.pid = 99;
    assert(dtraced_wire_decode_handoff_kill(&kill_decoded,
        kill_wire) == -1 && errno == EPROTO && kill_decoded.pid == 99);
    for (const auto &[offset, length] : {
        std::pair<size_t, size_t>{0, 16}, {16, 32}, {52, 16}}) {
        dtraced_wire_encode_handoff_kill(kill_wire, &kill);
        std::memset(kill_wire + offset, 0, length);
        kill_decoded.pid = 99;
        assert(dtraced_wire_decode_handoff_kill(&kill_decoded,
            kill_wire) == -1 && errno == EPROTO &&
            kill_decoded.pid == 99);
    }
    dtraced_wire_encode_handoff_kill(kill_wire, &kill);
    std::memset(kill_wire + 48, 0, 4);
    assert(dtraced_wire_decode_handoff_kill(&kill_decoded,
        kill_wire) == -1 && errno == EPROTO);
    dtraced_handoff_cleanup_request_t cleanup_lookup{};
    dtraced_handoff_cleanup_request_t cleanup_decoded{};
    unsigned char cleanup_wire[DTRACED_HANDOFF_CLEANUP_WIRE_SIZE];
    cleanup_lookup.token[0] = 0xa1;
    cleanup_lookup.digest[0] = 0xb2;
    cleanup_lookup.delivery_id = UINT64_C(0x0102030405060708);
    dtraced_wire_encode_handoff_cleanup(cleanup_wire, &cleanup_lookup);
    assert(cleanup_wire[48] == 8 && cleanup_wire[55] == 1 &&
        dtraced_wire_decode_handoff_cleanup(&cleanup_decoded,
        cleanup_wire) == 0 &&
        cleanup_decoded.delivery_id == cleanup_lookup.delivery_id);
    std::memset(cleanup_wire + 48, 0, 8);
    assert(dtraced_wire_decode_handoff_cleanup(&cleanup_decoded,
        cleanup_wire) == -1 && errno == EPROTO);
    dtraced_launch_result_t launch{};
    dtraced_launch_result_t launch_decoded{};
    unsigned char launch_wire[DTRACED_LAUNCH_WIRE_SIZE];
    launch.magic = DTRACED_LAUNCH_MAGIC;
    launch.installed = 1;
    launch.source_ident[0] = 'p';
    dtraced_wire_encode_launch(launch_wire, &launch);
    const unsigned char launch_magic[8] = {
        'H', 'T', 'I', 'N', 'S', 'T', '1', 0
    };
    assert(std::memcmp(launch_wire, launch_magic, 8) == 0 &&
        launch_wire[8] == 1 && launch_wire[9] == 0 &&
        launch_wire[16] == 'p');
    assert(dtraced_wire_decode_launch(&launch_decoded,
        launch_wire) == 0 &&
        launch_decoded.magic == launch.magic &&
        launch_decoded.installed == launch.installed &&
        launch_decoded.source_ident[0] == 'p');
    launch_wire[15] = 1;
    launch_decoded.magic = 99;
    assert(dtraced_wire_decode_launch(&launch_decoded,
        launch_wire) == -1 && errno == EPROTO &&
        launch_decoded.magic == 99);
    dtraced_wire_encode_launch(launch_wire, &launch);
    launch_wire[0] ^= 1;
    assert(dtraced_wire_decode_launch(&launch_decoded,
        launch_wire) == -1 && errno == EPROTO &&
        launch_decoded.magic == 99);
    dtraced_wire_encode_launch(launch_wire, &launch);
    launch_wire[8] = 2;
    assert(dtraced_wire_decode_launch(&launch_decoded,
        launch_wire) == -1 && errno == EPROTO &&
        launch_decoded.magic == 99);
    std::vector<unsigned char> b;
    append(b, "first", 6); append(b, "second", 7);
    assert(b[0] == 6 && b[1] == 0 && b[7] == 0);
    std::vector<std::string> out {"unchanged"};
    assert(parse_cleanup(b.data(), b.size(), 2, out));
    assert((out == std::vector<std::string>{"first", "second"}));
    for (size_t n = 0; n < b.size(); ++n) {
        out = {"unchanged"}; assert(!parse_cleanup(b.data(), n, 2, out));
        assert(out == std::vector<std::string>{"unchanged"});
    }
    assert(!parse_cleanup(b.data(), b.size(), 1, out));
    assert(!parse_cleanup(b.data(), b.size(), max_cleanup_entries + 1, out));
    out = {"unchanged"};
    assert(!parse_cleanup(nullptr, b.size(), 1, out));
    assert((out == std::vector<std::string>{"unchanged"}));
    dtraced_wire_put_u64(b.data(), UINT64_MAX);
    assert(!parse_cleanup(b.data(), b.size(), 2, out));
    dtraced_wire_put_u64(b.data(), 0);
    assert(!parse_cleanup(b.data(), b.size(), 2, out));
    b.clear(); append(b, "bad", 3); assert(!parse_cleanup(b.data(), b.size(), 1, out));
    b.clear(); append(b, "a\0b", 4); assert(!parse_cleanup(b.data(), b.size(), 1, out));
    b.clear(); assert(parse_cleanup(b.data(), 0, 0, out)); assert(out.empty());
    dtraced_rebind_decision_v2 decision{};
    std::memcpy(decision.intent.data(), "HRI1", 4);
    dtraced_wire_put_u32(decision.intent.data() + 4, 1);
    decision.intent[12] = 0xa1; /* Original claimed HTH2 token. */
    decision.intent[160] = 7;
    assert(SHA256(decision.intent.data(), 196,
        decision.intent.data() + 196) != nullptr);
    decision.plan_digest[0] = 0xb2;
    decision.stage_digest[0] = 0xc3;
    decision.foreign = true;
    std::array<uint8_t, DTRACED_REBIND_DECISION_V2_SIZE> decision_wire{};
    std::array<uint8_t, 16> decision_token{};
    decision_token[0] = 0xa1;
    dtraced_rebind_decision_v2 parsed{};
    assert(dtraced_rebind_decision_v2_encode(decision_wire.data(),
        decision) == 0);
    assert(dtraced_rebind_decision_v2_decode(&parsed,
        decision_wire.data(), decision_token.data()) == 0 &&
        parsed.foreign && parsed.intent == decision.intent &&
        parsed.plan_digest == decision.plan_digest &&
        parsed.stage_digest == decision.stage_digest);
    auto corrupt = decision_wire;
    corrupt[9] = 1;
    assert(SHA256(corrupt.data(), corrupt.size() - 32,
        corrupt.data() + corrupt.size() - 32) != nullptr);
    assert(dtraced_rebind_decision_v2_decode(&parsed, corrupt.data(),
        decision_token.data()) == -1 && errno == EPROTO && parsed.foreign);
    corrupt = decision_wire;
    corrupt[276] = 0; /* Foreign HJB1 digest cannot disappear. */
    assert(SHA256(corrupt.data(), corrupt.size() - 32,
        corrupt.data() + corrupt.size() - 32) != nullptr);
    assert(dtraced_rebind_decision_v2_decode(&parsed, corrupt.data(),
        decision_token.data()) == -1 && errno == EPROTO && parsed.foreign);
    decision_token[0] = 0xa2;
    assert(dtraced_rebind_decision_v2_decode(&parsed,
        decision_wire.data(), decision_token.data()) == -1 &&
        errno == EPROTO && parsed.foreign);
    decision_token[0] = 0xa1;
    decision.foreign = false;
    decision.stage_digest = {};
    assert(dtraced_rebind_decision_v2_encode(decision_wire.data(),
        decision) == 0);
    assert(dtraced_rebind_decision_v2_decode(&parsed,
        decision_wire.data(), decision_token.data()) == 0 &&
        !parsed.foreign);
    return 0;
}
