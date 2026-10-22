/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <openssl/sha.h>
#include <algorithm>
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <poll.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"
#include "dtraced_derived.h"

using namespace dtraced;

class test_client_fd : public client_fd {
public:
	using client_fd::client_fd;
	void set_kq(int descriptor) { kq = descriptor; }
};

static std::string
import_outcome_name(const std::array<uint8_t, 16> &token,
    const std::array<uint8_t, 32> &receipt_digest, char phase)
{
	static const char hex[] = "0123456789abcdef";
	std::string name = ".hro1.";
	for (uint8_t byte : token) {
		name.push_back(hex[byte >> 4]);
		name.push_back(hex[byte & 15]);
	}
	name.push_back('.');
	for (uint8_t byte : receipt_digest) {
		name.push_back(hex[byte >> 4]);
		name.push_back(hex[byte & 15]);
	}
	name.push_back('.');
	name.push_back(phase);
	return (name);
}

static void
bind_empty_transfer(durable_handoff &ticket)
{
    std::vector<uint8_t> bytes;
    assert(dtraced_transfer_wire_build(ticket.token.data(), {}, {}, bytes));
    memcpy(ticket.transfer_digest.data(), bytes.data() + bytes.size() - 32,
        ticket.transfer_digest.size());
}
namespace dtraced {
struct state_attestation_test {
    static void set_control(state &s) { s.ctrlmachine = 1; }
};
}
static int attestation_fd = -1;
static hypertrace_vm_attestation identity{};
static int drain_gate_fd = -1;
static bool drain_gate_suspended;
static uint8_t drain_gate_token[16] = {};
extern "C" int __real_open(const char *, int, ...);
extern "C" int __wrap_open(const char *path, int flags, ...)
{
    if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
        drain_gate_fd = __real_open("/dev/null", flags);
        return drain_gate_fd;
    }
    va_list args;
    va_start(args, flags);
    mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(args, int) : 0;
    va_end(args);
    return __real_open(path, flags, mode);
}
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
    if (fd == drain_gate_fd && (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY ||
        request == HYPERTRACE_IOC_EPOCH_SUSPEND ||
        request == HYPERTRACE_IOC_EPOCH_RESUME)) {
        va_list args;
        va_start(args, request);
        auto *gate = va_arg(args, hypertrace_epoch_gate *);
        va_end(args);
        if (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
            gate->suspended = drain_gate_suspended ? 1 : 0;
            memcpy(gate->token, drain_gate_token, sizeof(drain_gate_token));
            return 0;
        }
        if (request == HYPERTRACE_IOC_EPOCH_SUSPEND &&
            !drain_gate_suspended &&
            memcmp(gate->previous_token, drain_gate_token, 16) == 0) {
            drain_gate_suspended = true;
            memcpy(drain_gate_token, gate->token, 16);
            return 0;
        }
        if (request == HYPERTRACE_IOC_EPOCH_RESUME &&
            drain_gate_suspended &&
            memcmp(gate->token, drain_gate_token, 16) == 0) {
            drain_gate_suspended = false;
            return 0;
        }
        errno = ESTALE;
        return -1;
    }
    if (fd != attestation_fd || request != VM_GET_ATTESTATION) {
        errno = ENOTTY;
        return -1;
    }
    va_list args;
    va_start(args, request);
    void *data = va_arg(args, void *);
    va_end(args);
    memcpy(data, &identity, sizeof(identity));
    return 0;
}

int main()
{
    alarm(45);
    char path[] = "/tmp/hypertrace-host-ingress.XXXXXX";
    char outbound_path[] = "/tmp/hypertrace-host-kills.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    assert(mkdtemp(outbound_path) != nullptr);
    int sockets[2], consumer_sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, consumer_sockets) == 0);
    int kq = kqueue(); assert(kq >= 0);
    state host{};
    state_attestation_test::set_control(host);
    dir inbound(path, &process_inbound);
    dir outbound(outbound_path, &process_outbound);
    host.inbounddir = &inbound;
    host.outbounddir = &outbound;
    inbound.state = &host;
    outbound.state = &host;
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_READDATA;
    hello.session_id[0] = 0x47;
    strcpy(hello.ident, "guest-a");
    client_fd forwarder(kq, sockets[0], hello);
    attestation_fd = dup(sockets[0]);
    assert(attestation_fd >= 0);
    forwarder.vm_attestation_fd = attestation_fd;
    forwarder.vmid = identity.vmid = 7;
    forwarder.vm_epoch = identity.epoch = 42;
    strcpy(identity.name, "guest-a");
    hypertrace_vm_envelope envelope{};
    envelope.magic = HYPERTRACE_ENVELOPE_MAGIC;
    envelope.version = HYPERTRACE_ENVELOPE_VERSION;
    envelope.vmid = 7;
    envelope.epoch = 42;
    envelope.name_length = 7;
    const char elf[] = "\177ELFguest";
    std::vector<unsigned char> payload(HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
        7 + sizeof(elf));
    hypertrace_envelope_encode(payload.data(), &envelope);
    memcpy(payload.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "guest-a", 7);
    memcpy(payload.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7,
        elf, sizeof(elf));
    dtraced_hdr_t header{};
    header.msg_type = DTRACED_MSG_ELF;
    header.elf.len = payload.size();
    header.elf.delivery_id = 99;
    header.elf.program_id[0] = 0xaa;
    header.elf.source_id[0] = 0xbb;
    strcpy(header.elf.location, "inbound");
    auto send = [&](const std::vector<unsigned char> &bytes) {
        client_request request(host, header,
            const_cast<unsigned char *>(bytes.data()), bytes.size(),
            &forwarder);
        return request.handle();
    };
    payload[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE] ^= 1;
    assert(!send(payload) && errno == EPROTO);
    payload[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE] ^= 1;
	uint8_t orphan_program[16] = { 0xee };
	uint8_t orphan_source[16] = { 0xff };
	bool orphan_created = false;
	assert(inbound.write_identified_data(payload.data(), payload.size(),
	    orphan_program, &orphan_created, orphan_source) && orphan_created);
	header.elf.delivery_id = 102;
	header.elf.program_id[0] = 0xee;
	header.elf.source_id[0] = 0xff;
	assert(!send(payload) && errno == EEXIST);
	dirent orphan_file{};
	strcpy(orphan_file.d_name,
	    "elf.ee000000000000000000000000000000.ff000000000000000000000000000000");
	assert(process_inbound(inbound, &orphan_file));
	assert(inbound.memorized(orphan_file.d_name) && host.joblist.empty());
	assert(unlinkat(inbound.dirfd,
	    "elf.ee000000000000000000000000000000.ff000000000000000000000000000000",
	    0) == 0);
	header.elf.delivery_id = 99;
	header.elf.program_id[0] = 0xaa;
	header.elf.source_id[0] = 0xbb;
    assert(send(payload));
    std::vector<durable_delivery_state> records;
    assert(inbound.list_deliveries(records) && records.size() == 1);
    assert(records[0].record.scope == 3 &&
        records[0].record.journal_version == 4 &&
        records[0].phase == delivery_phase::accepted);
    uint8_t digest[32];
    assert(SHA256((const unsigned char *)elf, sizeof(elf), digest));
    assert(memcmp(records[0].record.payload_digest.data(), digest, 32) == 0);
    dtraced_hdr_t query{};
    query.msg_type = DTRACED_MSG_INGRESS_STATUS;
    query.installed.delivery_id = 99;
    query.installed.vmid = 7;
    query.installed.epoch = 42;
    query.installed.program_id[0] = 0xaa;
    query.installed.source_id[0] = 0xbb;
    strcpy(query.installed.name, "guest-a");
    auto status = [&] {
        client_request request(host, query, nullptr, 0, &forwarder);
        assert(request.handle() && request.status_response() != nullptr);
        return *request.status_response();
    };
    auto answer = status();
    assert(answer.delivery_id == 99 && answer.phase == 'a' &&
        answer.revoked == 0 && answer.replay == 0 &&
        memcmp(answer.digest, digest, 32) == 0);

    /* A restarted host daemon gives this attested VM a new socket session.
     * Its original token must still name the accepted transaction. */
    forwarder.session_id[0] = 0x48;
    answer = status();
    assert(answer.phase == 'a' && memcmp(answer.digest, digest, 32) == 0);
    assert(send(payload));
    records.clear();
    assert(inbound.list_deliveries(records) && records.size() == 1);
    query.installed.source_id[0] ^= 1;
    {
        client_request wrong(host, query, nullptr, 0, &forwarder);
        assert(!wrong.handle() && errno == EPROTO);
    }
    query.installed.source_id[0] ^= 1;
    assert(send(payload));
    records.clear();
    assert(inbound.list_deliveries(records) && records.size() == 1);
    payload.back() ^= 1;
    assert(!send(payload) && errno == EPROTO);
    payload.back() ^= 1;

    durable_delivery pending = records[0].record;
    pending.delivery_id = 100;
    pending.program_id[0] = 0xcc;
    pending.source_id[0] = 0xdd;
    assert(inbound.record_delivery(pending, delivery_phase::pending, true));
    durable_handoff pending_cut{};
    pending_cut.token[0] = 0x6b;
    pending_cut.source_session = forwarder.session_id;
    pending_cut.source_vmid = forwarder.vmid;
    pending_cut.source_epoch = forwarder.vm_epoch;
    assert(!outbound.prepare_handoff(pending_cut, false) && errno == EBUSY);
    query.installed.delivery_id = 100;
    query.installed.program_id[0] = 0xcc;
    query.installed.source_id[0] = 0xdd;
    answer = status();
    assert(answer.phase == 'p' && memcmp(answer.digest, digest, 32) == 0);
    assert(inbound.write_identified_data(payload.data(), payload.size(),
        pending.program_id.data(), nullptr, pending.source_id.data()));
    dirent accepted_file{};
    strcpy(accepted_file.d_name,
        "elf.aa000000000000000000000000000000.bb000000000000000000000000000000");
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty() && !inbound.memorized(accepted_file.d_name));
    dtd_initmsg_t consumer_hello{};
    consumer_hello.kind = DTRACED_KIND_CONSUMER;
    consumer_hello.subs = DTD_SUB_ELFWRITE;
    consumer_hello.session_id[0] = 0x76;
    std::snprintf(consumer_hello.ident, sizeof(consumer_hello.ident),
        "dtrace-%u-00000000000000000000000000000001",
        (unsigned)getpid());
    client_fd consumer(kq, consumer_sockets[0], consumer_hello);
    assert(consumer.enable_write(&consumer));
    host.sockfds.insert(&consumer);
    consumer.consumer_replay_pending = true;
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty() && !inbound.memorized(accepted_file.d_name));
    assert(consumer.consumer_birth_valid);
    /* Admission has opened, but no registration has arrived. Neither the
     * watcher nor an already queued job may deliver the first program. */
    consumer.consumer_replay_pending = false;
    assert(!consumer.consumer_replay_registration_pending.load());
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty() && !inbound.memorized(accepted_file.d_name));
    assert(inbound.queue_recovered_consumer(&consumer) == 0);
    assert(consumer.consumer_replay_registration_pending.load());
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty() && !inbound.memorized(accepted_file.d_name));
    {
        job early(NOTIFY_ELFWRITE, &consumer);
        auto &ne = early.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound; ne.nosha = true;
        assert(ne.path != nullptr);
        assert(!early.send_elf() && errno == EAGAIN);
        char byte;
        assert(recv(consumer_sockets[1], &byte, 1, MSG_DONTWAIT) == -1 &&
            (errno == EAGAIN || errno == EWOULDBLOCK));
    }
    dtraced_hdr_t program_announcement{};
    program_announcement.msg_type = DTRACED_MSG_CONSUMER_PROGRAM;
    program_announcement.elf.len = 32;
    std::array<uint8_t, 32> announced_program{};
    announced_program[0] = 0x51;
    auto announce = [&]() {
        client_request request(host, program_announcement,
            announced_program.data(), announced_program.size(), &consumer);
        return request.handle();
    };
    announced_program.fill(0);
    assert(!announce() && errno == EPROTO);
    assert(!consumer.consumer_program_valid &&
        consumer.consumer_replay_registration_pending.load());
    assert(host.joblist.empty());
    announced_program[0] = 0x51;
    assert(announce() && consumer.consumer_program_valid &&
        consumer.consumer_program_digest == announced_program);
    assert(!consumer.consumer_replay_registration_pending.load());
    assert(consumer.consumer_import_scan_done);
    assert(announce()); /* Exact retry retains the same connection binding. */
    announced_program[0] = 0x52;
    assert(!announce() && errno == EEXIST &&
        consumer.consumer_program_digest[0] == 0x51);
    announced_program.fill(0);
    assert(!announce() && errno == EPROTO);
    announced_program[0] = 0x51;
    host.sockfds.erase(&consumer);
    assert(!announce() && errno == EBUSY);
    host.sockfds.insert(&consumer);
    assert(inbound.queue_recovered_consumer(&consumer) == 0);
    consumer.consumer_replay_pending = false;
    auto acknowledge = [&](uint8_t outcome) {
        dtraced_consumer_ack_t ack{};
        unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
        ack.delivery_id = 99;
        ack.program_id[0] = 0xaa;
        ack.source_id[0] = 0xbb;
        ack.vmid = 7;
        ack.epoch = 42;
        ack.outcome = outcome;
        dtraced_wire_encode_consumer_ack(wire, &ack);
        assert(write(consumer_sockets[1], wire, sizeof(wire)) ==
            (ssize_t)sizeof(wire));
    };
    dirent file{};
    strcpy(file.d_name,
        "elf.cc000000000000000000000000000000.dd000000000000000000000000000000");
    assert(inbound.memorize_file(&file)); /* Startup saw an unresolved spool. */
    assert(process_inbound(inbound, &file));
    assert(host.joblist.empty() && inbound.memorized(file.d_name));
    header.elf.delivery_id = pending.delivery_id;
    header.elf.program_id[0] = 0xcc;
    header.elf.source_id[0] = 0xdd;
    assert(send(payload));
    assert(!inbound.memorized(file.d_name));
    assert(process_inbound(inbound, &file));
    assert(host.joblist.size() == 1 && inbound.memorized(file.d_name));
    delete host.joblist.front();
    host.joblist.clear();
    header.elf.delivery_id = 99;
    header.elf.program_id[0] = 0xaa;
    header.elf.source_id[0] = 0xbb;
    query.installed.delivery_id = 99;
    query.installed.program_id[0] = 0xaa;
    query.installed.source_id[0] = 0xbb;
    consumer.consumer_replay_registration_pending.store(true);
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty() && !inbound.memorized(accepted_file.d_name));
    consumer.consumer_replay_registration_pending.store(false);
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.size() == 1 && inbound.memorized(accepted_file.d_name));
    std::vector<durable_consumer_receipt_state> program_receipts;
    assert(inbound.list_consumer_receipts(program_receipts));
    auto program_receipt = std::find_if(program_receipts.begin(),
        program_receipts.end(), [](const auto &entry) {
        return entry.record.ingress.delivery_id == 99;
    });
    assert(program_receipt != program_receipts.end());
    std::array<uint8_t, 76> recorded_owner{};
    std::array<uint8_t, 32> recorded_program{};
    assert(inbound.consumer_program_status(program_receipt->record,
        recorded_owner, recorded_program) == 1 &&
        recorded_program == announced_program &&
        memcmp(recorded_owner.data() + 28,
        consumer.consumer_birth.data(), 16) == 0);
    assert(inbound.record_consumer_program(program_receipt->record,
        consumer) == 1);
    DIR *program_scan = fdopendir(dup(inbound.dirfd));
    assert(program_scan != nullptr);
    std::string program_name;
    char program_delivery[20];
    assert(snprintf(program_delivery, sizeof(program_delivery),
        ".%016jx.", (uintmax_t)program_receipt->record.ingress.delivery_id)
        > 0);
    for (dirent *entry; (entry = readdir(program_scan)) != nullptr;)
        if (strncmp(entry->d_name, ".program.", 9) == 0 &&
            strstr(entry->d_name, program_delivery) != nullptr)
            program_name = entry->d_name;
    assert(closedir(program_scan) == 0 && !program_name.empty());
    int program_fd = openat(inbound.dirfd, program_name.c_str(),
        O_RDWR | O_NOFOLLOW);
    assert(program_fd >= 0);
    uint8_t trailer;
    assert(pread(program_fd, &trailer, 1, 301) == 1);
    uint8_t changed_trailer = trailer ^ 1;
    assert(pwrite(program_fd, &changed_trailer, 1, 301) == 1 &&
        fsync(program_fd) == 0);
    assert(inbound.consumer_program_status(program_receipt->record,
        recorded_owner, recorded_program) == -1 && errno == EPROTO &&
        recorded_owner == decltype(recorded_owner){} &&
        recorded_program == decltype(recorded_program){});
    assert(pwrite(program_fd, &trailer, 1, 301) == 1 &&
        fsync(program_fd) == 0 && close(program_fd) == 0);
    assert(inbound.consumer_program_status(program_receipt->record,
        recorded_owner, recorded_program) == 1 &&
        recorded_program == announced_program);
    /* A queued ordinary delivery cannot bypass modern HPI2 registration.
     * Upgrade this fixture's legacy handle record temporarily; the real send
     * path must refuse before emitting even a header byte. */
    {
        std::string handle_name = ".handle." + program_name.substr(9);
        int fd = openat(inbound.dirfd, handle_name.c_str(), O_RDWR | O_NOFOLLOW);
        assert(fd >= 0);
        std::array<unsigned char, 362> original{}, modern{};
        assert(pread(fd, original.data(), original.size(), 0) ==
            (ssize_t)original.size());
        modern = original;
        modern[306] = 1; modern[314] = 2; modern[322] = 3;
        assert(SHA256(modern.data(), 330, modern.data() + 330));
        assert(pwrite(fd, modern.data(), modern.size(), 0) ==
            (ssize_t)modern.size() && fsync(fd) == 0);
        auto saved_lifetime = consumer.consumer_handle_lifetime;
        assert(consumer.consumer_program_valid && consumer.consumer_process_fd == -1);
        for (int missing = 0; missing != 4; ++missing) {
            consumer.consumer_program_valid = missing != 0;
            consumer.consumer_process_fd = missing == 1 ? -1 : dup(fd);
            std::copy(modern.begin() + 306, modern.begin() + 330,
                consumer.consumer_handle_lifetime.begin());
            consumer.consumer_replay_registration_pending.store(missing == 2);
            if (missing == 3) consumer.consumer_handle_lifetime[0] ^= 1;
            job blocked(NOTIFY_ELFWRITE, &consumer);
            auto &ne = blocked.notify_elfwrite_get();
            ne.path = strdup(accepted_file.d_name);
            ne.pathlen = strlen(accepted_file.d_name);
            ne.dir = &inbound; ne.nosha = true;
            assert(ne.path != nullptr);
            assert(!blocked.send_elf() && errno == EAGAIN);
            char byte;
            assert(recv(consumer_sockets[1], &byte, 1, MSG_DONTWAIT) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK));
            if (consumer.consumer_process_fd >= 0)
                assert(close(consumer.consumer_process_fd) == 0);
        }
        consumer.consumer_program_valid = true;
        consumer.consumer_process_fd = -1;
        consumer.consumer_handle_lifetime = saved_lifetime;
        consumer.consumer_replay_registration_pending.store(false);
        assert(pwrite(fd, original.data(), original.size(), 0) ==
            (ssize_t)original.size() && fsync(fd) == 0 && close(fd) == 0);
    }
    auto receipt_phase = [&](uint64_t delivery_id) {
        std::vector<durable_consumer_receipt_state> receipts;
        assert(inbound.list_consumer_receipts(receipts));
        for (const auto &receipt : receipts)
            if (receipt.record.ingress.delivery_id == delivery_id) {
                assert(receipt.record.consumer_session == consumer.session_id);
                return receipt.phase;
            }
        assert(false);
        return consumer_receipt_phase::pending;
    };
    auto rename_receipt_phase = [&](uint64_t delivery_id, char from,
        char to) {
        int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
        assert(scanfd >= 0);
        DIR *scan = fdopendir(scanfd);
        assert(scan != nullptr);
        char delivery_hex[17];
        assert(std::snprintf(delivery_hex, sizeof(delivery_hex),
            "%016jx", (uintmax_t)delivery_id) == 16);
        std::string original;
        while (dirent *entry = readdir(scan))
            if (strncmp(entry->d_name, ".consumer.", 10) == 0 &&
                strlen(entry->d_name) == 94 &&
                strncmp(entry->d_name + 43, delivery_hex, 16) == 0 &&
                entry->d_name[93] == from) {
                assert(original.empty());
                original = entry->d_name;
            }
        assert(closedir(scan) == 0 && !original.empty());
        std::string replacement = original;
        replacement[93] = to;
        assert(renameat(inbound.dirfd, original.c_str(), inbound.dirfd,
            replacement.c_str()) == 0 && fsync(inbound.dirfd) == 0);
    };
    assert(receipt_phase(99) == consumer_receipt_phase::pending);
    {
        int writer_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, writer_sockets) == 0);
        dtd_initmsg_t writer_hello{};
        writer_hello.kind = DTRACED_KIND_CONSUMER;
        writer_hello.subs = DTD_SUB_READDATA;
        writer_hello.session_id[0] = 0x79;
        client_fd writer(kq, writer_sockets[0], writer_hello);
        hypertrace_vm_envelope target{};
        target.magic = HYPERTRACE_TARGET_MAGIC;
        target.version = HYPERTRACE_ENVELOPE_VERSION;
        target.vmid = 9;
        target.epoch = 43;
        const char derived_elf[] = "\177ELFderived";
        std::vector<unsigned char> derived_payload(
            HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + sizeof(derived_elf));
        hypertrace_envelope_encode(derived_payload.data(), &target);
        memcpy(derived_payload.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
            derived_elf, sizeof(derived_elf));
        dtraced_derived_parent_t parent{};
        parent.delivery_id = 99;
        parent.consumer_session[0] = 0x76;
        parent.vmid = 7;
        parent.epoch = 42;
        parent.program_id[0] = 0xaa;
        parent.source_id[0] = 0xbb;
        dtraced_hdr_t derived{};
        derived.msg_type = DTRACED_MSG_ELF;
        derived.elf.len = derived_payload.size();
        derived.elf.source_id[0] = 0xbb;
        strcpy(derived.elf.location, "outbound");
        assert(dtraced_derived_parent_to_header(&derived, &parent) == 0);
        assert(dtraced_derived_program_id(&parent, derived_payload.data(),
            derived_payload.size(), derived.elf.program_id) == 0);
        auto publish_derived = [&] {
            client_request request(host, derived, derived_payload.data(),
                derived_payload.size(), &writer);
            return request.handle();
        };
        assert(publish_derived());
        assert(publish_derived()); /* Exact retry uses the same spool. */
        /* The result is durable while HCR1 is still pending. Losing the
         * ACK socket must reconcile it in this daemon, without restart. */
        {
            int lost_sockets[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, lost_sockets) == 0);
            client_fd lost(kq, lost_sockets[0], consumer_hello);
            /* Model a previously accepted HPI1 program registration. */
            lost.consumer_program_valid = true;
            lost.consumer_program_digest = announced_program;
            assert(lost.enable_write(&lost));
            assert(lost.peer_uid == consumer.peer_uid &&
                lost.peer_pid == consumer.peer_pid);
            job lost_ack(NOTIFY_ELFWRITE, &lost);
            auto &ne = lost_ack.notify_elfwrite_get();
            ne.path = strdup(accepted_file.d_name);
            ne.pathlen = strlen(accepted_file.d_name);
            ne.dir = &inbound;
            ne.nosha = true;
            assert(ne.path != nullptr);
            assert(shutdown(lost_sockets[1], SHUT_WR) == 0);
            assert(!lost_ack.send_elf() && errno == ECONNRESET);
            assert(receipt_phase(99) == consumer_receipt_phase::derived);
            unsigned char frame_wire[DTRACED_MSGHDRSIZE];
            dtraced_hdr_t frame{};
            assert(recv(lost_sockets[1], frame_wire, sizeof(frame_wire),
                MSG_WAITALL) == DTRACED_MSGHDRSIZE &&
                dtraced_wire_decode_header(&frame, frame_wire) == 0 &&
                frame.elf.delivery_id == 99);
            std::vector<unsigned char> received(payload.size());
            assert(recv(lost_sockets[1], received.data(), received.size(),
                MSG_WAITALL) == (ssize_t)received.size() &&
                received == payload);
            assert(close(lost_sockets[1]) == 0);
            /* Return the fixture to the pending state for startup and
             * malformed-claim recovery cases below. */
            rename_receipt_phase(99, 'd', 'p');
        }
        /* An explicit consumer failure cannot certify processing, but
         * the already durable derived result still resolves HCR1. */
        {
            int failed_sockets[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, failed_sockets) == 0);
            client_fd failed(kq, failed_sockets[0], consumer_hello);
            /* Model a previously accepted HPI1 program registration. */
            failed.consumer_program_valid = true;
            failed.consumer_program_digest = announced_program;
            assert(failed.enable_write(&failed));
            job failed_ack(NOTIFY_ELFWRITE, &failed);
            auto &ne = failed_ack.notify_elfwrite_get();
            ne.path = strdup(accepted_file.d_name);
            ne.pathlen = strlen(accepted_file.d_name);
            ne.dir = &inbound;
            ne.nosha = true;
            assert(ne.path != nullptr);
            dtraced_consumer_ack_t ack{};
            unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
            ack.delivery_id = 99;
            ack.program_id[0] = 0xaa;
            ack.source_id[0] = 0xbb;
            ack.vmid = 7;
            ack.epoch = 42;
            ack.outcome = DTRACED_CONSUMER_ACK_FAILURE;
            dtraced_wire_encode_consumer_ack(ack_wire, &ack);
            assert(write(failed_sockets[1], ack_wire,
                sizeof(ack_wire)) == (ssize_t)sizeof(ack_wire));
            assert(!failed_ack.send_elf() && errno == EPROTO);
            assert(receipt_phase(99) == consumer_receipt_phase::derived);
            assert(close(failed_sockets[1]) == 0);
            rename_receipt_phase(99, 'd', 'p');
        }
        /* With no derived claim, a lost ACK must leave the recipient
         * pending for a same-session replay. */
        {
            int lost_sockets[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, lost_sockets) == 0);
            client_fd lost(kq, lost_sockets[0], consumer_hello);
            /* Model a previously accepted HPI1 program registration. */
            lost.consumer_program_valid = true;
            lost.consumer_program_digest = announced_program;
            assert(lost.enable_write(&lost));
            job lost_ack(NOTIFY_ELFWRITE, &lost);
            auto &ne = lost_ack.notify_elfwrite_get();
            ne.path = strdup(file.d_name);
            ne.pathlen = strlen(file.d_name);
            ne.dir = &inbound;
            ne.nosha = true;
            assert(ne.path != nullptr);
            assert(shutdown(lost_sockets[1], SHUT_WR) == 0);
            assert(!lost_ack.send_elf() && errno == ECONNRESET);
            assert(receipt_phase(100) == consumer_receipt_phase::pending);
            assert(close(lost_sockets[1]) == 0);
        }
        std::atomic<bool> retry_entered{false}, retry_done{false};
        bool retry_ok = false;
        std::thread retry;
        {
            consumer_outcome_lock held(inbound.dirfd);
            assert(held.held());
            retry = std::thread([&] {
                retry_entered.store(true);
                retry_ok = publish_derived();
                retry_done.store(true);
            });
            while (!retry_entered.load())
                std::this_thread::yield();
            usleep(10000);
            assert(!retry_done.load());
        }
        retry.join();
        assert(retry_ok);
        std::vector<durable_derived_claim> claims;
        assert(outbound.list_derived_claims(claims) && claims.size() == 1);
        assert(claims[0].target_vmid == 9 && claims[0].target_epoch == 43);
        uint8_t first_derived_id[16];
        memcpy(first_derived_id, derived.elf.program_id, 16);
        target.epoch++;
        hypertrace_envelope_encode(derived_payload.data(), &target);
        assert(dtraced_derived_program_id(&parent, derived_payload.data(),
            derived_payload.size(), derived.elf.program_id) == 0);
        assert(!publish_derived() && errno == EPROTO);
        target.epoch--;
        hypertrace_envelope_encode(derived_payload.data(), &target);
        memcpy(derived.elf.program_id, first_derived_id, 16);
        derived_payload.back() ^= 1;
        assert(dtraced_derived_program_id(&parent, derived_payload.data(),
            derived_payload.size(), derived.elf.program_id) == 0);
        assert(!publish_derived() && errno == EPROTO);
        uint8_t rejected_digest[32];
        assert(!outbound.hash_identified_data(derived.elf.program_id,
            derived.elf.source_id, rejected_digest, false, true) &&
            errno == ENOENT);
        derived_payload.back() ^= 1;
        memcpy(derived.elf.program_id, first_derived_id, 16);
        uint8_t actual[32], expected[32], actual_bare[32];
        assert(outbound.hash_identified_data(derived.elf.program_id,
            derived.elf.source_id, actual, false, true, actual_bare));
        assert(SHA256(derived_payload.data(), derived_payload.size(),
            expected) != nullptr && memcmp(actual, expected, 32) == 0);
        assert(SHA256(derived_payload.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
            derived_payload.size() - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
            expected) != nullptr && memcmp(actual_bare, expected, 32) == 0);
        dir restarted(path, &process_inbound);
        std::vector<durable_consumer_receipt_state> audit_receipts;
        std::vector<durable_delivery_state> audit_ingress;
        assert(restarted.list_consumer_receipts(audit_receipts));
        assert(restarted.list_deliveries(audit_ingress));
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress));
        auto contradictory_receipts = audit_receipts;
        for (auto &receipt : contradictory_receipts)
            if (receipt.record.ingress.delivery_id == 99)
                receipt.phase = consumer_receipt_phase::no_derived;
        assert(!restarted.audit_derived_claims(outbound, claims,
            contradictory_receipts, audit_ingress) && errno == EPROTO);
        for (auto &receipt : contradictory_receipts)
            if (receipt.record.ingress.delivery_id == 99)
                receipt.phase = consumer_receipt_phase::derived;
        assert(!restarted.audit_derived_claims(outbound, {},
            contradictory_receipts, audit_ingress) && errno == EPROTO);
        assert(restarted.audit_derived_claims(outbound, claims,
            contradictory_receipts, audit_ingress));
        auto duplicate_claims = claims;
        duplicate_claims.push_back(claims[0]);
        assert(!restarted.audit_derived_claims(outbound, duplicate_claims,
            audit_receipts, audit_ingress) && errno == EPROTO);
        auto wrong_bare_claims = claims;
        wrong_bare_claims[0].bare_elf_digest[0] ^= 1;
        assert(!restarted.audit_derived_claims(outbound, wrong_bare_claims,
            audit_receipts, audit_ingress) && errno == EPROTO);
        assert(!restarted.audit_derived_claims(outbound, claims, {},
            audit_ingress) && errno == EPROTO);
        durable_consumer_receipt_state linked{};
        char derived_name[70];
        static const char hex[] = "0123456789abcdef";
        memcpy(derived_name, "elf.", 4);
        for (unsigned i = 0; i < 16; i++) {
            derived_name[4 + i * 2] =
                hex[derived.elf.program_id[i] >> 4];
            derived_name[5 + i * 2] =
                hex[derived.elf.program_id[i] & 15];
            derived_name[37 + i * 2] =
                hex[derived.elf.source_id[i] >> 4];
            derived_name[38 + i * 2] =
                hex[derived.elf.source_id[i] & 15];
        }
        derived_name[36] = '.';
        derived_name[69] = '\0';
        assert(unlinkat(outbound.dirfd, derived_name, 0) == 0);
        assert(fsync(outbound.dirfd) == 0);
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress)); /* Claim outlives failed spool. */
        auto unproven_derived = audit_receipts;
        for (auto &receipt : unproven_derived)
            if (receipt.record.ingress.delivery_id == 99)
                receipt.phase = consumer_receipt_phase::derived;
        assert(!restarted.audit_derived_claims(outbound, claims,
            unproven_derived, audit_ingress) && errno == EPROTO);
        durable_consumer_receipt_state missing_proof{};
        rename_receipt_phase(99, 'p', 'd');
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id,
            missing_proof) == -1 &&
            errno == EPROTO);
        rename_receipt_phase(99, 'd', 'p');
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress, true));
        assert(receipt_phase(99) == consumer_receipt_phase::pending);
        /* The HDU2 claim alone is not a completed result. A lost ACK at
         * this point must still permit exact-session replay. */
        {
            int lost_sockets[2];
            assert(socketpair(AF_UNIX, SOCK_STREAM, 0, lost_sockets) == 0);
            client_fd lost(kq, lost_sockets[0], consumer_hello);
            /* Model a previously accepted HPI1 program registration. */
            lost.consumer_program_valid = true;
            lost.consumer_program_digest = announced_program;
            assert(lost.enable_write(&lost));
            job lost_ack(NOTIFY_ELFWRITE, &lost);
            auto &ne = lost_ack.notify_elfwrite_get();
            ne.path = strdup(accepted_file.d_name);
            ne.pathlen = strlen(accepted_file.d_name);
            ne.dir = &inbound;
            ne.nosha = true;
            assert(ne.path != nullptr);
            assert(shutdown(lost_sockets[1], SHUT_WR) == 0);
            assert(!lost_ack.send_elf() && errno == ECONNRESET);
            assert(receipt_phase(99) == consumer_receipt_phase::pending);
            assert(close(lost_sockets[1]) == 0);
        }
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 0 &&
            linked.record.ingress.delivery_id == 0);
        assert(publish_derived()); /* Exact retry completes publication. */
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 1);
        assert(linked.record.ingress.delivery_id == 99 &&
            linked.record.consumer_session[0] == 0x76);
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress, true));
        assert(receipt_phase(99) == consumer_receipt_phase::derived);
        /* Restore the simulated pre-ACK disk phase for the live ACK path
         * below; this test explores two crash timelines from one fixture. */
        rename_receipt_phase(99, 'd', 'p');
        assert(receipt_phase(99) == consumer_receipt_phase::pending);
        durable_delivery delivered{};
        delivered.session_id[0] = 0x44;
        delivered.delivery_id = 301;
        delivered.vmid = target.vmid;
        delivered.epoch = target.epoch;
        memcpy(delivered.program_id.data(), derived.elf.program_id, 16);
        memcpy(delivered.source_id.data(), derived.elf.source_id, 16);
        delivered.peer_uid = (uint32_t)writer.peer_uid;
        delivered.peer_pid = (uint32_t)writer.peer_pid;
        delivered.scope = 0;
        delivered.journal_version = 4;
        assert(SHA256(derived_payload.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
            derived_payload.size() - HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
            delivered.payload_digest.data()) != nullptr);
        assert(claims[0].bare_elf_digest == delivered.payload_digest);
        assert(outbound.record_delivery(delivered, delivery_phase::pending,
            true));
        assert(outbound.record_delivery(delivered, delivery_phase::accepted));
        int spool_fd = openat(outbound.dirfd, derived_name,
            O_RDWR | O_NOFOLLOW);
        assert(spool_fd >= 0);
        unsigned char original_spool_byte;
        off_t spool_offset = HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 5;
        assert(pread(spool_fd, &original_spool_byte, 1, spool_offset) == 1);
        unsigned char corrupted_spool_byte = original_spool_byte ^ 1;
        assert(pwrite(spool_fd, &corrupted_spool_byte, 1, spool_offset) == 1);
        assert(fsync(spool_fd) == 0);
        assert(!publish_derived() && errno == EPROTO);
        assert(pwrite(spool_fd, &original_spool_byte, 1, spool_offset) == 1);
        assert(fsync(spool_fd) == 0 && close(spool_fd) == 0);
        assert(unlinkat(outbound.dirfd, derived_name, 0) == 0);
        assert(fsync(outbound.dirfd) == 0);
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress));
        assert(restarted.audit_derived_claims(outbound, claims,
            unproven_derived, audit_ingress));
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 1);
        assert(linked.record.ingress.delivery_id == 99);
        durable_delivery wrong_source = delivered;
        wrong_source.session_id[0] = 0x46;
        wrong_source.delivery_id = 303;
        wrong_source.source_id[0] ^= 1;
        assert(outbound.record_delivery(wrong_source,
            delivery_phase::pending, true));
        assert(outbound.record_delivery(wrong_source,
            delivery_phase::accepted));
        assert(!restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress) && errno == EPROTO);
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == -1 &&
            errno == EPROTO);
        std::string wrong_source_name = ".delivery.";
        for (uint8_t byte : wrong_source.session_id) {
            wrong_source_name += hex[byte >> 4];
            wrong_source_name += hex[byte & 15];
        }
        char wrong_source_suffix[32];
        assert(std::snprintf(wrong_source_suffix,
            sizeof(wrong_source_suffix), ".%016jx.a",
            (uintmax_t)wrong_source.delivery_id) > 0);
        wrong_source_name += wrong_source_suffix;
        assert(unlinkat(outbound.dirfd, wrong_source_name.c_str(), 0) == 0);
        assert(fsync(outbound.dirfd) == 0);
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress));
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 1);
        durable_delivery conflicting_delivery = delivered;
        conflicting_delivery.session_id[0] = 0x45;
        conflicting_delivery.delivery_id = 302;
        conflicting_delivery.payload_digest[0] ^= 1;
        assert(outbound.record_delivery(conflicting_delivery,
            delivery_phase::pending, true));
        assert(outbound.record_delivery(conflicting_delivery,
            delivery_phase::accepted));
        assert(!restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress) && errno == EPROTO);
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == -1 &&
            errno == EPROTO);
        bool recreated_derived = false;
        assert(outbound.write_identified_data(derived_payload.data(),
            derived_payload.size(), derived.elf.program_id,
            &recreated_derived, derived.elf.source_id) && recreated_derived);
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == -1 &&
            errno == EPROTO); /* A retained spool cannot hide bad receipts. */
        uint8_t orphan_id[16] = { 0xee };
        bool orphan_derived = false;
        assert(outbound.write_identified_data(derived_payload.data(),
            derived_payload.size(), orphan_id, &orphan_derived,
            derived.elf.source_id) && orphan_derived);
        assert(restarted.resolve_derived_outbound(outbound, orphan_id,
            derived.elf.source_id, linked) == -1 && errno == EPROTO);
        writer.peer_pid++;
        assert(!publish_derived() && errno == EPERM);
        writer.peer_pid--;
        derived.installed.name[0] ^= 1;
        dtraced_derived_parent_t wrong_session{};
        assert(dtraced_derived_parent_from_header(&wrong_session,
            &derived) == 0);
        assert(dtraced_derived_program_id(&wrong_session,
            derived_payload.data(), derived_payload.size(),
            derived.elf.program_id) == 0);
        assert(!publish_derived() && errno == EPERM);
        derived.installed.name[0] ^= 1;
        assert(dtraced_derived_program_id(&parent,
            derived_payload.data(), derived_payload.size(),
            derived.elf.program_id) == 0);
        derived.installed.name[17] = 1;
        assert(!publish_derived() && errno == EPROTO);
        derived.installed.name[17] = 0;
        derived.installed.program_id[0] ^= 1;
        assert(!publish_derived() && errno == EPROTO);
        derived.installed.program_id[0] ^= 1;
        derived.elf.program_id[0] ^= 1;
        assert(!publish_derived() && errno == EPROTO);
        memcpy(derived.elf.program_id, first_derived_id, 16);
        int claims_fd = openat(outbound.dirfd, ".",
            O_RDONLY | O_DIRECTORY);
        assert(claims_fd >= 0);
        DIR *claims_scan = fdopendir(claims_fd);
        assert(claims_scan != nullptr);
        std::string claim_name;
        while (dirent *entry = readdir(claims_scan))
            if (strncmp(entry->d_name, ".derived.", 9) == 0) {
                claim_name = entry->d_name;
                break;
            }
        assert(closedir(claims_scan) == 0 && !claim_name.empty());
        int claim_fd = openat(outbound.dirfd, claim_name.c_str(),
            O_RDWR | O_NOFOLLOW);
        assert(claim_fd >= 0);
        unsigned char original_byte;
        assert(pread(claim_fd, &original_byte, 1, 96) == 1);
        unsigned char corrupted_byte = original_byte ^ 1;
        assert(pwrite(claim_fd, &corrupted_byte, 1, 96) == 1);
        assert(fsync(claim_fd) == 0);
        claims.clear();
        assert(!outbound.list_derived_claims(claims) && errno == EPROTO);
        assert(pwrite(claim_fd, &original_byte, 1, 96) == 1);
        assert(fsync(claim_fd) == 0 && close(claim_fd) == 0);
        assert(outbound.list_derived_claims(claims) && claims.size() == 1);
        std::string conflicting_name = ".delivery.";
        for (uint8_t byte : conflicting_delivery.session_id) {
            conflicting_name += hex[byte >> 4];
            conflicting_name += hex[byte & 15];
        }
        char conflicting_suffix[32];
        assert(std::snprintf(conflicting_suffix,
            sizeof(conflicting_suffix), ".%016jx.a",
            (uintmax_t)conflicting_delivery.delivery_id) > 0);
        conflicting_name += conflicting_suffix;
        assert(unlinkat(outbound.dirfd, conflicting_name.c_str(), 0) == 0 &&
            fsync(outbound.dirfd) == 0);
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 1);
        assert(outbound.record_delivery(delivered, delivery_phase::installed));
        assert(outbound.record_delivery(delivered, delivery_phase::terminal));
        assert(unlinkat(outbound.dirfd, derived_name, 0) == 0);
        assert(fsync(outbound.dirfd) == 0);
        assert(restarted.audit_derived_claims(outbound, claims,
            audit_receipts, audit_ingress));
        assert(restarted.resolve_derived_outbound(outbound,
            derived.elf.program_id, derived.elf.source_id, linked) == 1);
        assert(publish_derived()); /* No spool resurrection after uninstall. */
        assert(faccessat(outbound.dirfd, derived_name, F_OK, 0) == -1 &&
            errno == ENOENT);
        close(writer_sockets[1]);
    }
    delete host.joblist.front();
    host.joblist.clear();
    {
        job queued(NOTIFY_ELFWRITE, &consumer);
        auto &ne = queued.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr);
        bool sent = false;
        std::thread sender([&] { sent = queued.send_elf(); });
        unsigned char frame_wire[DTRACED_MSGHDRSIZE];
        dtraced_hdr_t frame{};
        assert(recv(consumer_sockets[1], frame_wire, sizeof(frame_wire),
            MSG_WAITALL) == DTRACED_MSGHDRSIZE);
        assert(dtraced_wire_decode_header(&frame, frame_wire) == 0);
        assert(frame.msg_type == DTRACED_MSG_ELF &&
            frame.elf.len == payload.size() &&
            frame.elf.delivery_id == 99 && frame.elf.vmid == 7 &&
            frame.elf.epoch == 42 && frame.elf.program_id[0] == 0xaa &&
            frame.elf.source_id[0] == 0xbb &&
            frame.installed.delivery_id == frame.elf.delivery_id &&
            frame.installed.vmid == frame.elf.vmid &&
            frame.installed.epoch == frame.elf.epoch &&
            frame.installed.program_id[0] == frame.elf.program_id[0] &&
            frame.installed.source_id[0] == frame.elf.source_id[0] &&
            memcmp(frame.installed.name, pending.session_id.data(), 16) == 0);
        std::vector<unsigned char> forwarded(payload.size());
        assert(recv(consumer_sockets[1], forwarded.data(), forwarded.size(),
            MSG_WAITALL) == (ssize_t)forwarded.size());
        assert(forwarded == payload);
        uint8_t source_id[16] = {0xbb};
        auto can_publish = outbound.lock_live_source(source_id, 7, 42);
        assert(can_publish && can_publish->valid());
        can_publish.reset();
        host.revocationmtx.lock();
        host.revocationmtx.unlock();
        {
            consumer_outcome_lock held(inbound.dirfd);
            assert(held.held());
            acknowledge(DTRACED_CONSUMER_ACK_NO_DERIVED);
            usleep(10000);
            assert(receipt_phase(99) == consumer_receipt_phase::pending);
        }
        sender.join();
        assert(sent);
        assert(receipt_phase(99) == consumer_receipt_phase::derived);
        std::vector<durable_consumer_receipt_state> receipts;
        assert(inbound.list_consumer_receipts(receipts));
        bool checked = false;
        for (auto receipt : receipts) {
            if (receipt.record.ingress.delivery_id != 99)
                continue;
            assert(inbound.record_consumer_receipt(receipt.record,
                consumer_receipt_phase::pending) ==
                (int)consumer_receipt_phase::derived);
            receipt.record.consumer_uid ^= 1;
            assert(inbound.record_consumer_receipt(receipt.record,
                consumer_receipt_phase::pending) == -1 && errno == EPROTO);
            checked = true;
        }
        assert(checked);
    }
    /* Model a crash after the derived result was durably delivered but
     * before its HCR1 ACK transition. The terminal outbound receipt proves
     * that startup may complete this exact pending consumer result. */
    {
        rename_receipt_phase(99, 'd', 'p');
        assert(receipt_phase(99) == consumer_receipt_phase::pending);
        std::vector<durable_consumer_receipt_state> receipts;
        std::vector<durable_delivery_state> ingresses;
        std::vector<durable_derived_claim> claims;
        assert(inbound.list_consumer_receipts(receipts) &&
            inbound.list_deliveries(ingresses) &&
            outbound.list_derived_claims(claims));
        assert(inbound.audit_derived_claims(outbound, claims,
            receipts, ingresses, true));
        assert(receipt_phase(99) == consumer_receipt_phase::derived);
        receipts.clear();
        assert(inbound.list_consumer_receipts(receipts) &&
            inbound.audit_derived_claims(outbound, claims,
            receipts, ingresses, true)); /* Idempotent restart. */
    }
    {
        job forged(NOTIFY_ELFWRITE, &consumer);
        auto &ne = forged.notify_elfwrite_get();
        ne.path = strdup(file.d_name);
        ne.pathlen = strlen(file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr);
        dtraced_consumer_ack_t ack{};
        unsigned char ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
        ack.delivery_id = 100;
        ack.program_id[0] = 0xcc;
        ack.source_id[0] = 0xdd;
        ack.vmid = 7;
        ack.epoch = 42;
        ack.outcome = DTRACED_CONSUMER_ACK_DERIVED;
        dtraced_wire_encode_consumer_ack(ack_wire, &ack);
        assert(write(consumer_sockets[1], ack_wire, sizeof(ack_wire)) ==
            (ssize_t)sizeof(ack_wire));
        assert(!forged.send_elf() && errno == EPROTO);
        unsigned char frame_wire[DTRACED_MSGHDRSIZE];
        dtraced_hdr_t frame{};
        assert(recv(consumer_sockets[1], frame_wire, sizeof(frame_wire),
            MSG_WAITALL) == DTRACED_MSGHDRSIZE &&
            dtraced_wire_decode_header(&frame, frame_wire) == 0 &&
            frame.elf.delivery_id == 100);
        std::vector<unsigned char> forwarded(payload.size());
        assert(recv(consumer_sockets[1], forwarded.data(), forwarded.size(),
            MSG_WAITALL) == (ssize_t)forwarded.size() &&
            forwarded == payload);
        assert(receipt_phase(100) == consumer_receipt_phase::pending);
    }
    /* An interrupted watcher may revisit an accepted spool after HCR1 was
     * fsynced. A different consumer session must not run that upload again. */
    {
        int changed_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, changed_sockets) == 0);
        state changed_host{};
        state_attestation_test::set_control(changed_host);
        dir changed_inbound(path, &process_inbound);
        changed_host.inbounddir = &changed_inbound;
        changed_host.outbounddir = &outbound;
        changed_inbound.state = &changed_host;
        dtd_initmsg_t changed_hello = consumer_hello;
        changed_hello.session_id[0]++;
        client_fd changed(kq, changed_sockets[0], changed_hello);
        /* Model a previously accepted HPI1 program registration. */
        changed.consumer_program_valid = true;
        changed.consumer_program_digest = announced_program;
        changed_host.sockfds.insert(&changed);
        std::vector<durable_consumer_receipt_state> before, after;
        assert(changed_inbound.list_consumer_receipts(before));
        assert(process_inbound(changed_inbound, &file) &&
            changed_inbound.memorized(file.d_name) &&
            changed_host.joblist.empty());
        assert(changed_inbound.list_consumer_receipts(after) &&
            after.size() == before.size());
        changed_host.sockfds.clear();
        close(changed_sockets[1]);
    }
    {
        int replay_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, replay_sockets) == 0);
        state replay_host{};
        state_attestation_test::set_control(replay_host);
        dir replay_inbound(path, &process_inbound);
        replay_host.inbounddir = &replay_inbound;
        replay_host.outbounddir = &outbound;
        replay_inbound.state = &replay_host;
        assert(replay_inbound.populate_existing());
        int changed_birth_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
            changed_birth_sockets) == 0);
        dtd_initmsg_t changed_birth_hello = consumer_hello;
        size_t birth_last = strlen(changed_birth_hello.ident) - 1;
        changed_birth_hello.ident[birth_last] = '3';
        client_fd changed_birth(kq, changed_birth_sockets[0],
            changed_birth_hello);
        /* Model a previously accepted HPI1 program registration. */
        changed_birth.consumer_program_valid = true;
        changed_birth.consumer_program_digest = announced_program;
        assert(changed_birth.consumer_birth_valid);
        assert(replay_inbound.queue_recovered_consumer(&changed_birth) == -1 &&
            errno == EBUSY && replay_host.joblist.empty());
        close(changed_birth_sockets[1]);
        test_client_fd replay(kq, replay_sockets[0], consumer_hello);
        /* Model a previously accepted HPI1 program registration. */
        replay.consumer_program_valid = true;
        replay.consumer_program_digest = announced_program;
        assert(replay.enable_write(&replay));
        replay.set_kq(-1);
        assert(replay_inbound.queue_recovered_consumer(&replay) == -1 &&
            errno == EBADF && replay_host.joblist.empty());
        replay.set_kq(kq);
        assert(replay_inbound.queue_recovered_consumer(&replay) == 1);
        assert(replay_host.joblist.size() == 1);
        auto *pending = replay_host.joblist.front();
        assert(strcmp(pending->notify_elfwrite_get().path,
            file.d_name) == 0); /* Token 100 is pending; 99 is processed. */
        assert(pending->handoff_vmid == 7 && pending->handoff_epoch == 42 &&
            !pending->handoff_deferred);
        replay_host.retire_handoff_consumers(7, 42);
        assert(replay_host.joblist.empty());
        close(replay_sockets[1]);
    }
    {
        job awaiting(NOTIFY_ELFWRITE, &consumer);
        auto &ne = awaiting.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr);
        std::thread sender([&] { assert(awaiting.send_elf()); });
        unsigned char frame_wire[DTRACED_MSGHDRSIZE];
        dtraced_hdr_t frame{};
        assert(recv(consumer_sockets[1], frame_wire, sizeof(frame_wire),
            MSG_WAITALL) == DTRACED_MSGHDRSIZE);
        assert(dtraced_wire_decode_header(&frame, frame_wire) == 0 &&
            frame.elf.delivery_id == 99);
        std::vector<unsigned char> received(payload.size());
        assert(recv(consumer_sockets[1], received.data(), received.size(),
            MSG_WAITALL) == (ssize_t)received.size() &&
            received == payload);
        int lockfd = openat(outbound.dirfd, ".handoff.lock",
            O_RDWR | O_CLOEXEC);
        assert(lockfd >= 0);
        assert(flock(lockfd, LOCK_EX) == 0);
        assert(flock(lockfd, LOCK_UN) == 0 && close(lockfd) == 0);
        acknowledge(DTRACED_CONSUMER_ACK_DERIVED);
        sender.join();
    }
    {
        job mismatched(NOTIFY_ELFWRITE, &consumer);
        auto &ne = mismatched.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr);
        dtraced_consumer_ack_t ack{};
        unsigned char wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
        ack.delivery_id = 100; /* The accepted journal has delivery 99. */
        ack.program_id[0] = 0xaa;
        ack.source_id[0] = 0xbb;
        ack.vmid = 7;
        ack.epoch = 42;
        ack.outcome = DTRACED_CONSUMER_ACK_NO_DERIVED;
        dtraced_wire_encode_consumer_ack(wire, &ack);
        assert(write(consumer_sockets[1], wire, sizeof(wire)) ==
            (ssize_t)sizeof(wire));
        assert(!mismatched.send_elf() && errno == EPROTO);
        unsigned char frame_wire[DTRACED_MSGHDRSIZE];
        assert(recv(consumer_sockets[1], frame_wire, sizeof(frame_wire),
            MSG_WAITALL) == DTRACED_MSGHDRSIZE);
        std::vector<unsigned char> received(payload.size());
        assert(recv(consumer_sockets[1], received.data(), received.size(),
            MSG_WAITALL) == (ssize_t)received.size() &&
            received == payload);
    }
    {
        int spool = openat(inbound.dirfd, accepted_file.d_name, O_RDWR);
        assert(spool >= 0);
        unsigned char changed = payload.back() ^ 1;
        off_t last = (off_t)payload.size() - 1;
        assert(pwrite(spool, &changed, 1, last) == 1);
        job queued(NOTIFY_ELFWRITE, &consumer);
        auto &ne = queued.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr && !queued.send_elf() && errno == EPROTO);
        unsigned char byte;
        assert(recv(consumer_sockets[1], &byte, 1, MSG_DONTWAIT) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK));
        assert(pwrite(spool, &payload.back(), 1, last) == 1);
        assert(close(spool) == 0);
    }
    assert(send(payload));
    assert(process_inbound(inbound, &accepted_file));
    assert(host.joblist.empty());
    /* Simulate an accepted spool recovered while another source VM is
     * prepared. Its watcher must not create HCR1 or publish a job across
     * that source cut; ABORT must request a scan of the deferred file. */
    durable_handoff watcher_cut{};
    watcher_cut.token[0] = 0x6c;
    watcher_cut.source_session = forwarder.session_id;
    watcher_cut.source_vmid = 8;
    watcher_cut.source_epoch = 43;
    bind_empty_transfer(watcher_cut);
    assert(outbound.prepare_handoff(watcher_cut, false));
    durable_delivery watcher_ingress = pending;
    watcher_ingress.delivery_id = 102;
    watcher_ingress.vmid = 8;
    watcher_ingress.epoch = 43;
    watcher_ingress.program_id[0] = 0xee;
    watcher_ingress.source_id[0] = 0xef;
    auto watcher_payload = payload;
    auto watcher_envelope = envelope;
    watcher_envelope.vmid = 8;
    watcher_envelope.epoch = 43;
    hypertrace_envelope_encode(watcher_payload.data(), &watcher_envelope);
    assert(inbound.record_delivery(watcher_ingress,
        delivery_phase::pending, true));
    assert(inbound.write_identified_data(watcher_payload.data(),
        watcher_payload.size(), watcher_ingress.program_id.data(), nullptr,
        watcher_ingress.source_id.data()));
    assert(inbound.record_delivery(watcher_ingress,
        delivery_phase::accepted));
    dirent watcher_file{};
    strcpy(watcher_file.d_name,
        "elf.ee000000000000000000000000000000.ef000000000000000000000000000000");
    assert(process_inbound(inbound, &watcher_file));
    assert(host.joblist.empty() && !inbound.memorized(watcher_file.d_name));
    std::vector<durable_consumer_receipt_state> watcher_receipts;
    assert(inbound.list_consumer_receipts(watcher_receipts));
    for (const auto &receipt : watcher_receipts)
        assert(receipt.record.ingress.delivery_id != 102);
    assert(outbound.abort_handoff(watcher_cut));
    assert(host.wake_handoff_source(forwarder));
    assert(process_inbound(inbound, &watcher_file));
    assert(host.joblist.size() == 1 && inbound.memorized(watcher_file.d_name));
    assert(host.joblist.front()->handoff_vmid == 8 &&
        host.joblist.front()->handoff_epoch == 43 &&
        !host.joblist.front()->handoff_deferred);
    host.retire_handoff_consumers(8, 43);
    assert(host.joblist.empty());
    host.sockfds.clear();

    /* PREPARE must wait for any current upload's source transaction and
     * reject a later one until ABORT reopens this VM incarnation. */
    durable_handoff cut{};
    cut.token[0] = 0x6a;
    cut.source_session = forwarder.session_id;
    cut.source_vmid = forwarder.vmid;
    cut.source_epoch = forwarder.vm_epoch;
    assert(!outbound.prepare_handoff(cut, false) && errno == EBUSY);
    /* Exercise the consumer's prepared-phase behavior in isolation. The
     * production host refuses this cut until receipts are durable. */
    outbound.state = nullptr;
    assert(outbound.prepare_handoff(cut, false));
    outbound.state = &host;
    dtraced_hdr_t original_header = header;
    header.elf.delivery_id = 108;
    header.elf.program_id[0] = 0xf1;
    header.elf.source_id[0] = 0xf2;
    assert(!send(payload) && errno == EBUSY);
    header = original_header;
    job deferred(NOTIFY_ELFWRITE, &consumer);
    auto &deferred_elf = deferred.notify_elfwrite_get();
    deferred_elf.path = strdup(accepted_file.d_name);
    deferred_elf.pathlen = strlen(accepted_file.d_name);
    deferred_elf.dir = &inbound;
    deferred_elf.nosha = true;
    assert(deferred_elf.path != nullptr);
    assert(!deferred.send_elf() && errno == EBUSY &&
        deferred.handoff_deferred && deferred.handoff_vmid == 7 &&
        deferred.handoff_epoch == 42);
    unsigned char unsent;
    assert(recv(consumer_sockets[1], &unsent, 1, MSG_DONTWAIT) < 0 &&
        (errno == EAGAIN || errno == EWOULDBLOCK));
    /* ABORT cannot pass a worker between its phase check and requeue. */
    std::atomic<bool> phase_entered{false}, phase_release{false};
    std::atomic<bool> abort_started{false}, abort_complete{false};
    std::thread phase_reader([&] {
        assert(outbound.with_source_handoff_phase(7, 42,
            [&](int phase) {
                assert(phase == (int)handoff_phase::prepared);
                phase_entered.store(true);
                while (!phase_release.load())
                    std::this_thread::yield();
            }) == (int)handoff_phase::prepared);
    });
    while (!phase_entered.load())
        std::this_thread::yield();
    std::thread aborter([&] {
        abort_started.store(true);
        assert(outbound.abort_handoff(cut));
        abort_complete.store(true);
    });
    while (!abort_started.load())
        std::this_thread::yield();
    usleep(10000);
    assert(!abort_complete.load());
    phase_release.store(true);
    phase_reader.join();
    aborter.join();
    assert(abort_complete.load());
    acknowledge(DTRACED_CONSUMER_ACK_NO_DERIVED);
    assert(deferred.send_elf() && !deferred.handoff_deferred);
    unsigned char resumed_wire[DTRACED_MSGHDRSIZE];
    dtraced_hdr_t resumed{};
    assert(recv(consumer_sockets[1], resumed_wire, sizeof(resumed_wire),
        MSG_WAITALL) == DTRACED_MSGHDRSIZE &&
        dtraced_wire_decode_header(&resumed, resumed_wire) == 0 &&
        resumed.msg_type == DTRACED_MSG_ELF &&
        resumed.elf.delivery_id == 99 && resumed.elf.vmid == 7 &&
        resumed.elf.epoch == 42 && resumed.elf.program_id[0] == 0xaa &&
        resumed.elf.source_id[0] == 0xbb);
    std::vector<unsigned char> resumed_payload(payload.size());
    assert(recv(consumer_sockets[1], resumed_payload.data(),
        resumed_payload.size(), MSG_WAITALL) ==
        (ssize_t)resumed_payload.size() && resumed_payload == payload);
    auto abandoned = std::make_unique<job>(NOTIFY_ELFWRITE, &consumer);
    abandoned->handoff_deferred = true;
    abandoned->handoff_vmid = 7;
    abandoned->handoff_epoch = 42;
    host.joblist.push_back(abandoned.get());
    (void)abandoned.release();
    host.retire_handoff_consumers(8, 42);
    assert(host.joblist.size() == 1);
    host.retire_handoff_consumers(7, 42);
    assert(host.joblist.empty());
    assert(send(payload));

    /* A host KILL lives in the outbound journal, while the upload receipt
     * lives in inbound. Both admission and receipt status must see it. */
    durable_kill killed{};
    killed.pid = 123;
    killed.vmid = 8;
    killed.epoch = 42;
    killed.source_id[0] = 0xbb;
    assert(outbound.record_kill(killed));
    answer = status();
    assert(answer.phase == 'a' && answer.revoked == 0);
    assert(send(payload));
    killed.vmid = 7;
    killed.epoch = 43;
    assert(outbound.record_kill(killed));
    answer = status();
    assert(answer.phase == 'a' && answer.revoked == 0);
    assert(send(payload));
    killed.epoch = 42;
    assert(outbound.record_kill(killed));
    answer = status();
    assert(answer.phase == 'a' && answer.revoked == 1);
    assert(!send(payload) && errno == ECANCELED);
    {
        dir scanner(path, &process_inbound);
        scanner.state = &host;
        assert(process_inbound(scanner, &accepted_file));
        assert(scanner.memorized(accepted_file.d_name) && host.joblist.empty());
    }
    {
        job queued(NOTIFY_ELFWRITE, &consumer);
        auto &ne = queued.notify_elfwrite_get();
        ne.path = strdup(accepted_file.d_name);
        ne.pathlen = strlen(accepted_file.d_name);
        ne.dir = &inbound;
        ne.nosha = true;
        assert(ne.path != nullptr && queued.send_elf());
        unsigned char byte;
        assert(recv(consumer_sockets[1], &byte, 1, MSG_DONTWAIT) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK));
    }

    /* A KILL before the first upload must not leave a pending receipt. */
    killed.source_id[0] = 0x77;
    assert(outbound.record_kill(killed));
    header.elf.delivery_id = 107;
    header.elf.program_id[0] = 0x77;
    header.elf.source_id[0] = 0x77;
    assert(!send(payload) && errno == ECANCELED);
    records.clear();
    assert(inbound.list_deliveries(records) && records.size() == 3);
    bool watcher_record_found = false;
    for (const auto &record : records)
        if (record.record.delivery_id == 102 && record.record.vmid == 8 &&
            record.record.epoch == 43)
            watcher_record_found = true;
    assert(watcher_record_found);

    /* A different daemon process cannot commit KILL during the guarded
     * inbound acceptance. Once KILL wins, a new acceptance is refused. */
    int start[2], done[2];
    assert(pipe(start) == 0 && pipe(done) == 0);
    durable_kill racing{};
    racing.pid = 123;
    racing.vmid = 7;
    racing.epoch = 42;
    racing.source_id[0] = 0x78;
    pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        close(start[1]); close(done[0]);
        char byte;
        if (read(start[0], &byte, 1) != 1 ||
            write(done[1], &byte, 1) != 1 ||
            !outbound.record_kill(racing) ||
            write(done[1], &byte, 1) != 1)
            _exit(1);
        _exit(0);
    }
    close(start[0]); close(done[1]);
    auto live = outbound.lock_live_source(racing.source_id.data(), 7, 42);
    assert(live && live->valid());
    char byte = 1;
    assert(write(start[1], &byte, 1) == 1);
    assert(read(done[0], &byte, 1) == 1); /* Child is about to publish. */
    struct pollfd blocked{done[0], POLLIN, 0};
    assert(poll(&blocked, 1, 100) == 0);
    live.reset();
    assert(read(done[0], &byte, 1) == 1);
    int child_status;
    assert(waitpid(child, &child_status, 0) == child &&
        WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
    close(start[1]); close(done[0]);
    assert(!outbound.lock_live_source(racing.source_id.data(), 7, 42) &&
        errno == ECANCELED);

    {
        dir recovered(path, nullptr);
        std::vector<durable_consumer_receipt_state> receipts;
        assert(recovered.list_consumer_receipts(receipts));
        bool processed = false;
        for (const auto &receipt : receipts)
            if (receipt.record.ingress.delivery_id == 99 &&
                receipt.record.consumer_session == consumer.session_id &&
                receipt.phase == consumer_receipt_phase::derived)
                processed = true;
        assert(processed);
        int receipt_fd = openat(recovered.dirfd, ".",
            O_RDONLY | O_DIRECTORY);
        assert(receipt_fd >= 0);
        DIR *entries = fdopendir(receipt_fd);
        assert(entries != nullptr);
        std::string receipt_name;
        while (dirent *entry = readdir(entries))
            if (strncmp(entry->d_name, ".consumer.", 10) == 0 &&
                strlen(entry->d_name) == 94 && entry->d_name[93] == 'd') {
                receipt_name = entry->d_name;
                break;
            }
        assert(closedir(entries) == 0 && !receipt_name.empty());
        std::string legacy_name = receipt_name;
        legacy_name[93] = 'c';
        assert(renameat(recovered.dirfd, receipt_name.c_str(),
            recovered.dirfd, legacy_name.c_str()) == 0);
        assert(fsync(recovered.dirfd) == 0 &&
            recovered.list_consumer_receipts(receipts));
        bool legacy_seen = false;
        for (const auto &receipt : receipts)
            if (receipt.record.ingress.delivery_id == 99 &&
                receipt.phase == consumer_receipt_phase::processed)
                legacy_seen = true;
        assert(legacy_seen);
        assert(renameat(recovered.dirfd, legacy_name.c_str(),
            recovered.dirfd, receipt_name.c_str()) == 0 &&
            fsync(recovered.dirfd) == 0);
        receipt_fd = openat(recovered.dirfd, receipt_name.c_str(),
            O_RDWR | O_NOFOLLOW);
        assert(receipt_fd >= 0);
        unsigned char original;
        assert(pread(receipt_fd, &original, 1, 25) == 1);
        unsigned char altered = original ^ 1;
        assert(pwrite(receipt_fd, &altered, 1, 25) == 1);
        assert(fsync(receipt_fd) == 0);
        assert(!recovered.list_consumer_receipts(receipts) && errno == EPROTO);
        assert(pwrite(receipt_fd, &original, 1, 25) == 1);
        assert(fsync(receipt_fd) == 0 && close(receipt_fd) == 0);
        assert(recovered.list_consumer_receipts(receipts));
        std::string fifo_name = receipt_name;
        fifo_name[11] = fifo_name[11] == '0' ? '1' : '0';
        assert(mkfifoat(recovered.dirfd, fifo_name.c_str(), 0600) == 0);
        assert(!recovered.list_consumer_receipts(receipts) && errno == EPROTO);
        assert(unlinkat(recovered.dirfd, fifo_name.c_str(), 0) == 0);
        assert(recovered.list_consumer_receipts(receipts));
    }
    {
        std::vector<durable_consumer_receipt_state> receipts;
        assert(inbound.list_consumer_receipts(receipts));
        bool promoted = false;
        for (const auto &receipt : receipts)
            if (receipt.record.ingress.delivery_id == 99 &&
                receipt.record.consumer_session == consumer.session_id) {
                assert(receipt.phase == consumer_receipt_phase::derived);
                assert(inbound.record_consumer_receipt(receipt.record,
                    consumer_receipt_phase::executed_derived) ==
                    (int)consumer_receipt_phase::executed_derived);
                assert(inbound.record_consumer_receipt(receipt.record,
                    consumer_receipt_phase::derived) ==
                    (int)consumer_receipt_phase::executed_derived);
                promoted = true;
            }
        assert(promoted);
        dir recovered(path, nullptr);
        assert(recovered.list_consumer_receipts(receipts));
        assert(receipt_phase(99) ==
            consumer_receipt_phase::executed_derived);
    }
    /* Recovery must match each receipt to its complete ingress identity
     * even when many records share the same VM, session, and ELF digest. */
    std::vector<durable_delivery_state> indexed_ingress;
    assert(inbound.list_deliveries(indexed_ingress));
    const durable_delivery *base = nullptr;
    for (const auto &entry : indexed_ingress)
        if (entry.record.scope == 3 && entry.record.delivery_id == 99 &&
            entry.phase == delivery_phase::accepted)
            base = &entry.record;
    assert(base != nullptr);
    /* PREPARE may consider an execution-settled upload only while its
     * original, identity-matched ELF spool is still intact. */
    assert(inbound.verify_host_ingress_payload(*base) == 1);
    {
        int fd = openat(inbound.dirfd, accepted_file.d_name,
            O_RDWR | O_NOFOLLOW);
        assert(fd >= 0);
        struct stat sb;
        assert(fstat(fd, &sb) == 0 && sb.st_size > 0);
        unsigned char tail, changed;
        assert(pread(fd, &tail, 1, sb.st_size - 1) == 1);
        changed = tail ^ 1;
        assert(pwrite(fd, &changed, 1, sb.st_size - 1) == 1 &&
            fsync(fd) == 0);
        assert(inbound.verify_host_ingress_payload(*base) == -1 &&
            errno == EPROTO);
        assert(pwrite(fd, &tail, 1, sb.st_size - 1) == 1 &&
            fsync(fd) == 0);
        unsigned char vmid_byte;
        assert(pread(fd, &vmid_byte, 1, 6) == 1);
        changed = vmid_byte ^ 1;
        assert(pwrite(fd, &changed, 1, 6) == 1 && fsync(fd) == 0);
        assert(inbound.verify_host_ingress_payload(*base) == -1 &&
            errno == EPROTO);
        assert(pwrite(fd, &vmid_byte, 1, 6) == 1 && fsync(fd) == 0 &&
            close(fd) == 0);
        assert(inbound.verify_host_ingress_payload(*base) == 1);
    }
    /* A source cut progresses from missing cohort through parsed and
     * execution-settled HCR1, but cannot publish without transfer state. */
    {
        char transfer_in[] = "/tmp/hypertrace-transfer-in.XXXXXX";
        char transfer_out[] = "/tmp/hypertrace-transfer-out.XXXXXX";
        assert(mkdtemp(transfer_in) != nullptr &&
            mkdtemp(transfer_out) != nullptr);
        {
            state transfer_host{};
            state_attestation_test::set_control(transfer_host);
            dir transfer_inbound(transfer_in, &process_inbound);
            dir transfer_outbound(transfer_out, &process_outbound);
            transfer_host.inbounddir = &transfer_inbound;
            transfer_host.outbounddir = &transfer_outbound;
            transfer_inbound.state = &transfer_host;
            transfer_outbound.state = &transfer_host;
            assert(transfer_inbound.queue_recovered_consumer(&consumer) == 0);
            durable_delivery transfer = *base;
            assert(transfer_inbound.write_identified_data(payload.data(),
                payload.size(), transfer.program_id.data(), nullptr,
                transfer.source_id.data()));
            assert(transfer_inbound.record_delivery(transfer,
                delivery_phase::pending, true) &&
                transfer_inbound.record_delivery(transfer,
                delivery_phase::accepted));
            durable_handoff transfer_cut{};
            transfer_cut.token[0] = 0x7d;
            transfer_cut.source_session = forwarder.session_id;
            transfer_cut.source_vmid = transfer.vmid;
            transfer_cut.source_epoch = transfer.epoch;
            assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
                errno == EBUSY);
            durable_consumer_receipt recipient{};
            recipient.ingress = transfer;
            recipient.consumer_session = consumer.session_id;
            recipient.consumer_uid = (uint32_t)consumer.peer_uid;
            recipient.consumer_pid = (uint32_t)consumer.peer_pid;
            std::vector<durable_consumer_receipt> fixed;
            assert(transfer_inbound.consumer_cohort(transfer,
                {recipient}, fixed) == 1);
            assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
                errno == EBUSY);
            assert(transfer_inbound.record_consumer_receipt(recipient,
                consumer_receipt_phase::pending) ==
                (int)consumer_receipt_phase::pending);
            assert(transfer_inbound.record_consumer_program(recipient,
                consumer) == 1);
            assert(transfer_inbound.record_consumer_receipt(recipient,
                consumer_receipt_phase::no_derived) ==
                (int)consumer_receipt_phase::no_derived);
            assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
                errno == EBUSY);
            assert(transfer_inbound.record_consumer_receipt(recipient,
                consumer_receipt_phase::executed_no_derived) ==
                (int)consumer_receipt_phase::executed_no_derived);
            int spool = openat(transfer_inbound.dirfd,
                accepted_file.d_name, O_RDWR | O_NOFOLLOW);
            assert(spool >= 0);
            unsigned char tail, changed;
            assert(pread(spool, &tail, 1, payload.size() - 1) == 1);
            changed = tail ^ 1;
            assert(pwrite(spool, &changed, 1, payload.size() - 1) == 1 &&
                fsync(spool) == 0);
			std::vector<uint8_t> verified_copy;
			assert(transfer_inbound.verify_host_ingress_payload(
			    transfer, &verified_copy) == -1 && errno == EPROTO &&
			    verified_copy.empty());
            assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
                errno == EPROTO);
            assert(pwrite(spool, &tail, 1, payload.size() - 1) == 1 &&
                fsync(spool) == 0 && close(spool) == 0);
			assert(transfer_inbound.verify_host_ingress_payload(
			    transfer, &verified_copy) == 1 &&
			    verified_copy == payload);
			assert(dir::validate_host_ingress_transfer_payload(
			    transfer, verified_copy));
			verified_copy.back() ^= 1;
			assert(!dir::validate_host_ingress_transfer_payload(
			    transfer, verified_copy) && errno == EPROTO);
			verified_copy.back() ^= 1;
			verified_copy[6] ^= 1;
			assert(!dir::validate_host_ingress_transfer_payload(
			    transfer, verified_copy) && errno == EPROTO);
			verified_copy[6] ^= 1;
			durable_delivery wrong_digest = transfer;
			wrong_digest.payload_digest[0] ^= 1;
			assert(!dir::validate_host_ingress_transfer_payload(
			    wrong_digest, verified_copy) && errno == EPROTO);
			std::vector<uint8_t> transfer_frame, decoded_payload;
			assert(dir::encode_host_ingress_transfer_frame(
			    transfer_cut, transfer, verified_copy, transfer_frame));
			assert(dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, transfer_frame,
			    &decoded_payload) && decoded_payload == verified_copy);
			durable_handoff invalid_frame_ticket = transfer_cut;
			invalid_frame_ticket.checkpoint_digest[0] = 1;
			std::vector<uint8_t> rejected_frame;
			assert(!dir::encode_host_ingress_transfer_frame(
			    invalid_frame_ticket, transfer, verified_copy,
			    rejected_frame) && errno == EINVAL && rejected_frame.empty());
			assert(!dir::decode_host_ingress_transfer_frame(
			    invalid_frame_ticket, transfer, transfer_frame,
			    &decoded_payload) && errno == EPROTO && decoded_payload.empty());
			invalid_frame_ticket = transfer_cut;
			invalid_frame_ticket.destination_vmid = 2;
			invalid_frame_ticket.destination_epoch = 1;
			assert(!dir::decode_host_ingress_transfer_frame(
			    invalid_frame_ticket, transfer, transfer_frame) &&
			    errno == EPROTO);
			std::vector<uint8_t> changed_frame = transfer_frame;
			changed_frame.back() ^= 1;
			assert(!dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, changed_frame,
			    &decoded_payload) && errno == EPROTO &&
			    decoded_payload.empty());
			changed_frame = transfer_frame;
			changed_frame[163] ^= 1;
			assert(!dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, changed_frame) &&
			    errno == EPROTO);
			changed_frame = transfer_frame;
			changed_frame[167 + verified_copy.size() - 1] ^= 1;
			assert(SHA256(changed_frame.data(), changed_frame.size() - 32,
			    changed_frame.data() + changed_frame.size() - 32));
			assert(!dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, changed_frame) &&
			    errno == EPROTO);
			changed_frame = transfer_frame;
			changed_frame[20 + 79] ^= 1;
			assert(SHA256(changed_frame.data(), changed_frame.size() - 32,
			    changed_frame.data() + changed_frame.size() - 32));
			assert(!dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, changed_frame) &&
			    errno == EPROTO);
			assert(!dir::decode_host_ingress_transfer_frame(
			    transfer_cut, wrong_digest, transfer_frame) &&
			    errno == EPROTO);
			std::vector<uint8_t> manifest;
			assert(transfer_inbound.host_ingress_transfer_manifest(
			    transfer_cut, manifest) == 1);
			assert(manifest.size() == 50 + 143 + 4 + 159 + 32 &&
			    memcmp(manifest.data(), "HTM1", 4) == 0);
			assert(dir::validate_host_ingress_transfer_manifest(
			    transfer_cut, manifest));
			std::vector<uint8_t> program_manifest, nested_manifest;
			std::vector<host_ingress_program_evidence> source_programs;
			assert(transfer_inbound.host_ingress_program_manifest(
			    transfer_cut, manifest, program_manifest) == 1 &&
			    program_manifest.size() == 12 + manifest.size() + 302 + 32);
			assert(dir::validate_host_ingress_program_manifest(
			    transfer_cut, program_manifest, &nested_manifest,
			    &source_programs) && nested_manifest == manifest &&
			    source_programs.size() == 1 &&
			    source_programs[0].recipient.consumer_session ==
			    consumer.session_id &&
			    source_programs[0].program_digest == announced_program);
			std::vector<uint8_t> drain_manifest, drain_bundle;
			std::vector<std::vector<uint8_t>> drain_frames;
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, drain_manifest, drain_frames, true) == 1 &&
			    dtraced_transfer_wire_build(transfer_cut.token.data(),
			    drain_manifest, drain_frames, drain_bundle));
			durable_handoff drain_cut = transfer_cut;
			memcpy(drain_cut.transfer_digest.data(),
			    drain_bundle.data() + drain_bundle.size() - 32, 32);
			auto attested_drain_step = [&](const durable_handoff &cut,
			    int expected) {
			    dtraced_handoff_request_t request{};
			    request.op = DTRACED_HANDOFF_SOURCE_DRAIN_STEP;
			    memcpy(request.token, cut.token.data(), 16);
			    memcpy(request.digest, cut.transfer_digest.data(), 32);
			    uint8_t wire[DTRACED_HANDOFF_WIRE_SIZE];
			    dtraced_wire_encode_handoff(wire, &request);
			    dtraced_hdr_t header{};
			    header.msg_type = DTRACED_MSG_HANDOFF;
			    client_request step(transfer_host, header,
			        wire, sizeof(wire), &forwarder);
			    if (expected < 0) {
			        assert(!step.handle() && errno == ESTALE);
			        return;
			    }
			    assert(step.handle() && step.drain_step_response() != nullptr &&
			        *step.drain_step_response() == expected);
			};
			assert(transfer_outbound.source_gate_begin(transfer_cut));
			assert(transfer_outbound.source_consumer_drain_receipt(
			    drain_cut, source_programs[0], false) == 0);
			assert(!transfer_outbound.prepare_handoff(drain_cut) &&
			    errno == EBUSY);
			transfer_host.sockfds.insert(&consumer);
			std::thread drain_reply([&] {
			    uint8_t header_wire[DTRACED_MSGHDRSIZE];
			    uint8_t challenge_wire[DTRACED_CONSUMER_DRAIN_WIRE_SIZE];
			    assert(recv(consumer_sockets[1], header_wire,
			        sizeof(header_wire), MSG_WAITALL) ==
			        (ssize_t)sizeof(header_wire));
			    dtraced_hdr_t challenge_header{};
			    assert(dtraced_wire_decode_header(&challenge_header,
			        header_wire) == 0 &&
			        challenge_header.msg_type == DTRACED_MSG_CONSUMER_DRAIN);
			    assert(recv(consumer_sockets[1], challenge_wire,
			        sizeof(challenge_wire), MSG_WAITALL) ==
			        (ssize_t)sizeof(challenge_wire));
			    dtraced_consumer_drain_t challenge{};
			    assert(dtraced_wire_decode_consumer_drain(&challenge,
			        challenge_wire) == 0 &&
			        memcmp(challenge.token, drain_cut.token.data(), 16) == 0 &&
			        memcmp(challenge.program_digest,
			        announced_program.data(), 32) == 0);
			    challenge.result = 1;
			    uint8_t ack[DTRACED_CONSUMER_DRAIN_ACK_WIRE_SIZE];
			    dtraced_wire_encode_consumer_drain_ack(ack, &challenge);
			    assert(write(consumer_sockets[1], ack, sizeof(ack)) ==
			        (ssize_t)sizeof(ack));
			});
			attested_drain_step(drain_cut, 1);
			drain_reply.join();
			transfer_host.sockfds.erase(&consumer);
			attested_drain_step(drain_cut, 0);
			assert(!transfer_outbound.prepare_handoff(drain_cut) &&
			    errno == EOPNOTSUPP);
			assert(transfer_outbound.source_consumer_drain_receipt(
			    drain_cut, source_programs[0], true) == 1);
			{
			    dir restarted(transfer_out, &process_outbound);
			    restarted.state = &transfer_host;
			    transfer_host.outbounddir = &restarted;
			    assert(restarted.source_consumer_drain_receipt(
			        drain_cut, source_programs[0], false) == 1);
			    transfer_host.outbounddir = &transfer_outbound;
			}
			DIR *drain_scan = fdopendir(dup(transfer_outbound.dirfd));
			assert(drain_scan != nullptr);
			std::string drain_name;
			for (dirent *entry; (entry = readdir(drain_scan)) != nullptr;)
			    if (strncmp(entry->d_name, ".drain.", 7) == 0)
			        drain_name = entry->d_name;
			assert(closedir(drain_scan) == 0 && !drain_name.empty());
			int drain_fd = openat(transfer_outbound.dirfd,
			    drain_name.c_str(), O_RDWR | O_NOFOLLOW);
			assert(drain_fd >= 0);
			uint8_t drain_trailer;
			assert(pread(drain_fd, &drain_trailer, 1, 411) == 1);
			uint8_t bad_trailer = drain_trailer ^ 1;
			assert(pwrite(drain_fd, &bad_trailer, 1, 411) == 1 &&
			    fsync(drain_fd) == 0);
			assert(transfer_outbound.source_consumer_drain_receipt(
			    drain_cut, source_programs[0], false) == -1 &&
			    errno == EPROTO);
			assert(!transfer_outbound.prepare_handoff(drain_cut) &&
			    errno == EPROTO);
			assert(pwrite(drain_fd, &drain_trailer, 1, 411) == 1 &&
			    fsync(drain_fd) == 0 && close(drain_fd) == 0);
			assert(transfer_outbound.source_consumer_drain_receipt(
			    drain_cut, source_programs[0], true) == 1);
			assert(!transfer_outbound.prepare_handoff(drain_cut) &&
			    errno == EOPNOTSUPP);
			durable_handoff changed_drain = drain_cut;
			changed_drain.transfer_digest[0] ^= 1;
			attested_drain_step(changed_drain, -1);
			assert(transfer_outbound.source_consumer_drain_receipt(
			    changed_drain, source_programs[0], false) == -1 &&
			    errno == ESTALE);
			auto bad_program_manifest = program_manifest;
			bad_program_manifest.back() ^= 1;
			assert(!dir::validate_host_ingress_program_manifest(
			    transfer_cut, bad_program_manifest, &nested_manifest,
			    &source_programs) && errno == EPROTO &&
			    nested_manifest.empty() && source_programs.empty());
			bad_program_manifest = program_manifest;
			const size_t proof_offset = 12 + manifest.size();
			bad_program_manifest[proof_offset + 190] ^= 1;
			assert(SHA256(bad_program_manifest.data() + proof_offset,
			    270, bad_program_manifest.data() + proof_offset + 270));
			assert(SHA256(bad_program_manifest.data(),
			    bad_program_manifest.size() - 32,
			    bad_program_manifest.data() +
			    bad_program_manifest.size() - 32));
			assert(!dir::validate_host_ingress_program_manifest(
			    transfer_cut, bad_program_manifest, &nested_manifest,
			    &source_programs) && errno == EPROTO &&
			    nested_manifest.empty() && source_programs.empty());
			std::vector<uint8_t> audited_manifest;
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    transfer_cut, audited_manifest) == 1 &&
			    audited_manifest == manifest);
			std::vector<uint8_t> exported;
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, manifest, 0, exported) == 1);
			assert(dir::decode_host_ingress_transfer_frame(
			    transfer_cut, transfer, exported, &decoded_payload) &&
			    decoded_payload == payload);
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, manifest, 1, exported) == -1 &&
			    errno == EINVAL && exported.empty());
			/* A provisional export belongs only to this prepared source
			 * ticket; a second owner of the token cannot read its bytes. */
			transfer_outbound.state = nullptr;
			assert(transfer_outbound.prepare_handoff(transfer_cut, false));
			transfer_outbound.state = &transfer_host;
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    transfer_cut, audited_manifest) == 1 &&
			    audited_manifest == manifest);
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, manifest, 0, exported) == 1);
			durable_handoff foreign_cut = transfer_cut;
			foreign_cut.source_session[0] ^= 1;
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    foreign_cut, audited_manifest) == -1 &&
			    errno == EBUSY && audited_manifest.empty());
			std::vector<uint8_t> bundle_manifest;
			std::vector<std::vector<uint8_t>> bundle_frames;
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    foreign_cut, bundle_manifest, bundle_frames) == -1 &&
			    errno == EBUSY && bundle_manifest.empty() &&
			    bundle_frames.empty());
			durable_handoff competing_cut = transfer_cut;
			competing_cut.token[0] ^= 1;
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    competing_cut, audited_manifest) == -1 &&
			    errno == EBUSY && audited_manifest.empty());
			std::vector<uint8_t> competing_manifest;
			assert(transfer_inbound.host_ingress_transfer_manifest(
			    competing_cut, competing_manifest) == 1);
			assert(transfer_inbound.host_ingress_transfer_frame(
			    competing_cut, competing_manifest, 0, exported) == -1 &&
			    errno == EBUSY && exported.empty());
			assert(transfer_outbound.abort_handoff(transfer_cut));
			assert(transfer_outbound.source_gate_abort(transfer_cut));
			std::vector<uint8_t> changed_manifest = manifest;
			changed_manifest.back() ^= 1;
			assert(!dir::validate_host_ingress_transfer_manifest(
			    transfer_cut, changed_manifest) && errno == EPROTO);
			changed_manifest = manifest;
			changed_manifest[50 + 143 + 4 + 158] = 'n';
			assert(SHA256(changed_manifest.data(),
			    changed_manifest.size() - 32,
			    changed_manifest.data() + changed_manifest.size() - 32));
			assert(!dir::validate_host_ingress_transfer_manifest(
			    transfer_cut, changed_manifest) && errno == EPROTO);
			durable_handoff wrong_ticket = transfer_cut;
			wrong_ticket.token[0] ^= 1;
			assert(!dir::validate_host_ingress_transfer_manifest(
			    wrong_ticket, manifest) && errno == EPROTO);
			durable_delivery second = transfer;
			second.delivery_id = 98;
			second.program_id[0] = 0xab;
			second.source_id[0] = 0xbc;
			assert(transfer_inbound.write_identified_data(payload.data(),
			    payload.size(), second.program_id.data(), nullptr,
			    second.source_id.data()));
			assert(transfer_inbound.record_delivery(second,
			    delivery_phase::pending, true) &&
			    transfer_inbound.record_delivery(second,
			    delivery_phase::accepted));
			durable_consumer_receipt second_recipient = recipient;
			second_recipient.ingress = second;
			fixed.clear();
			assert(transfer_inbound.consumer_cohort(second,
			    {second_recipient}, fixed) == 1);
			assert(transfer_inbound.record_consumer_receipt(
			    second_recipient, consumer_receipt_phase::pending) ==
			    (int)consumer_receipt_phase::pending);
			assert(transfer_inbound.record_consumer_program(
			    second_recipient, consumer) == 1);
			assert(transfer_inbound.record_consumer_receipt(
			    second_recipient, consumer_receipt_phase::no_derived) ==
			    (int)consumer_receipt_phase::no_derived);
			assert(transfer_inbound.record_consumer_receipt(
			    second_recipient,
			    consumer_receipt_phase::executed_no_derived) ==
			    (int)consumer_receipt_phase::executed_no_derived);
			std::vector<uint8_t> both;
			assert(transfer_inbound.host_ingress_transfer_manifest(
			    transfer_cut, both) == 1);
			assert(both.size() == 50 + 2 * (143 + 4 + 159) + 32 &&
			    both[50 + 20] == 98 &&
			    both[50 + 143 + 4 + 159 + 20] == 99);
			assert(transfer_inbound.host_ingress_program_manifest(
			    transfer_cut, manifest, program_manifest) == -1 &&
			    errno == ESTALE && program_manifest.empty());
			assert(transfer_inbound.host_ingress_program_manifest(
			    transfer_cut, both, program_manifest) == 1 &&
			    program_manifest.size() == 12 + both.size() + 2 * 302 + 32);
			assert(dir::validate_host_ingress_program_manifest(
			    transfer_cut, program_manifest, &nested_manifest,
			    &source_programs) && nested_manifest == both &&
			    source_programs.size() == 2 &&
			    source_programs[0].recipient.ingress.delivery_id == 98 &&
			    source_programs[1].recipient.ingress.delivery_id == 99 &&
			    source_programs[0].program_digest == announced_program &&
			    source_programs[1].program_digest == announced_program);
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames) == 1 &&
			    bundle_manifest == both && bundle_frames.size() == 2);
			std::vector<uint8_t> program_export;
			std::vector<std::vector<uint8_t>> program_frames;
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, program_export, program_frames, true) == 1 &&
			    program_export == program_manifest &&
			    program_frames == bundle_frames);
			host_ingress_transfer_bundle complete_bundle;
			assert(dir::decode_host_ingress_transfer_bundle(transfer_cut,
			    bundle_manifest, bundle_frames, complete_bundle) &&
			    complete_bundle.entries.size() == 2 &&
			    complete_bundle.payloads.size() == 2 &&
			    complete_bundle.payloads[0] == payload &&
			    complete_bundle.payloads[1] == payload);
			std::vector<uint8_t> transfer_wire;
			assert(dtraced_transfer_wire_build(
			    transfer_cut.token.data(), bundle_manifest,
			    bundle_frames, transfer_wire));
			memcpy(transfer_cut.transfer_digest.data(),
			    transfer_wire.data() + transfer_wire.size() - 32, 32);
			host_ingress_transfer_bundle wire_bundle;
			assert(dir::decode_host_ingress_transfer_wire(
			    transfer_cut, transfer_wire, wire_bundle) &&
			    wire_bundle.entries.size() == 2 &&
			    wire_bundle.payloads == complete_bundle.payloads);
			transfer_wire[DTRACED_TRANSFER_HEADER_SIZE + 20] ^= 1;
			size_t transfer_tail = transfer_wire.size() -
			    DTRACED_TRANSFER_DIGEST_SIZE;
			assert(SHA256(transfer_wire.data(), transfer_tail,
			    transfer_wire.data() + transfer_tail) != nullptr);
			assert(!dir::decode_host_ingress_transfer_wire(
			    transfer_cut, transfer_wire, wire_bundle) &&
			    wire_bundle.entries.empty() &&
			    wire_bundle.payloads.empty());
			transfer_wire[DTRACED_TRANSFER_HEADER_SIZE + 20] ^= 1;
			assert(SHA256(transfer_wire.data(), transfer_tail,
			    transfer_wire.data() + transfer_tail) != nullptr);
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, manifest, 0, exported) == -1 &&
			    errno == ESTALE && exported.empty());
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, both, 0, exported) == 1);
			assert(dir::decode_host_ingress_transfer_frame(
			    transfer_cut, second, exported, &decoded_payload) &&
			    decoded_payload == payload);
			std::vector<host_ingress_transfer_entry> decoded;
			assert(dir::validate_host_ingress_transfer_manifest(
			    transfer_cut, both, &decoded));
			assert(decoded.size() == 2 &&
			    decoded[0].ingress.delivery_id == 98 &&
			    decoded[1].ingress.delivery_id == 99 &&
			    decoded[0].recipients.size() == 1 &&
			    decoded[0].recipients[0].phase ==
			    consumer_receipt_phase::executed_no_derived &&
			    decoded[0].recipients[0].record.consumer_session ==
			    recipient.consumer_session);
			std::vector<uint8_t> later_frame;
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, both, 1, later_frame) == 1);
			std::vector<std::vector<uint8_t>> frames{
			    exported, later_frame};
			host_ingress_transfer_bundle bundle;
			assert(dir::decode_host_ingress_transfer_bundle(
			    transfer_cut, both, frames, bundle) &&
			    bundle.entries.size() == 2 &&
			    bundle.entries[0].ingress.delivery_id == 98 &&
			    bundle.entries[1].ingress.delivery_id == 99 &&
			    bundle.payloads.size() == 2 &&
			    bundle.payloads[0] == payload &&
			    bundle.payloads[1] == payload);
			std::vector<uint8_t> program_wire;
			assert(dtraced_transfer_wire_build(transfer_cut.token.data(),
			    program_manifest, frames, program_wire));
			memcpy(transfer_cut.transfer_digest.data(),
			    program_wire.data() + program_wire.size() - 32, 32);
			transfer_wire = program_wire;
			host_ingress_transfer_bundle program_bundle;
			assert(dir::decode_host_ingress_transfer_wire(transfer_cut,
			    program_wire, program_bundle) &&
			    program_bundle.entries.size() == 2 &&
			    program_bundle.source_programs.size() == 2 &&
			    program_bundle.source_programs[0].recipient.ingress.delivery_id
			    == 98 &&
			    program_bundle.source_programs[1].recipient.ingress.delivery_id
			    == 99 &&
			    program_bundle.payloads == bundle.payloads);
			durable_handoff reserved_cut = transfer_cut;
			reserved_cut.checkpoint_digest[0] = 1;
			reserved_cut.destination_vmid = 8;
			reserved_cut.destination_epoch = 43;
			std::array<uint8_t, 16> destination_session{};
			destination_session[0] = 0xde;
			host_ingress_destination_plan destination_plan;
			assert(dir::plan_host_ingress_destination(reserved_cut,
			    program_manifest, frames, destination_session, 100, 200,
			    "guest-b", destination_plan) &&
			    destination_plan.source_programs.size() == 2 &&
			    destination_plan.source_programs[0].program_digest ==
			    announced_program);
			assert(dir::plan_host_ingress_destination(reserved_cut,
			    both, frames, destination_session, 100, 200, "guest-b",
			    destination_plan));
			assert(destination_plan.source_entries.size() == 2 &&
			    destination_plan.source_programs.empty() &&
			    destination_plan.deliveries.size() == 2 &&
			    destination_plan.payloads.size() == 2 &&
			    destination_plan.deliveries[0].vmid == 8 &&
			    destination_plan.deliveries[0].epoch == 43 &&
			    destination_plan.deliveries[0].session_id ==
			    destination_session &&
			    destination_plan.deliveries[0].journal_version == 5 &&
			    destination_plan.deliveries[0].handoff_token ==
			    reserved_cut.token &&
			    destination_plan.deliveries[0].source_session ==
			    bundle.entries[0].ingress.session_id &&
			    destination_plan.deliveries[0].payload_vmid == 7 &&
			    destination_plan.deliveries[0].payload_epoch ==
			    transfer_cut.source_epoch &&
			    destination_plan.deliveries[0].peer_uid == 100 &&
			    destination_plan.deliveries[0].peer_pid == 200 &&
			    destination_plan.source_entries[0].ingress.vmid == 7 &&
			    destination_plan.payloads[0].size() == payload.size() &&
			    memcmp(destination_plan.payloads[0].data() +
			    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, "guest-b", 7) == 0 &&
			    dir::validate_host_ingress_transfer_payload(
			    destination_plan.deliveries[0],
			    destination_plan.payloads[0]) &&
			    bundle.payloads[0] == payload);
			assert(!dir::plan_host_ingress_destination(transfer_cut,
			    both, frames, destination_session, 100, 200, "guest-b",
			    destination_plan) && errno == EINVAL &&
			    destination_plan.deliveries.empty());
			assert(!dir::plan_host_ingress_destination(reserved_cut,
			    both, frames, transfer_cut.source_session, 100, 200,
			    "guest-b", destination_plan) && errno == EINVAL &&
			    destination_plan.payloads.empty());
			assert(!dir::plan_host_ingress_destination(reserved_cut,
			    both, frames, destination_session, 100, 200,
			    std::string("bad\0name", 8), destination_plan) &&
			    errno == EINVAL && destination_plan.deliveries.empty());
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-b",
			    destination_plan) == 0 &&
			    destination_plan.deliveries.empty());
			assert(transfer_inbound.stage_host_ingress_destination(
			    reserved_cut, both, frames, destination_session, 100, 200,
			    "guest-b", destination_plan) &&
			    destination_plan.deliveries.size() == 2);
			assert(transfer_inbound.stage_host_ingress_destination(
			    reserved_cut, both, frames, destination_session, 100, 200,
			    "guest-b", destination_plan));
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-b",
			    destination_plan) == 1 &&
			    destination_plan.deliveries.size() == 2 &&
			    destination_plan.payloads[0].size() == payload.size());
			assert(!transfer_inbound.stage_host_ingress_destination(
			    reserved_cut, both, frames, destination_session, 100, 200,
			    "guest-c", destination_plan) && errno == EEXIST &&
			    destination_plan.deliveries.empty());
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-c",
			    destination_plan) == -1 && errno == EPROTO &&
			    destination_plan.deliveries.empty());
			char stage_name[39];
			memset(stage_name, '0', 38);
			memcpy(stage_name, ".htb1.", 6);
			stage_name[6] = '7';
			stage_name[7] = 'd';
			stage_name[38] = '\0';
			assert(fchmodat(transfer_inbound.dirfd, stage_name, 0644, 0)
			    == 0);
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-b",
			    destination_plan) == -1 && errno == EPROTO &&
			    destination_plan.deliveries.empty());
			assert(fchmodat(transfer_inbound.dirfd, stage_name, 0600, 0)
			    == 0);
			int stage_fd = openat(transfer_inbound.dirfd, stage_name,
			    O_RDWR | O_NOFOLLOW);
			assert(stage_fd >= 0);
			struct stat stage_stat{};
			assert(fstat(stage_fd, &stage_stat) == 0 &&
			    stage_stat.st_size > 0);
			unsigned char stage_tail;
			assert(pread(stage_fd, &stage_tail, 1,
			    stage_stat.st_size - 1) == 1);
			unsigned char corrupted_tail = stage_tail ^ 1;
			assert(pwrite(stage_fd, &corrupted_tail, 1,
			    stage_stat.st_size - 1) == 1 && fsync(stage_fd) == 0);
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-b",
			    destination_plan) == -1 && errno == EPROTO &&
			    destination_plan.deliveries.empty());
			assert(pwrite(stage_fd, &stage_tail, 1,
			    stage_stat.st_size - 1) == 1 && fsync(stage_fd) == 0 &&
			    close(stage_fd) == 0);
			assert(transfer_inbound.load_host_ingress_destination_stage(
			    reserved_cut, destination_session, 100, 200, "guest-b",
			    destination_plan) == 1);
			char transfer_dest[] = "/tmp/hypertrace-transfer-dest.XXXXXX";
			char transfer_dest_out[] =
			    "/tmp/hypertrace-transfer-dest-out.XXXXXX";
			assert(mkdtemp(transfer_dest) != nullptr);
			assert(mkdtemp(transfer_dest_out) != nullptr);
			{
				dir destination_inbound(transfer_dest,
				    &process_inbound);
				dir destination_outbound(transfer_dest_out,
				    &process_outbound);
				transfer_host.inbounddir = &destination_inbound;
				transfer_host.outbounddir = &destination_outbound;
				destination_inbound.state = &transfer_host;
				destination_outbound.state = &transfer_host;
				std::vector<uint8_t> no_ingress;
				assert(dtraced_transfer_wire_build(
				    reserved_cut.token.data(), {}, {}, no_ingress));
				assert(destination_inbound.
				    stage_host_ingress_destination_wire(reserved_cut,
				    no_ingress, destination_session, 100, 200,
				    "guest-b", destination_plan) == 0 &&
				    destination_plan.deliveries.empty());
				assert(destination_inbound.
				    stage_host_ingress_destination_wire(reserved_cut,
				    transfer_wire, destination_session, 100, 200,
				    "guest-b", destination_plan) == 1 &&
				    destination_plan.deliveries.size() == 2);
				assert(destination_inbound.stage_host_ingress_destination(
				    reserved_cut, program_manifest, frames, destination_session,
				    100, 200, "guest-b", destination_plan));
				assert(!destination_inbound.import_host_ingress_pending(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b") && errno == ENOENT);
				durable_handoff prepared_cut = reserved_cut;
				prepared_cut.checkpoint_digest.fill(0);
				prepared_cut.destination_vmid = 0;
				prepared_cut.destination_epoch = 0;
				durable_handoff committed_cut = reserved_cut;
				committed_cut.destination_vmid = 0;
				committed_cut.destination_epoch = 0;
				destination_outbound.state = nullptr;
				assert(destination_outbound.prepare_handoff(prepared_cut, false));
				assert(destination_outbound.commit_handoff(committed_cut));
				assert(destination_outbound.record_source_release(committed_cut));
				assert(destination_outbound.reserve_handoff(reserved_cut));
				destination_outbound.state = &transfer_host;
				auto hex16 = [](const std::array<uint8_t, 16> &id) {
					static constexpr char hex[] = "0123456789abcdef";
					std::string result(32, '0');
					for (size_t i = 0; i < id.size(); i++) {
						result[i * 2] = hex[id[i] >> 4];
						result[i * 2 + 1] = hex[id[i] & 15];
					}
					return result;
				};
				std::string stray_activation_name = ".hla1." +
				    hex16(reserved_cut.token);
				int stray_activation_fd = openat(destination_inbound.dirfd,
				    stray_activation_name.c_str(), O_CREAT | O_EXCL | O_WRONLY |
				    O_NOFOLLOW, 0600);
				assert(stray_activation_fd >= 0);
				std::array<uint8_t, 128> stray_activation{};
				assert(write(stray_activation_fd, stray_activation.data(),
				    stray_activation.size()) == (ssize_t)stray_activation.size() &&
				    fsync(stray_activation_fd) == 0 &&
				    close(stray_activation_fd) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(!destination_outbound.cancel_handoff_reservation(
				    reserved_cut) && errno == EPROTO);
				assert(unlinkat(destination_inbound.dirfd,
				    stray_activation_name.c_str(), 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.import_host_ingress_pending(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				for (const auto &delivery :
				    destination_plan.deliveries) {
					assert(destination_inbound.delivery_status(delivery) ==
					    (int)delivery_phase::pending);
					assert(!destination_inbound.record_delivery(delivery,
					    delivery_phase::accepted) && errno == EBUSY);
					assert(destination_inbound.delivery_status(delivery) ==
					    (int)delivery_phase::pending);
					assert(destination_inbound.verify_host_ingress_payload(
					    delivery) == 1);
				}
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EBUSY);
				transfer_host.sockfds.insert(&consumer);
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EBUSY);
				assert(destination_inbound.queue_recovered_consumer(
				    &consumer) == 0);
				uid_t original_consumer_uid = consumer.peer_uid;
				consumer.peer_uid = original_consumer_uid + 1;
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EPERM);
				consumer.peer_uid = original_consumer_uid;
				consumer.consumer_program_digest[0] ^= 1;
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EPROTO);
				consumer.consumer_program_digest[0] ^= 1;
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				transfer_host.sockfds.erase(&consumer);
				std::vector<std::array<uint8_t, 76>> durable_owners;
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == 1 && durable_owners.size() == 1 &&
				    memcmp(durable_owners[0].data() + 4,
				    consumer.session_id.data(), 16) == 0);
				host_ingress_destination_plan reloaded_program_plan;
				assert(destination_inbound.
				    load_host_ingress_destination_stage(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    reloaded_program_plan) == 1 &&
				    reloaded_program_plan.source_programs.size() == 2);
				std::vector<std::vector<uint8_t>> planned_cohorts;
				assert(dir::plan_import_consumer_cohorts(
				    reloaded_program_plan, durable_owners,
				    planned_cohorts) && planned_cohorts.size() == 2);
				for (size_t i = 0; i < planned_cohorts.size(); i++) {
					std::vector<durable_import_consumer_receipt> members;
					assert(dir::decode_import_consumer_cohort(
					    reloaded_program_plan.deliveries[i],
					    planned_cohorts[i], members) &&
					    members.size() == 1 &&
					    members[0].program_digest == announced_program &&
					    members[0].owner_wire == durable_owners[0]);
				}
				char hck1_name[39];
				memcpy(hck1_name, stage_name, sizeof(hck1_name));
				memcpy(hck1_name, ".hck1.", 6);
				int hck1_fd = openat(destination_inbound.dirfd,
				    hck1_name, O_RDWR | O_NOFOLLOW);
				assert(hck1_fd >= 0);
				struct stat hck1_stat{};
				assert(fstat(hck1_fd, &hck1_stat) == 0 &&
				    hck1_stat.st_size > 88 + 32);
				std::vector<uint8_t> hck1_bytes((size_t)hck1_stat.st_size);
				assert(pread(hck1_fd, hck1_bytes.data(),
				    hck1_bytes.size(), 0) ==
				    (ssize_t)hck1_bytes.size() &&
				    memcmp(hck1_bytes.data(), "HCK1", 4) == 0 &&
				    memcmp(hck1_bytes.data() + 4,
				    reserved_cut.token.data(), 16) == 0 &&
				    dtraced_wire_get_u32(hck1_bytes.data() + 84) == 2);
				uint8_t hck1_digest[32];
				assert(SHA256(hck1_bytes.data(), hck1_bytes.size() - 32,
				    hck1_digest) != nullptr &&
				    memcmp(hck1_digest, hck1_bytes.data() +
				    hck1_bytes.size() - 32, 32) == 0);
				size_t hck1_offset = 88;
				for (const auto &cohort : planned_cohorts) {
					assert(dtraced_wire_get_u32(hck1_bytes.data() +
					    hck1_offset) == cohort.size());
					hck1_offset += 4;
					assert(memcmp(hck1_bytes.data() + hck1_offset,
					    cohort.data(), cohort.size()) == 0);
					hck1_offset += cohort.size();
				}
				assert(hck1_offset == hck1_bytes.size() - 32);
				std::vector<std::vector<uint8_t>> recovered_cohorts;
				assert(destination_inbound.load_import_consumer_cohorts(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_cohorts) == 1 &&
				    recovered_cohorts == planned_cohorts);
				assert(close(hck1_fd) == 0 &&
				    unlinkat(destination_inbound.dirfd, hck1_name, 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_import_consumer_cohorts(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_cohorts) == 0 &&
				    recovered_cohorts.empty());
				transfer_host.sockfds.insert(&consumer);
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				transfer_host.sockfds.erase(&consumer);
				hck1_fd = openat(destination_inbound.dirfd,
				    hck1_name, O_RDWR | O_NOFOLLOW);
				assert(hck1_fd >= 0 &&
				    pread(hck1_fd, hck1_bytes.data(),
				    hck1_bytes.size(), 0) ==
				    (ssize_t)hck1_bytes.size());
				uint8_t trailer = hck1_bytes.back();
				uint8_t corrupt_trailer = trailer ^ 1;
				assert(pwrite(hck1_fd, &corrupt_trailer, 1,
				    hck1_bytes.size() - 1) == 1 && fsync(hck1_fd) == 0);
				assert(destination_inbound.load_import_consumer_cohorts(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_cohorts) == -1 &&
				    errno == EPROTO && recovered_cohorts.empty());
				transfer_host.sockfds.insert(&consumer);
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EEXIST);
				transfer_host.sockfds.erase(&consumer);
				assert(pwrite(hck1_fd, &trailer, 1,
				    hck1_bytes.size() - 1) == 1 &&
				    fsync(hck1_fd) == 0 && close(hck1_fd) == 0);
				assert(destination_inbound.load_import_consumer_cohorts(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_cohorts) == 1 &&
				    recovered_cohorts == planned_cohorts);
				char hrs1_name[39];
				memcpy(hrs1_name, stage_name, sizeof(hrs1_name));
				memcpy(hrs1_name, ".hrs1.", 6);
				int hrs1_fd = openat(destination_inbound.dirfd,
				    hrs1_name, O_RDWR | O_NOFOLLOW);
				assert(hrs1_fd >= 0);
				struct stat hrs1_stat{};
				assert(fstat(hrs1_fd, &hrs1_stat) == 0 &&
				    hrs1_stat.st_size == 64 + 2 * 33 + 32);
				std::vector<uint8_t> hrs1_bytes((size_t)hrs1_stat.st_size);
				assert(pread(hrs1_fd, hrs1_bytes.data(),
				    hrs1_bytes.size(), 0) ==
				    (ssize_t)hrs1_bytes.size() &&
				    memcmp(hrs1_bytes.data(), "HRS1", 4) == 0 &&
				    dtraced_wire_get_u32(hrs1_bytes.data() + 52) == 2 &&
				    hrs1_bytes[64 + 32] == 'p' &&
				    hrs1_bytes[64 + 33 + 32] == 'p');
				std::vector<std::array<uint8_t, 32>> slot_ids;
				assert(destination_inbound.load_import_pending_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", slot_ids) == 1 &&
				    slot_ids.size() == 2 && slot_ids[0] != slot_ids[1]);
				char hpa1_name[39];
				memcpy(hpa1_name, stage_name, sizeof(hpa1_name));
				memcpy(hpa1_name, ".hpa1.", 6);
				int hpa1_fd = openat(destination_inbound.dirfd,
				    hpa1_name, O_RDWR | O_NOFOLLOW);
				assert(hpa1_fd >= 0);
				std::vector<uint8_t> hpa1_bytes(160);
				assert(pread(hpa1_fd, hpa1_bytes.data(),
				    hpa1_bytes.size(), 0) ==
				    (ssize_t)hpa1_bytes.size() &&
				    memcmp(hpa1_bytes.data(), "HPA1", 4) == 0 &&
				    dtraced_wire_get_u32(hpa1_bytes.data() + 52) == 2 &&
				    memcmp(hpa1_bytes.data() + 20,
				    hrs1_bytes.data() + hrs1_bytes.size() - 32, 32) == 0);
				std::vector<std::array<uint8_t, 32>> delivery_ids;
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == 1 &&
				    delivery_ids.size() == 2 &&
				    delivery_ids[0] != delivery_ids[1]);
				uint8_t hpa1_trailer = hpa1_bytes.back();
				uint8_t bad_hpa1_trailer = hpa1_trailer ^ 1;
				assert(pwrite(hpa1_fd, &bad_hpa1_trailer, 1,
				    hpa1_bytes.size() - 1) == 1 && fsync(hpa1_fd) == 0);
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == -1 && errno == EPROTO &&
				    delivery_ids.empty());
				assert(pwrite(hpa1_fd, &hpa1_trailer, 1,
				    hpa1_bytes.size() - 1) == 1 &&
				    fsync(hpa1_fd) == 0 && close(hpa1_fd) == 0);
				assert(unlinkat(destination_inbound.dirfd,
				    hpa1_name, 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == 0 &&
				    delivery_ids.empty());
				transfer_host.sockfds.insert(&consumer);
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				transfer_host.sockfds.erase(&consumer);
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == 1 &&
				    delivery_ids.size() == 2);
				durable_import_consumer_result outcome{};
				outcome.token = reserved_cut.token;
				memcpy(outcome.slots_digest.data(),
				    hrs1_bytes.data() + hrs1_bytes.size() - 32, 32);
				outcome.receipt_digest = slot_ids[0];
				outcome.phase = consumer_receipt_phase::no_derived;
				std::vector<uint8_t> outcome_wire;
				durable_import_consumer_result decoded_outcome{};
				assert(dir::encode_import_consumer_result(outcome,
				    outcome_wire) && outcome_wire.size() == 156 &&
				    dir::decode_import_consumer_result(outcome_wire,
				    decoded_outcome) &&
				    decoded_outcome.receipt_digest == slot_ids[0] &&
				    decoded_outcome.phase ==
				    consumer_receipt_phase::no_derived);
				auto bad_outcome_wire = outcome_wire;
				bad_outcome_wire[117] = 1;
				assert(SHA256(bad_outcome_wire.data(), 124,
				    bad_outcome_wire.data() + 124) != nullptr &&
				    !dir::decode_import_consumer_result(
				    bad_outcome_wire, decoded_outcome) && errno == EPROTO);
				outcome.phase = consumer_receipt_phase::derived;
				outcome.derived_claim_digest[0] = 1;
				assert(dir::encode_import_consumer_result(outcome,
				    outcome_wire) &&
				    dir::decode_import_consumer_result(outcome_wire,
				    decoded_outcome) &&
				    decoded_outcome.phase ==
				    consumer_receipt_phase::derived &&
				    decoded_outcome.derived_claim_digest ==
				    outcome.derived_claim_digest);
				outcome.derived_claim_digest.fill(0);
				assert(!dir::encode_import_consumer_result(outcome,
				    outcome_wire) && errno == EINVAL &&
				    outcome_wire.empty());
				outcome.phase = consumer_receipt_phase::no_derived;
				outcome.derived_claim_digest[0] = 1;
				assert(!dir::encode_import_consumer_result(outcome,
				    outcome_wire) && errno == EINVAL &&
				    outcome_wire.empty());
				outcome.phase = consumer_receipt_phase::pending;
				assert(!dir::encode_import_consumer_result(outcome,
				    outcome_wire) && errno == EINVAL &&
				    outcome_wire.empty());
				uint8_t hrs1_trailer = hrs1_bytes.back();
				uint8_t bad_hrs1_trailer = hrs1_trailer ^ 1;
				assert(pwrite(hrs1_fd, &bad_hrs1_trailer, 1,
				    hrs1_bytes.size() - 1) == 1 && fsync(hrs1_fd) == 0);
				assert(destination_inbound.load_import_pending_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", slot_ids) == -1 && errno == EPROTO &&
				    slot_ids.empty());
				transfer_host.sockfds.insert(&consumer);
				assert(!destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b") &&
				    errno == EEXIST);
				transfer_host.sockfds.erase(&consumer);
				assert(pwrite(hrs1_fd, &hrs1_trailer, 1,
				    hrs1_bytes.size() - 1) == 1 &&
				    fsync(hrs1_fd) == 0 && close(hrs1_fd) == 0);
				assert(unlinkat(destination_inbound.dirfd,
				    hrs1_name, 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_import_pending_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", slot_ids) == 0 && slot_ids.empty());
				transfer_host.sockfds.insert(&consumer);
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				transfer_host.sockfds.erase(&consumer);
				assert(destination_inbound.load_import_pending_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", slot_ids) == 1 && slot_ids.size() == 2);
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == 1 &&
				    delivery_ids.size() == 2);
				auto wrong_plan = reloaded_program_plan;
				wrong_plan.source_programs[0].program_digest.fill(0);
				assert(!dir::plan_import_consumer_cohorts(wrong_plan,
				    durable_owners, planned_cohorts) && errno == EPROTO &&
				    planned_cohorts.empty());
				wrong_plan = reloaded_program_plan;
				std::swap(wrong_plan.source_programs[0],
				    wrong_plan.source_programs[1]);
				assert(!dir::plan_import_consumer_cohorts(wrong_plan,
				    durable_owners, planned_cohorts) && errno == EPROTO &&
				    planned_cohorts.empty());
				/* HCR2/HCB2 bind the complete imported HTD5, the HCO1
				 * incarnation, and a nonzero program identity. The codecs
				 * themselves do not grant an execution lease. */
				durable_import_consumer_receipt imported_receipt{};
				imported_receipt.ingress =
				    destination_plan.deliveries[0];
				imported_receipt.owner_wire = durable_owners[0];
				imported_receipt.program_digest[0] = 0x81;
				std::vector<uint8_t> receipt_wire, cohort_wire;
				assert(dir::encode_import_consumer_receipt(
				    imported_receipt, receipt_wire) &&
				    receipt_wire.size() == 329);
				durable_import_consumer_receipt decoded_receipt{};
				assert(dir::decode_import_consumer_receipt(
				    imported_receipt.ingress, receipt_wire,
				    decoded_receipt) &&
				    decoded_receipt.owner_wire == durable_owners[0]);
				assert(!dir::decode_import_consumer_receipt(
				    destination_plan.deliveries[1], receipt_wire,
				    decoded_receipt) && errno == EPROTO &&
				    decoded_receipt.program_digest ==
				    decltype(decoded_receipt.program_digest){});
				auto missing_program = imported_receipt;
				missing_program.program_digest.fill(0);
				assert(!dir::encode_import_consumer_receipt(
				    missing_program, receipt_wire) && errno == EINVAL &&
				    receipt_wire.empty());
				assert(dir::encode_import_consumer_receipt(
				    imported_receipt, receipt_wire));
				auto second_recipient = imported_receipt;
				second_recipient.owner_wire[4]++;
				assert(SHA256(second_recipient.owner_wire.data(), 44,
				    second_recipient.owner_wire.data() + 44));
				std::vector<durable_import_consumer_receipt> decoded_cohort;
				assert(dir::encode_import_consumer_cohort(
				    imported_receipt.ingress,
				    {second_recipient, imported_receipt}, cohort_wire));
				assert(dir::decode_import_consumer_cohort(
				    imported_receipt.ingress, cohort_wire,
				    decoded_cohort) && decoded_cohort.size() == 2 &&
				    decoded_cohort[0].owner_wire == imported_receipt.owner_wire &&
				    decoded_cohort[1].owner_wire == second_recipient.owner_wire);
				assert(!dir::decode_import_consumer_cohort(
				    destination_plan.deliveries[1], cohort_wire,
				    decoded_cohort) && errno == EPROTO &&
				    decoded_cohort.empty());
				assert(!dir::encode_import_consumer_cohort(
				    imported_receipt.ingress,
				    {imported_receipt, imported_receipt},
				    cohort_wire) && errno == EPROTO &&
				    cohort_wire.empty());
				assert(dir::encode_import_consumer_cohort(
				    imported_receipt.ingress,
				    {second_recipient, imported_receipt}, cohort_wire));
				auto shortened_cohort = cohort_wire;
				shortened_cohort.pop_back();
				assert(!dir::decode_import_consumer_cohort(
				    imported_receipt.ingress, shortened_cohort,
				    decoded_cohort) && errno == EPROTO &&
				    decoded_cohort.empty());
				auto forged_cohort = cohort_wire;
				forged_cohort[8 + 189 + 28] ^= 1;
				assert(SHA256(forged_cohort.data() + 8, 297,
				    forged_cohort.data() + 8 + 297));
				assert(SHA256(forged_cohort.data(),
				    forged_cohort.size() - 32,
				    forged_cohort.data() + forged_cohort.size() - 32));
				assert(!dir::decode_import_consumer_cohort(
				    imported_receipt.ingress, forged_cohort,
				    decoded_cohort) && errno == EPROTO &&
				    decoded_cohort.empty());
				/* Even a wrongly renamed imported record cannot make the
				 * ordinary watcher launch a destination consumer. */
				const auto &guarded = destination_plan.deliveries[0];
				char delivery_name[80];
				assert(snprintf(delivery_name, sizeof(delivery_name),
				    ".delivery.%s.%016jx.p",
				    hex16(guarded.session_id).c_str(),
				    (uintmax_t)guarded.delivery_id) > 0);
				std::string pending_name = delivery_name;
				std::string spool_name = "elf." +
				    hex16(guarded.program_id) + "." +
				    hex16(guarded.source_id);
				assert(faccessat(destination_inbound.dirfd,
				    pending_name.c_str(), F_OK, 0) == 0 &&
				    faccessat(destination_inbound.dirfd,
				    spool_name.c_str(), F_OK, 0) == 0);
				std::string accepted_name = pending_name;
				accepted_name.back() = 'a';
				assert(renameat(destination_inbound.dirfd,
				    pending_name.c_str(), destination_inbound.dirfd,
				    accepted_name.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.host_ingress_phase(
				    guarded.program_id.data(), guarded.source_id.data()) ==
				    (int)delivery_phase::accepted);
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == -1 && errno == EBUSY &&
				    durable_owners.empty());
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids) == -1 && errno == EBUSY &&
				    delivery_ids.empty());
				assert(destination_inbound.load_import_promotion_intent(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", delivery_ids, true) == 1 &&
				    delivery_ids.size() == 2);
				dirent imported_file{};
				strcpy(imported_file.d_name, spool_name.c_str());
				const size_t jobs_before = transfer_host.joblist.size();
				assert(process_inbound(destination_inbound, &imported_file) &&
				    transfer_host.joblist.size() == jobs_before);
				assert(renameat(destination_inbound.dirfd,
				    accepted_name.c_str(), destination_inbound.dirfd,
				    pending_name.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == 1 && durable_owners.size() == 1);
				assert(destination_inbound.import_host_ingress_pending(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				DIR *scan = fdopendir(dup(destination_inbound.dirfd));
				assert(scan != nullptr);
				bool removed_spool = false;
				struct dirent *entry;
				while ((entry = readdir(scan)) != nullptr)
					if (strncmp(entry->d_name, "elf.", 4) == 0) {
						assert(unlinkat(destination_inbound.dirfd,
						    entry->d_name, 0) == 0);
						removed_spool = true;
						break;
					}
				assert(closedir(scan) == 0 && removed_spool);
				assert(destination_inbound.import_host_ingress_pending(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				for (const auto &delivery :
				    destination_plan.deliveries)
					assert(destination_inbound.verify_host_ingress_payload(
					    delivery) == 1);
				std::string owner_reservation_name = ".htl1." +
				    hex16(reserved_cut.token);
				assert(faccessat(destination_inbound.dirfd,
				    owner_reservation_name.c_str(), F_OK, 0) == 0);
				char owner_pid_hex[9];
				assert(snprintf(owner_pid_hex, sizeof(owner_pid_hex),
				    "%08x", dtraced_wire_get_u32(
				    durable_owners[0].data() + 24)) == 8);
				std::string current_owner_name = ".owner." +
				    hex16(consumer.session_id) + "." + owner_pid_hex;
				assert(renameat(destination_inbound.dirfd,
				    current_owner_name.c_str(), destination_inbound.dirfd,
				    ".owner.hidden") == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == -1 && errno == EBUSY &&
				    durable_owners.empty());
				assert(renameat(destination_inbound.dirfd, ".owner.hidden",
				    destination_inbound.dirfd,
				    current_owner_name.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == 1 && durable_owners.size() == 1);
				int reservation_fd = openat(destination_inbound.dirfd,
				    owner_reservation_name.c_str(), O_RDWR | O_NOFOLLOW);
				assert(reservation_fd >= 0);
				struct stat reservation_stat{};
				assert(fstat(reservation_fd, &reservation_stat) == 0 &&
				    reservation_stat.st_size > 0);
				unsigned char reservation_tail;
				assert(pread(reservation_fd, &reservation_tail, 1,
				    reservation_stat.st_size - 1) == 1);
				unsigned char bad_reservation_tail = reservation_tail ^ 1;
				assert(pwrite(reservation_fd, &bad_reservation_tail, 1,
				    reservation_stat.st_size - 1) == 1 &&
				    fsync(reservation_fd) == 0);
				assert(destination_inbound.load_host_ingress_consumer_owners(
				    reserved_cut, destination_session, 100, 200, "guest-b",
				    durable_owners) == -1 && errno == EPROTO &&
				    durable_owners.empty());
				assert(pwrite(reservation_fd, &reservation_tail, 1,
				    reservation_stat.st_size - 1) == 1 &&
				    fsync(reservation_fd) == 0 &&
				    close(reservation_fd) == 0);
				char hlc1_name[39];
				memcpy(hlc1_name, stage_name, sizeof(hlc1_name));
				memcpy(hlc1_name, ".hlc1.", 6);
				int stray_commit = openat(destination_inbound.dirfd,
				    hlc1_name, O_WRONLY | O_CREAT | O_EXCL, 0600);
				assert(stray_commit >= 0);
				std::array<uint8_t, 128> stray_bytes{};
				assert(write(stray_commit, stray_bytes.data(),
				    stray_bytes.size()) == (ssize_t)stray_bytes.size() &&
				    fsync(stray_commit) == 0 && close(stray_commit) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(!destination_outbound.cancel_handoff_reservation(
				    reserved_cut) && errno == EBUSY);
				assert(unlinkat(destination_inbound.dirfd,
				    hlc1_name, 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_outbound.cancel_handoff_reservation(
				    reserved_cut));
				assert(faccessat(destination_inbound.dirfd,
				    owner_reservation_name.c_str(), F_OK, 0) == -1 &&
				    errno == ENOENT);
				assert(faccessat(destination_inbound.dirfd,
				    hck1_name, F_OK, 0) == -1 && errno == ENOENT);
				assert(faccessat(destination_inbound.dirfd,
				    hrs1_name, F_OK, 0) == -1 && errno == ENOENT);
				assert(faccessat(destination_inbound.dirfd,
				    hpa1_name, F_OK, 0) == -1 && errno == ENOENT);
				/* Reuse the committed ticket for a claimed restore. A crash
				 * after the first phase rename must retain the fixed cohort;
				 * HLC1 appears only after the remaining member advances. */
				assert(destination_outbound.reserve_handoff(reserved_cut));
				host_ingress_destination_plan claimed_plan;
				assert(destination_inbound.
				    stage_host_ingress_destination_wire_reserved(
				    reserved_cut, transfer_wire, destination_session,
				    100, 200, "guest-b", claimed_plan) == 1 &&
				    claimed_plan.deliveries.size() == 2);
				assert(destination_inbound.import_host_ingress_pending(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				transfer_host.sockfds.insert(&consumer);
				assert(destination_inbound.
				    reserve_host_ingress_consumer_owners(reserved_cut,
				    destination_session, 100, 200, "guest-b"));
				assert(!destination_inbound.promote_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b") && errno == EBUSY);
				assert(destination_outbound.begin_handoff_mutation(
				    reserved_cut));
				assert(destination_outbound.claim_handoff(reserved_cut));
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == -1 && errno == EBUSY &&
				    delivery_ids.empty());
				consumer.consumer_program_digest[0] ^= 1;
				assert(!destination_inbound.promote_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b") && errno == EPROTO);
				consumer.consumer_program_digest[0] ^= 1;
				for (const auto &delivery : claimed_plan.deliveries)
					assert(destination_inbound.delivery_status(
					    delivery) == (int)delivery_phase::pending);
				assert(renameat(destination_inbound.dirfd,
				    pending_name.c_str(), destination_inbound.dirfd,
				    accepted_name.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(faccessat(destination_inbound.dirfd,
				    hlc1_name, F_OK, 0) == -1 && errno == ENOENT);
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == -1 && errno == EBUSY &&
				    delivery_ids.empty());
				assert(destination_inbound.promote_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				for (const auto &delivery : claimed_plan.deliveries)
					assert(destination_inbound.delivery_status(
					    delivery) == (int)delivery_phase::accepted);
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == 1 && delivery_ids.size() == 2);
				std::vector<durable_committed_import_entry>
				    committed_recipients;
				assert(destination_inbound.
				    load_committed_import_recipients(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_recipients) == 1 &&
				    committed_recipients.size() ==
				    claimed_plan.deliveries.size());
				for (size_t i = 0; i < committed_recipients.size(); i++) {
					const auto &entry = committed_recipients[i];
					assert(entry.ingress.handoff_token ==
					    reserved_cut.token &&
					    destination_inbound.delivery_status(
					    entry.ingress) ==
					    (int)delivery_phase::accepted &&
					    entry.recipients.size() ==
					    claimed_plan.source_entries[i].recipients.size());
					for (const auto &recipient : entry.recipients)
						assert(recipient.ingress.delivery_id ==
						    entry.ingress.delivery_id &&
						    memcmp(recipient.owner_wire.data() + 4,
						    consumer.session_id.data(), 16) == 0 &&
						    recipient.program_digest ==
						    consumer.consumer_program_digest);
				}
				std::vector<durable_committed_import_result_state>
				    recovered_results;
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == 1 &&
				    recovered_results.size() == slot_ids.size());
				for (size_t i = 0; i < recovered_results.size(); i++)
					assert(recovered_results[i].outcome.phase ==
					    consumer_receipt_phase::pending &&
					    recovered_results[i].outcome.receipt_digest ==
					    slot_ids[i] &&
					    recovered_results[i].recipient.program_digest ==
					    consumer.consumer_program_digest);
				int current_hrs1 = openat(destination_inbound.dirfd,
				    hrs1_name, O_RDONLY | O_NOFOLLOW);
				assert(current_hrs1 >= 0);
				struct stat current_hrs1_stat{};
				assert(fstat(current_hrs1, &current_hrs1_stat) == 0 &&
				    current_hrs1_stat.st_size ==
				    (off_t)hrs1_bytes.size());
				durable_import_consumer_result committed_result{};
				committed_result.token = reserved_cut.token;
				committed_result.receipt_digest = slot_ids[0];
				assert(pread(current_hrs1,
				    committed_result.slots_digest.data(), 32,
				    current_hrs1_stat.st_size - 32) == 32 &&
				    close(current_hrs1) == 0);
				durable_import_consumer_result observed_result{};
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result.receipt_digest,
				    observed_result) == 0);
				committed_result.phase =
				    consumer_receipt_phase::executed_no_derived;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result) == -1 && errno == EBUSY);
				auto wrong_result = committed_result;
				wrong_result.slots_digest[0] ^= 1;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", wrong_result) == -1 && errno == EPROTO);
				wrong_result = committed_result;
				wrong_result.receipt_digest[0] ^= 1;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", wrong_result) == -1 && errno == EPROTO);
				committed_result.phase = consumer_receipt_phase::no_derived;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result) ==
				    (int)consumer_receipt_phase::no_derived);
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result) ==
				    (int)consumer_receipt_phase::no_derived);
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result.receipt_digest,
				    observed_result) ==
				    (int)consumer_receipt_phase::no_derived);
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == 1 &&
				    recovered_results.size() == 2 &&
				    recovered_results[0].outcome.phase ==
				    consumer_receipt_phase::no_derived &&
				    recovered_results[1].outcome.phase ==
				    consumer_receipt_phase::pending);
				committed_result.phase =
				    consumer_receipt_phase::executed_no_derived;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result) ==
				    (int)consumer_receipt_phase::executed_no_derived);
				committed_result.phase = consumer_receipt_phase::no_derived;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result) ==
				    (int)consumer_receipt_phase::executed_no_derived);
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result.receipt_digest,
				    observed_result) ==
				    (int)consumer_receipt_phase::executed_no_derived);
				wrong_result = committed_result;
				wrong_result.phase = consumer_receipt_phase::derived;
				wrong_result.derived_claim_digest[0] = 1;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", wrong_result) == -1 && errno == EPROTO);
				std::string executed_name = import_outcome_name(
				    reserved_cut.token, committed_result.receipt_digest, 'N');
				int executed_fd = openat(destination_inbound.dirfd,
				    executed_name.c_str(), O_RDWR | O_NOFOLLOW);
				assert(executed_fd >= 0);
				uint8_t outcome_tail, bad_outcome_tail;
				assert(pread(executed_fd, &outcome_tail, 1, 155) == 1);
				bad_outcome_tail = outcome_tail ^ 1;
				assert(pwrite(executed_fd, &bad_outcome_tail, 1, 155) == 1 &&
				    fsync(executed_fd) == 0);
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", committed_result.receipt_digest,
				    observed_result) == -1 && errno == EPROTO);
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == -1 &&
				    errno == EPROTO && recovered_results.empty());
				assert(pwrite(executed_fd, &outcome_tail, 1, 155) == 1 &&
				    fsync(executed_fd) == 0 && close(executed_fd) == 0);
				durable_import_consumer_result derived_result =
				    committed_result;
				derived_result.receipt_digest = slot_ids[1];
				derived_result.derived_claim_digest[0] = 1;
				derived_result.phase = consumer_receipt_phase::derived;
				assert(destination_inbound.record_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", derived_result) ==
				    (int)consumer_receipt_phase::derived);
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", derived_result.receipt_digest,
				    observed_result) ==
				    (int)consumer_receipt_phase::derived &&
				    observed_result.derived_claim_digest ==
				    derived_result.derived_claim_digest);
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == 1 &&
				    recovered_results.size() == 2 &&
				    recovered_results[0].outcome.phase ==
				    consumer_receipt_phase::executed_no_derived &&
				    recovered_results[1].outcome.phase ==
				    consumer_receipt_phase::derived);
				auto unknown_slot = slot_ids[0];
				unknown_slot[0] ^= 1;
				if (unknown_slot == slot_ids[1])
					unknown_slot[1] ^= 1;
				std::string stray_outcome = import_outcome_name(
				    reserved_cut.token, unknown_slot, 'n');
				int stray_fd = openat(destination_inbound.dirfd,
				    stray_outcome.c_str(),
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
				assert(stray_fd >= 0 && close(stray_fd) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == -1 &&
				    errno == EPROTO && recovered_results.empty());
				assert(unlinkat(destination_inbound.dirfd,
				    stray_outcome.c_str(), 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				std::string held_promotion =
				    std::string(hpa1_name) + ".held";
				assert(renameat(destination_inbound.dirfd,
				    hpa1_name, destination_inbound.dirfd,
				    held_promotion.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == -1 && errno == EPROTO &&
				    delivery_ids.empty());
				assert(destination_inbound.
				    load_committed_import_recipients(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_recipients) == -1 && errno == EPROTO &&
				    committed_recipients.empty());
				assert(renameat(destination_inbound.dirfd,
				    held_promotion.c_str(), destination_inbound.dirfd,
				    hpa1_name) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				std::string held_commit =
				    std::string(hlc1_name) + ".held";
				assert(renameat(destination_inbound.dirfd,
				    hlc1_name, destination_inbound.dirfd,
				    held_commit.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == 0 && delivery_ids.empty());
				assert(destination_inbound.
				    load_committed_import_recipients(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_recipients) == 0 &&
				    committed_recipients.empty());
				assert(destination_inbound.load_committed_import_results(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", recovered_results) == -1 &&
				    errno == EPROTO &&
				    recovered_results.empty());
				assert(faccessat(destination_inbound.dirfd,
				    hlc1_name, F_OK, 0) == -1 && errno == ENOENT);
				assert(renameat(destination_inbound.dirfd,
				    held_commit.c_str(), destination_inbound.dirfd,
				    hlc1_name) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				int hlc1_fd = openat(destination_inbound.dirfd,
				    hlc1_name, O_RDWR | O_NOFOLLOW);
				assert(hlc1_fd >= 0);
				struct stat hlc1_stat{};
				assert(fstat(hlc1_fd, &hlc1_stat) == 0 &&
				    hlc1_stat.st_size == 128);
				uint8_t hlc1_tail, bad_hlc1_tail;
				assert(pread(hlc1_fd, &hlc1_tail, 1, 127) == 1);
				bad_hlc1_tail = hlc1_tail ^ 1;
				assert(pwrite(hlc1_fd, &bad_hlc1_tail, 1, 127) == 1 &&
				    fsync(hlc1_fd) == 0);
				assert(!destination_inbound.promote_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b") && errno == EPROTO);
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == -1 && errno == EPROTO &&
				    delivery_ids.empty());
				assert(destination_inbound.
				    load_committed_import_recipients(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_recipients) == -1 && errno == EPROTO &&
				    committed_recipients.empty());
				assert(pwrite(hlc1_fd, &hlc1_tail, 1, 127) == 1 &&
				    fsync(hlc1_fd) == 0 && close(hlc1_fd) == 0);
				transfer_host.sockfds.erase(&consumer);
				assert(destination_inbound.promote_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				assert(destination_inbound.
				    load_committed_import_host_ingress(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    delivery_ids) == 1 && delivery_ids.size() == 2);
				assert(destination_inbound.
				    load_committed_import_recipients(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_recipients) == 1 &&
				    committed_recipients.size() == 2);
				assert(destination_outbound.
				    handoff_rekey_applied_status(reserved_cut) == 0);
				assert(destination_inbound.load_import_activation(reserved_cut,
				    destination_session, 100, 200, "guest-b") == 0);
				std::vector<durable_committed_import_entry> activated_entries;
				std::vector<durable_committed_import_result_state>
				    activated_results;
				assert(destination_inbound.load_activated_import_view(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", activated_entries, activated_results) == 0 &&
				    activated_entries.empty() && activated_results.empty());
				assert(destination_inbound.
				    record_activated_import_consumer_result(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_result) == -1 && errno == EBUSY);
				durable_committed_import_result_state inactive_import{};
				assert(destination_inbound.load_activated_import_recipient(
				    reserved_cut.token,
				    committed_recipients[0].ingress.session_id,
				    committed_recipients[0].ingress.delivery_id,
				    consumer.session_id, (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, inactive_import) == 0);
				assert(!destination_inbound.activate_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b") && errno == EBUSY);
				assert(destination_outbound.
				    mark_handoff_rekey_applied(reserved_cut));
				assert(destination_outbound.
				    handoff_rekey_applied_status(reserved_cut) == 1);
				assert(destination_inbound.activate_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				assert(destination_inbound.activate_import_host_ingress(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b"));
				assert(destination_inbound.load_import_activation(reserved_cut,
				    destination_session, 100, 200, "guest-b") == 1);
				assert(destination_inbound.
				    record_activated_import_consumer_result(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_result) ==
				    (int)consumer_receipt_phase::executed_no_derived);
				assert(destination_inbound.load_activated_import_view(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", activated_entries, activated_results) == 1 &&
				    activated_entries.size() == committed_recipients.size() &&
				    activated_results.size() == slot_ids.size());
				durable_committed_import_result_state exact_import{};
				const auto exact_ingress =
				    activated_results[0].recipient.ingress;
				assert(destination_inbound.load_activated_import_recipient(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, consumer.session_id,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, exact_import) == 1 &&
				    exact_import.outcome.receipt_digest ==
				    activated_results[0].outcome.receipt_digest &&
				    exact_import.recipient.program_digest ==
				    consumer.consumer_program_digest);
				std::vector<durable_committed_import_result_state>
				    import_work;
				assert(destination_inbound.list_activated_import_recipients(
				    &consumer, import_work) == 1 &&
				    import_work.size() == 2);
				auto wrong_consumer_session = consumer.session_id;
				wrong_consumer_session[0] ^= 1;
				std::array<uint8_t, 16> empty_token{};
				assert(destination_inbound.load_activated_import_recipient(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, wrong_consumer_session,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, exact_import) == 0 &&
				    exact_import.outcome.token == empty_token);
				assert(destination_inbound.record_activated_import_execution(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, consumer.session_id,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid,
				    consumer_receipt_phase::executed_no_derived) ==
				    (int)consumer_receipt_phase::executed_no_derived);
				assert(destination_inbound.record_activated_import_execution(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, consumer.session_id,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid,
				    consumer_receipt_phase::executed_derived) == -1 &&
				    errno == EPROTO);
				int import_execution_sockets[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    import_execution_sockets) == 0);
				dtd_initmsg_t import_execution_hello = consumer_hello;
				import_execution_hello.subs = DTD_SUB_READDATA;
				client_fd import_executor(kq, import_execution_sockets[0],
				    import_execution_hello);
				dtraced_hdr_t import_execution_header{};
				import_execution_header.msg_type =
				    DTRACED_MSG_CONSUMER_EXECUTION;
				import_execution_header.elf.len =
				    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE;
				dtraced_consumer_ack_t import_execution{};
				const auto report_ingress =
				    activated_results[1].recipient.ingress;
				import_execution.delivery_id = report_ingress.delivery_id;
				import_execution.vmid = report_ingress.vmid;
				import_execution.epoch = report_ingress.epoch;
				memcpy(import_execution.program_id,
				    report_ingress.program_id.data(), 16);
				memcpy(import_execution.source_id,
				    report_ingress.source_id.data(), 16);
				memcpy(import_execution.ingress_session,
				    report_ingress.session_id.data(), 16);
				import_execution.outcome =
				    DTRACED_CONSUMER_ACK_DERIVED;
				unsigned char import_execution_wire[
				    DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
				dtraced_wire_encode_consumer_execution(
				    import_execution_wire, &import_execution);
				dtraced_consumer_ack_t decoded_import_execution{};
				assert(dtraced_wire_decode_consumer_execution(
				    &decoded_import_execution, import_execution_wire) == 0 &&
				    import_executor.session_id == consumer.session_id);
				durable_delivery_state matched_import_ingress{};
				assert(destination_inbound.host_ingress_phase(
				    import_execution.program_id,
				    import_execution.source_id,
				    &matched_import_ingress) ==
				    (int)delivery_phase::accepted &&
				    matched_import_ingress.record.delivery_id ==
				    report_ingress.delivery_id);
				durable_consumer_receipt_state imported_exact{};
				assert(destination_inbound.consumer_receipt_exact(
				    report_ingress.session_id, report_ingress.delivery_id,
				    consumer.session_id, (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, imported_exact) == 2 &&
				    imported_exact.record.ingress.handoff_token ==
				    reserved_cut.token);
				{
					std::lock_guard clients(transfer_host.sockfdsmtx);
					transfer_host.sockfds.insert(&consumer);
				}
				hypertrace_vm_envelope imported_target{};
				imported_target.magic = HYPERTRACE_TARGET_MAGIC;
				imported_target.version = HYPERTRACE_ENVELOPE_VERSION;
				imported_target.vmid = report_ingress.vmid;
				imported_target.epoch = report_ingress.epoch;
				const char imported_elf[] = "\177ELFimported-derived";
				std::vector<unsigned char> imported_derived_payload(
				    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + sizeof(imported_elf));
				hypertrace_envelope_encode(imported_derived_payload.data(),
				    &imported_target);
				memcpy(imported_derived_payload.data() +
				    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, imported_elf,
				    sizeof(imported_elf));
				dtraced_derived_parent_t imported_parent{};
				memcpy(imported_parent.consumer_session,
				    consumer.session_id.data(), 16);
				imported_parent.delivery_id = report_ingress.delivery_id;
				imported_parent.vmid = report_ingress.vmid;
				imported_parent.epoch = report_ingress.epoch;
				memcpy(imported_parent.program_id,
				    report_ingress.program_id.data(), 16);
				memcpy(imported_parent.source_id,
				    report_ingress.source_id.data(), 16);
				dtraced_hdr_t imported_derived_header{};
				imported_derived_header.msg_type = DTRACED_MSG_ELF;
				imported_derived_header.elf.len =
				    imported_derived_payload.size();
				memcpy(imported_derived_header.elf.source_id,
				    imported_parent.source_id, 16);
				strcpy(imported_derived_header.elf.location, "outbound");
				assert(dtraced_derived_parent_to_header(
				    &imported_derived_header, &imported_parent) == 0);
				assert(dtraced_derived_program_id(&imported_parent,
				    imported_derived_payload.data(),
				    imported_derived_payload.size(),
				    imported_derived_header.elf.program_id) == 0);
				import_executor.peer_pid++;
				client_request wrong_import_writer(transfer_host,
				    imported_derived_header,
				    imported_derived_payload.data(),
				    imported_derived_payload.size(), &import_executor);
				assert(!wrong_import_writer.handle() && errno == EBUSY);
				import_executor.peer_pid--;
				client_request imported_derived(transfer_host,
				    imported_derived_header,
				    imported_derived_payload.data(),
				    imported_derived_payload.size(), &import_executor);
				assert(imported_derived.handle());
				std::vector<durable_derived_claim> imported_claims;
				assert(destination_outbound.list_derived_claims(
				    imported_claims) && imported_claims.size() == 1 &&
				    imported_claims[0].ingress_delivery_id ==
				    report_ingress.delivery_id &&
				    imported_claims[0].consumer_session ==
				    consumer.session_id);
				std::array<uint8_t, 32> proven_claim_digest{};
				const std::array<uint8_t, 32> empty_claim_digest{};
				assert(destination_inbound.resolve_import_derived_outbound(
				    destination_outbound, activated_results[1],
				    imported_claims[0], proven_claim_digest) == 1 &&
				    proven_claim_digest != empty_claim_digest);
				const auto expected_claim_digest = proven_claim_digest;
				auto wrong_import_claim = imported_claims[0];
				wrong_import_claim.bare_elf_digest[0] ^= 1;
				assert(destination_inbound.resolve_import_derived_outbound(
				    destination_outbound, activated_results[1],
				    wrong_import_claim, proven_claim_digest) == -1 &&
				    errno == EPROTO &&
				    proven_claim_digest == empty_claim_digest);
				import_execution.outcome =
				    DTRACED_CONSUMER_ACK_NO_DERIVED;
				dtraced_wire_encode_consumer_execution(
				    import_execution_wire, &import_execution);
				client_request wrong_import_outcome(transfer_host,
				    import_execution_header, import_execution_wire,
				    sizeof(import_execution_wire), &import_executor);
				assert(!wrong_import_outcome.handle() && errno == EPROTO);
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", derived_result.receipt_digest,
				    observed_result) == (int)consumer_receipt_phase::derived);
				import_execution.outcome = DTRACED_CONSUMER_ACK_DERIVED;
				dtraced_wire_encode_consumer_execution(
				    import_execution_wire, &import_execution);
				client_request import_report(transfer_host,
				    import_execution_header, import_execution_wire,
				    sizeof(import_execution_wire), &import_executor);
				assert(import_report.handle());
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", derived_result.receipt_digest,
				    observed_result) ==
				    (int)consumer_receipt_phase::executed_derived &&
				    observed_result.derived_claim_digest ==
				    derived_result.derived_claim_digest);
				consumer.consumer_program_digest[0] ^= 1;
				assert(destination_inbound.list_activated_import_recipients(
				    &consumer, import_work) == -1 && errno == EPROTO &&
				    import_work.empty());
				client_request wrong_import_program(transfer_host,
				    import_execution_header, import_execution_wire,
				    sizeof(import_execution_wire), &import_executor);
				assert(!wrong_import_program.handle() && errno == EAGAIN);
				consumer.consumer_program_digest[0] ^= 1;
				/* Reset this fixture's second immutable outcome to its
				 * HRS1 pending slot to exercise the ACK-backed send path. */
				std::string old_derived = import_outcome_name(
				    reserved_cut.token, derived_result.receipt_digest, 'd');
				std::string old_executed = import_outcome_name(
				    reserved_cut.token, derived_result.receipt_digest, 'D');
				assert(unlinkat(destination_inbound.dirfd,
				    old_derived.c_str(), 0) == 0 &&
				    unlinkat(destination_inbound.dirfd,
				    old_executed.c_str(), 0) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				int imported_receiver_sockets[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    imported_receiver_sockets) == 0);
				test_client_fd imported_receiver(kq,
				    imported_receiver_sockets[0], consumer_hello);
				assert(imported_receiver.consumer_birth_valid &&
				    imported_receiver.enable_write(&imported_receiver));
				{
					std::lock_guard clients(transfer_host.sockfdsmtx);
					transfer_host.sockfds.erase(&consumer);
					transfer_host.sockfds.insert(&imported_receiver);
				}
				const size_t prior_jobs = transfer_host.joblist.size();
				dtraced_hdr_t imported_program_header{};
				imported_program_header.msg_type =
				    DTRACED_MSG_CONSUMER_PROGRAM;
				imported_program_header.elf.len = 32;
				imported_receiver.consumer_replay_pending = true;
				client_request early_program(transfer_host,
				    imported_program_header,
				    consumer.consumer_program_digest.data(), 32,
				    &imported_receiver);
				assert(early_program.handle() &&
				    transfer_host.joblist.size() == prior_jobs);
				imported_receiver.consumer_replay_pending = false;
				imported_receiver.set_kq(-1);
				client_request failed_program(transfer_host,
				    imported_program_header,
				    consumer.consumer_program_digest.data(), 32,
				    &imported_receiver);
				assert(!failed_program.handle() && errno == EBADF &&
				    transfer_host.joblist.size() == prior_jobs &&
				    !imported_receiver.consumer_import_scan_done);
				imported_receiver.set_kq(kq);
				client_request imported_program(transfer_host,
				    imported_program_header,
				    consumer.consumer_program_digest.data(), 32,
				    &imported_receiver);
				assert(imported_program.handle() &&
				    imported_receiver.consumer_program_valid &&
				    transfer_host.joblist.size() == prior_jobs + 1);
				client_request exact_program(transfer_host,
				    imported_program_header,
				    consumer.consumer_program_digest.data(), 32,
				    &imported_receiver);
				assert(exact_program.handle() &&
				    transfer_host.joblist.size() == prior_jobs + 1);
				/* An activation ACK may be retried while HRO1 is still
				 * pending. Its exact recipient must keep only one live job. */
				assert(destination_inbound.queue_activated_import_consumer(
				    &imported_receiver, &reserved_cut.token) == 0 &&
				    transfer_host.joblist.size() == prior_jobs + 1);
				job *import_job = transfer_host.joblist.back();
				transfer_host.joblist.pop_back();
				bool import_sent = false;
				std::thread import_sender([&] {
					import_sent = import_job->send_elf();
				});
				unsigned char import_frame_wire[DTRACED_MSGHDRSIZE];
				dtraced_hdr_t import_frame{};
				assert(recv(imported_receiver_sockets[1],
				    import_frame_wire, sizeof(import_frame_wire),
				    MSG_WAITALL) == DTRACED_MSGHDRSIZE &&
				    dtraced_wire_decode_header(&import_frame,
				    import_frame_wire) == 0 &&
				    import_frame.elf.delivery_id ==
				    report_ingress.delivery_id &&
				    import_frame.elf.vmid == report_ingress.vmid &&
				    import_frame.elf.epoch == report_ingress.epoch);
				std::vector<uint8_t> imported_frame_payload(
				    import_frame.elf.len);
				assert(recv(imported_receiver_sockets[1],
				    imported_frame_payload.data(),
				    imported_frame_payload.size(), MSG_WAITALL) ==
				    (ssize_t)imported_frame_payload.size());
				dtraced_consumer_ack_t import_ack{};
				import_ack.delivery_id = import_frame.elf.delivery_id;
				import_ack.vmid = import_frame.elf.vmid;
				import_ack.epoch = import_frame.elf.epoch;
				memcpy(import_ack.program_id,
				    import_frame.elf.program_id, 16);
				memcpy(import_ack.source_id,
				    import_frame.elf.source_id, 16);
				import_ack.outcome = DTRACED_CONSUMER_ACK_DERIVED;
				unsigned char import_ack_wire[DTRACED_CONSUMER_ACK_WIRE_SIZE];
				dtraced_wire_encode_consumer_ack(import_ack_wire,
				    &import_ack);
				assert(::send(imported_receiver_sockets[1], import_ack_wire,
				    sizeof(import_ack_wire), 0) ==
				    (ssize_t)sizeof(import_ack_wire));
				import_sender.join();
				assert(import_sent);
				delete import_job;
				assert(destination_inbound.load_import_consumer_result(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", derived_result.receipt_digest,
				    observed_result) ==
				    (int)consumer_receipt_phase::derived &&
				    observed_result.derived_claim_digest ==
				    expected_claim_digest);
				assert(destination_inbound.queue_activated_import_consumer(
				    &imported_receiver) == 0 &&
				    imported_receiver.consumer_import_queued_receipts.empty());
				client_request replayed_import_report(transfer_host,
				    import_execution_header, import_execution_wire,
				    sizeof(import_execution_wire), &import_executor);
				assert(replayed_import_report.handle());
				{
					std::lock_guard clients(transfer_host.sockfdsmtx);
					transfer_host.sockfds.erase(&imported_receiver);
				}
				close(imported_receiver_sockets[1]);
				{
					std::lock_guard clients(transfer_host.sockfdsmtx);
					transfer_host.sockfds.erase(&consumer);
				}
				close(import_execution_sockets[1]);
				assert(destination_inbound.load_activated_import_view(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", activated_entries, activated_results) == 1);
				assert(activated_results[0].outcome.phase ==
				    consumer_receipt_phase::executed_no_derived &&
				    activated_results[1].outcome.phase ==
				    consumer_receipt_phase::executed_derived);
				for (size_t i = 0; i < activated_entries.size(); i++)
					assert(activated_entries[i].ingress.delivery_id ==
					    committed_recipients[i].ingress.delivery_id &&
					    activated_entries[i].recipients.size() ==
					    committed_recipients[i].recipients.size());
				std::string activation_name = ".hla1." +
				    hex16(reserved_cut.token);
				std::string held_stage =
				    std::string(stage_name) + ".activation-held";
				assert(renameat(destination_inbound.dirfd, stage_name,
				    destination_inbound.dirfd, held_stage.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_activated_import_recipient(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, consumer.session_id,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, exact_import) == -1 &&
				    errno == EPROTO);
				assert(renameat(destination_inbound.dirfd,
				    held_stage.c_str(), destination_inbound.dirfd,
				    stage_name) == 0 && fsync(destination_inbound.dirfd) == 0);
				int activation_fd = openat(destination_inbound.dirfd,
				    activation_name.c_str(), O_RDWR | O_NOFOLLOW);
				assert(activation_fd >= 0);
				uint8_t activation_tail;
				assert(pread(activation_fd, &activation_tail, 1, 127) == 1);
				uint8_t bad_activation_tail = activation_tail ^ 1;
				assert(pwrite(activation_fd, &bad_activation_tail, 1,
				    127) == 1 && fsync(activation_fd) == 0);
				assert(destination_inbound.load_import_activation(reserved_cut,
				    destination_session, 100, 200, "guest-b") == -1 &&
				    errno == EPROTO);
				assert(destination_inbound.
				    record_activated_import_consumer_result(reserved_cut,
				    destination_session, 100, 200, "guest-b",
				    committed_result) == -1 && errno == EPROTO);
				assert(destination_inbound.load_activated_import_view(
				    reserved_cut, destination_session, 100, 200,
				    "guest-b", activated_entries, activated_results) == -1 &&
				    errno == EPROTO && activated_entries.empty() &&
				    activated_results.empty());
				assert(destination_inbound.load_activated_import_recipient(
				    reserved_cut.token, exact_ingress.session_id,
				    exact_ingress.delivery_id, consumer.session_id,
				    (uint32_t)consumer.peer_uid,
				    (uint32_t)consumer.peer_pid, exact_import) == -1 &&
				    errno == EPROTO);
				assert(pwrite(activation_fd, &activation_tail, 1, 127) == 1 &&
				    fsync(activation_fd) == 0 && close(activation_fd) == 0);
				assert(destination_inbound.load_import_activation(reserved_cut,
				    destination_session, 100, 200, "guest-b") == 1);
				std::string activation_held_commit =
				    std::string(hlc1_name) + ".activation-held";
				assert(renameat(destination_inbound.dirfd, hlc1_name,
				    destination_inbound.dirfd,
				    activation_held_commit.c_str()) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				assert(destination_inbound.load_import_activation(reserved_cut,
				    destination_session, 100, 200, "guest-b") == -1 &&
				    errno == EPROTO);
				assert(renameat(destination_inbound.dirfd,
				    activation_held_commit.c_str(),
				    destination_inbound.dirfd, hlc1_name) == 0 &&
				    fsync(destination_inbound.dirfd) == 0);
				dirent committed_file{};
				strcpy(committed_file.d_name, spool_name.c_str());
				const size_t committed_jobs = transfer_host.joblist.size();
				assert(process_inbound(destination_inbound,
				    &committed_file) &&
				    transfer_host.joblist.size() == committed_jobs);
				transfer_host.inbounddir = &transfer_inbound;
				transfer_host.outbounddir = &transfer_outbound;
			}
			DIR *dest_scan = opendir(transfer_dest);
			assert(dest_scan != nullptr);
			struct dirent *dest_entry;
			while ((dest_entry = readdir(dest_scan)) != nullptr)
				if (strcmp(dest_entry->d_name, ".") != 0 &&
				    strcmp(dest_entry->d_name, "..") != 0) {
					std::string path = std::string(transfer_dest) +
					    "/" + dest_entry->d_name;
					assert(unlink(path.c_str()) == 0);
				}
			assert(closedir(dest_scan) == 0 &&
			    rmdir(transfer_dest) == 0);
			dest_scan = opendir(transfer_dest_out);
			assert(dest_scan != nullptr);
			while ((dest_entry = readdir(dest_scan)) != nullptr)
				if (strcmp(dest_entry->d_name, ".") != 0 &&
				    strcmp(dest_entry->d_name, "..") != 0) {
					std::string path = std::string(transfer_dest_out) +
					    "/" + dest_entry->d_name;
					assert(unlink(path.c_str()) == 0);
				}
			assert(closedir(dest_scan) == 0 &&
			    rmdir(transfer_dest_out) == 0);
			/* Exercise the attested request path with a complete two-member
			 * HTX1. The ACK must mean that only pending records are durable. */
			char endpoint_in[] =
			    "/tmp/hypertrace-import-endpoint-in.XXXXXX";
			char endpoint_out[] =
			    "/tmp/hypertrace-import-endpoint-out.XXXXXX";
			assert(mkdtemp(endpoint_in) != nullptr &&
			    mkdtemp(endpoint_out) != nullptr);
			{
				dir inbound_endpoint(endpoint_in, &process_inbound);
				dir outbound_endpoint(endpoint_out, &process_outbound);
				transfer_host.inbounddir = &inbound_endpoint;
				transfer_host.outbounddir = &outbound_endpoint;
				inbound_endpoint.state = &transfer_host;
				outbound_endpoint.state = nullptr;
				durable_handoff prepared_cut = reserved_cut;
				prepared_cut.checkpoint_digest.fill(0);
				prepared_cut.destination_vmid = 0;
				prepared_cut.destination_epoch = 0;
				durable_handoff committed_cut = reserved_cut;
				committed_cut.destination_vmid = 0;
				committed_cut.destination_epoch = 0;
				assert(outbound_endpoint.prepare_handoff(prepared_cut, false));
				assert(outbound_endpoint.commit_handoff(committed_cut));
				assert(outbound_endpoint.record_source_release(committed_cut));
				assert(outbound_endpoint.reserve_handoff(reserved_cut));
				outbound_endpoint.state = &transfer_host;
				int endpoint_sockets[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    endpoint_sockets) == 0);
				dtd_initmsg_t destination_hello = hello;
				memcpy(destination_hello.session_id,
				    destination_session.data(), 16);
				strlcpy(destination_hello.ident, "guest-b",
				    sizeof(destination_hello.ident));
				const int old_attestation_fd = attestation_fd;
				const auto old_identity = identity;
				{
					client_fd destination(kq,
					    endpoint_sockets[0], destination_hello);
					attestation_fd = destination.vm_attestation_fd =
					    dup(endpoint_sockets[0]);
					assert(attestation_fd >= 0);
					destination.vmid = identity.vmid = 8;
					destination.vm_epoch = identity.epoch = 43;
					strlcpy(identity.name, "guest-b",
					    sizeof(identity.name));
					std::vector<uint8_t> body(
					    DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
					    transfer_wire.size());
					memcpy(body.data(), reserved_cut.token.data(), 16);
					memcpy(body.data() + 16,
					    reserved_cut.checkpoint_digest.data(), 32);
					memcpy(body.data() +
					    DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
					    transfer_wire.data(), transfer_wire.size());
					dtraced_hdr_t import_header{};
					import_header.msg_type =
					    DTRACED_MSG_HANDOFF_IMPORT;
					std::vector<uint8_t> alternate_bundle;
					assert(dtraced_transfer_wire_build(
					    reserved_cut.token.data(), {}, {}, alternate_bundle));
					std::vector<uint8_t> alternate_body(
					    DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
					    alternate_bundle.size());
					memcpy(alternate_body.data(), body.data(),
					    DTRACED_HANDOFF_IMPORT_BINDING_SIZE);
					memcpy(alternate_body.data() +
					    DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
					    alternate_bundle.data(), alternate_bundle.size());
					client_request alternate_request(transfer_host,
					    import_header, alternate_body.data(),
					    alternate_body.size(), &destination);
					assert(!alternate_request.handle() && errno == EPROTO);
					client_request no_owner_request(transfer_host,
					    import_header, body.data(), body.size(),
					    &destination);
					assert(!no_owner_request.handle() && errno == EBUSY);
					transfer_host.sockfds.insert(&consumer);
					assert(inbound_endpoint.queue_recovered_consumer(
					    &consumer) == 0);
					for (unsigned retry = 0; retry < 2; retry++) {
						client_request request(transfer_host,
						    import_header, body.data(),
						    body.size(), &destination);
						assert(request.handle());
					}
					std::vector<std::array<uint8_t, 32>>
					    imported_identities;
					assert(inbound_endpoint.load_import_promotion_intent(
					    reserved_cut, destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, "guest-b",
					    imported_identities) == 1 &&
					    imported_identities.size() == 2);
					host_ingress_destination_plan imported;
					assert(inbound_endpoint.
					    load_host_ingress_destination_stage(
					    reserved_cut, destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", imported) == 1 &&
					    imported.deliveries.size() == 2);
					for (const auto &delivery : imported.deliveries)
						assert(inbound_endpoint.delivery_status(
						    delivery) ==
						    (int)delivery_phase::pending &&
						    inbound_endpoint.
						    verify_host_ingress_payload(delivery) == 1);
					/* A record advanced to accepted cannot be cancelled.
					 * Restore the phase and simulate a crash after one spool
					 * deletion before retrying the pending-only rollback. */
					const auto &first = imported.deliveries[0];
					static const char digits[] =
					    "0123456789abcdef";
					char session_hex[33], program_hex[33],
					    source_hex[33];
					for (unsigned i = 0; i < 16; i++) {
						session_hex[i * 2] =
						    digits[first.session_id[i] >> 4];
						session_hex[i * 2 + 1] =
						    digits[first.session_id[i] & 15];
						program_hex[i * 2] =
						    digits[first.program_id[i] >> 4];
						program_hex[i * 2 + 1] =
						    digits[first.program_id[i] & 15];
						source_hex[i * 2] =
						    digits[first.source_id[i] >> 4];
						source_hex[i * 2 + 1] =
						    digits[first.source_id[i] & 15];
					}
					session_hex[32] = program_hex[32] =
					    source_hex[32] = '\0';
					char pending_name[80], accepted_name[80],
					    spool_name[70];
					assert(snprintf(pending_name,
					    sizeof(pending_name),
					    ".delivery.%s.%016jx.p", session_hex,
					    (uintmax_t)first.delivery_id) > 0);
					assert(snprintf(accepted_name,
					    sizeof(accepted_name),
					    ".delivery.%s.%016jx.a", session_hex,
					    (uintmax_t)first.delivery_id) > 0);
					assert(snprintf(spool_name,
					    sizeof(spool_name), "elf.%s.%s",
					    program_hex, source_hex) > 0);
					assert(renameat(inbound_endpoint.dirfd,
					    pending_name, inbound_endpoint.dirfd,
					    accepted_name) == 0 &&
					    fsync(inbound_endpoint.dirfd) == 0);
					assert(!outbound_endpoint.
					    cancel_handoff_reservation(reserved_cut) &&
					    errno == EBUSY);
					assert(renameat(inbound_endpoint.dirfd,
					    accepted_name, inbound_endpoint.dirfd,
					    pending_name) == 0 &&
					    fsync(inbound_endpoint.dirfd) == 0);
					assert(unlinkat(inbound_endpoint.dirfd,
					    spool_name, 0) == 0 &&
					    fsync(inbound_endpoint.dirfd) == 0);
					assert(outbound_endpoint.
					    cancel_handoff_reservation(reserved_cut));
					transfer_host.sockfds.erase(&consumer);
					assert(outbound_endpoint.
					    cancel_handoff_reservation(reserved_cut));
					for (const auto &delivery : imported.deliveries)
						assert(inbound_endpoint.delivery_status(
						    delivery) == 0);
					host_ingress_destination_plan removed;
					assert(inbound_endpoint.
					    load_host_ingress_destination_stage(
					    reserved_cut, destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", removed) == 0);
					/* Cancellation between stage and pending import also
					 * removes the inert sidecar before releasing the ticket. */
					assert(outbound_endpoint.reserve_handoff(
					    reserved_cut));
					assert(inbound_endpoint.
					    stage_host_ingress_destination_wire_reserved(
					    reserved_cut, alternate_bundle,
					    destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", removed) == -1 &&
					    errno == EPROTO && removed.deliveries.empty());
					assert(inbound_endpoint.
					    stage_host_ingress_destination_wire_reserved(
					    reserved_cut, transfer_wire,
					    destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", removed) == 1);
					assert(outbound_endpoint.
					    cancel_handoff_reservation(reserved_cut));
					assert(!inbound_endpoint.
					    import_host_ingress_pending(reserved_cut,
					    destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b") && errno == EBUSY);
					assert(inbound_endpoint.
					    load_host_ingress_destination_stage(
					    reserved_cut, destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", removed) == 0);
					for (unsigned race = 0; race < 4; race++) {
						assert(outbound_endpoint.reserve_handoff(
						    reserved_cut));
						std::atomic<bool> start{false};
						int stage_result = -2, stage_error = 0;
						bool cancelled = false;
						std::thread staging([&] {
							while (!start.load())
								std::this_thread::yield();
							host_ingress_destination_plan race_plan;
							stage_result = inbound_endpoint.
							    stage_host_ingress_destination_wire_reserved(
							    reserved_cut, transfer_wire,
							    destination_session,
							    (uint32_t)destination.peer_uid,
							    (uint32_t)destination.peer_pid,
							    "guest-b", race_plan);
							stage_error = errno;
						});
						std::thread cancelling([&] {
							while (!start.load())
								std::this_thread::yield();
							cancelled = outbound_endpoint.
							    cancel_handoff_reservation(reserved_cut);
						});
						start.store(true);
						staging.join();
						cancelling.join();
						assert(cancelled &&
						    (stage_result == 1 ||
						    (stage_result == -1 &&
						    stage_error == EBUSY)));
						assert(inbound_endpoint.
						    load_host_ingress_destination_stage(
						    reserved_cut, destination_session,
						    (uint32_t)destination.peer_uid,
						    (uint32_t)destination.peer_pid,
						    "guest-b", removed) == 0);
					}
					assert(inbound_endpoint.
					    stage_host_ingress_destination_wire_reserved(
					    reserved_cut, transfer_wire,
					    destination_session,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid,
					    "guest-b", removed) == -1 &&
					    errno == EBUSY && removed.deliveries.empty());
					assert(outbound_endpoint.reserve_handoff(
					    reserved_cut));
					transfer_host.sockfds.insert(&consumer);
					assert(inbound_endpoint.queue_recovered_consumer(
					    &consumer) == 0);
					client_request claimed_import(transfer_host,
					    import_header, body.data(), body.size(),
					    &destination);
					assert(claimed_import.handle());
					dtraced_handoff_request_t promote{};
					promote.op = DTRACED_HANDOFF_PROMOTE_IMPORT;
					memcpy(promote.token, reserved_cut.token.data(), 16);
					memcpy(promote.digest,
					    reserved_cut.checkpoint_digest.data(), 32);
					dtraced_hdr_t promote_header{};
					promote_header.msg_type = DTRACED_MSG_HANDOFF;
					client_request early_promotion(transfer_host,
					    promote_header, (unsigned char *)&promote,
					    sizeof(promote), &destination);
					assert(!early_promotion.handle() && errno == EBUSY);
					assert(outbound_endpoint.begin_handoff_mutation(
					    reserved_cut));
					assert(outbound_endpoint.claim_handoff(reserved_cut));
					promote.digest[0] ^= 1;
					client_request wrong_promotion(transfer_host,
					    promote_header, (unsigned char *)&promote,
					    sizeof(promote), &destination);
					assert(!wrong_promotion.handle() && errno == EPROTO);
					promote.digest[0] ^= 1;
					client_request accepted_promotion(transfer_host,
					    promote_header, (unsigned char *)&promote,
					    sizeof(promote), &destination);
					assert(accepted_promotion.handle());
					for (const auto &delivery : imported.deliveries)
						assert(inbound_endpoint.delivery_status(
						    delivery) ==
						    (int)delivery_phase::accepted);
					transfer_host.sockfds.erase(&consumer);
					client_request retried_promotion(transfer_host,
					    promote_header, (unsigned char *)&promote,
					    sizeof(promote), &destination);
					assert(retried_promotion.handle());
				}
				attestation_fd = old_attestation_fd;
				identity = old_identity;
				assert(close(endpoint_sockets[1]) == 0);
				transfer_host.inbounddir = &transfer_inbound;
				transfer_host.outbounddir = &transfer_outbound;
			}
			for (const char *directory : {endpoint_in, endpoint_out}) {
				DIR *scan = opendir(directory);
				assert(scan != nullptr);
				struct dirent *entry;
				while ((entry = readdir(scan)) != nullptr)
					if (strcmp(entry->d_name, ".") != 0 &&
					    strcmp(entry->d_name, "..") != 0) {
						std::string path = std::string(directory) +
						    "/" + entry->d_name;
						assert(unlink(path.c_str()) == 0);
					}
				assert(closedir(scan) == 0 && rmdir(directory) == 0);
			}
			/* A combined HJM1 carries the same accepted ingress as a
			 * nested HTM2/HCP1 part. Its ACK certifies durable pending
			 * receipts, spools, and owner sidecars, not execution. */
			{
				char combined_in[] =
				    "/tmp/hypertrace-combined-import-in.XXXXXX";
				char combined_out[] =
				    "/tmp/hypertrace-combined-import-out.XXXXXX";
				assert(mkdtemp(combined_in) != nullptr &&
				    mkdtemp(combined_out) != nullptr);
				{
					dir inbound_combined(combined_in, &process_inbound);
					dir outbound_combined(combined_out, &process_outbound);
					transfer_host.inbounddir = &inbound_combined;
					transfer_host.outbounddir = &outbound_combined;
					inbound_combined.state = &transfer_host;
					outbound_combined.state = nullptr;
					source_journal_cut empty_journal;
					std::vector<uint8_t> archive, combined_manifest,
					    combined_wire;
					std::vector<std::vector<uint8_t>> combined_frames;
					assert(dir::encode_source_journal_archive(
					    transfer_cut, empty_journal, archive) &&
					    dtraced_transfer_journal_wrap(
					    transfer_cut.token.data(), program_manifest,
					    frames, archive, combined_manifest,
					    combined_frames) &&
					    dtraced_transfer_wire_build(
					    transfer_cut.token.data(), combined_manifest,
					    combined_frames, combined_wire));
					durable_handoff combined_ticket = reserved_cut;
					memcpy(combined_ticket.transfer_digest.data(),
					    combined_wire.data() + combined_wire.size() - 32, 32);
					durable_handoff combined_prepared = combined_ticket;
					combined_prepared.checkpoint_digest.fill(0);
					combined_prepared.destination_vmid = 0;
					combined_prepared.destination_epoch = 0;
					durable_handoff combined_committed = combined_ticket;
					combined_committed.destination_vmid = 0;
					combined_committed.destination_epoch = 0;
					assert(outbound_combined.prepare_handoff(
					    combined_prepared, false) &&
					    outbound_combined.commit_handoff(
					    combined_committed) &&
					    outbound_combined.record_source_release(
					    combined_committed) &&
					    outbound_combined.reserve_handoff(
					    combined_ticket));
					outbound_combined.state = &transfer_host;
					int sockets[2];
					assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
					    sockets) == 0);
					dtd_initmsg_t destination_hello = hello;
					memcpy(destination_hello.session_id,
					    destination_session.data(), 16);
					strlcpy(destination_hello.ident, "guest-b",
					    sizeof(destination_hello.ident));
					const int old_attestation_fd = attestation_fd;
					const auto old_identity = identity;
					{
						client_fd destination(kq, sockets[0],
						    destination_hello);
						attestation_fd = destination.vm_attestation_fd =
						    dup(sockets[0]);
						assert(attestation_fd >= 0);
						destination.vmid = identity.vmid = 8;
						destination.vm_epoch = identity.epoch = 43;
						strlcpy(identity.name, "guest-b",
						    sizeof(identity.name));
						std::vector<uint8_t> body(
						    DTRACED_HANDOFF_IMPORT_BINDING_SIZE +
						    combined_wire.size());
						memcpy(body.data(), combined_ticket.token.data(),
						    16);
						memcpy(body.data() + 16,
						    combined_ticket.checkpoint_digest.data(), 32);
						memcpy(body.data() +
						    DTRACED_HANDOFF_IMPORT_BINDING_SIZE,
						    combined_wire.data(), combined_wire.size());
						dtraced_hdr_t header{};
						header.msg_type = DTRACED_MSG_HANDOFF_IMPORT;
						client_request waiting(transfer_host, header,
						    body.data(), body.size(), &destination);
						assert(!waiting.handle() && errno == EBUSY &&
						    outbound_combined.populate_existing() &&
						    inbound_combined.populate_existing());
						transfer_host.sockfds.insert(&consumer);
						assert(inbound_combined.queue_recovered_consumer(
						    &consumer) == 0);
						consumer.consumer_program_digest[0] ^= 1;
						client_request wrong_program(transfer_host,
						    header, body.data(), body.size(), &destination);
						assert(!wrong_program.handle() && errno == EPROTO);
						consumer.consumer_program_digest[0] ^= 1;
						for (unsigned retry = 0; retry < 2; retry++) {
							client_request request(transfer_host,
							    header, body.data(), body.size(),
							    &destination);
							assert(request.handle());
						}
						assert(outbound_combined.populate_existing() &&
						    inbound_combined.populate_existing());
						std::vector<std::array<uint8_t, 76>> owners;
						assert(inbound_combined.
						    load_host_ingress_consumer_owners(
						    combined_ticket, destination_session,
						    (uint32_t)destination.peer_uid,
						    (uint32_t)destination.peer_pid,
						    "guest-b", owners) == 1 &&
						    owners.size() == 1 &&
						    memcmp(owners[0].data() + 4,
						    consumer.session_id.data(), 16) == 0);
						source_journal_destination_plan journal_plan;
						assert(outbound_combined.
						    source_journal_pending_status(
						    combined_ticket, destination_session,
						    (uint32_t)destination.peer_uid,
						    (uint32_t)destination.peer_pid,
						    journal_plan) == 2 &&
						    journal_plan.has_ingress &&
						    journal_plan.deliveries.empty());
						host_ingress_destination_plan imported;
						assert(inbound_combined.
						    load_host_ingress_destination_stage(
						    combined_ticket, destination_session,
						    (uint32_t)destination.peer_uid,
						    (uint32_t)destination.peer_pid,
						    "guest-b", imported) == 1 &&
						    imported.deliveries.size() == 2 &&
						    imported.source_programs.size() == 2);
						for (const auto &delivery : imported.deliveries)
							assert(inbound_combined.delivery_status(
							    delivery) ==
							    (int)delivery_phase::pending &&
							    inbound_combined.verify_host_ingress_payload(
							    delivery) == 1);
						durable_handoff still_reserved{};
						assert(!outbound_combined.
						    begin_handoff_mutation(combined_ticket) &&
						    errno == EOPNOTSUPP &&
						    outbound_combined.handoff_status(
						    combined_ticket.token, still_reserved) ==
						    (int)handoff_phase::reserved);
						assert(outbound_combined.
						    cancel_handoff_reservation(combined_ticket));
						transfer_host.sockfds.erase(&consumer);
						for (const auto &delivery : imported.deliveries)
							assert(inbound_combined.delivery_status(
							    delivery) == 0);
					}
					attestation_fd = old_attestation_fd;
					identity = old_identity;
					assert(close(sockets[1]) == 0);
					transfer_host.inbounddir = &transfer_inbound;
					transfer_host.outbounddir = &transfer_outbound;
				}
				for (const char *directory : {combined_in, combined_out}) {
					DIR *scan = opendir(directory);
					assert(scan != nullptr);
					for (dirent *entry;
					    (entry = readdir(scan)) != nullptr; )
						if (strcmp(entry->d_name, ".") != 0 &&
						    strcmp(entry->d_name, "..") != 0)
							assert(unlinkat(dirfd(scan),
							    entry->d_name, 0) == 0);
					assert(closedir(scan) == 0 && rmdir(directory) == 0);
				}
			}
			frames.pop_back();
			assert(!dir::decode_host_ingress_transfer_bundle(
			    transfer_cut, both, frames, bundle) && errno == EPROTO &&
			    bundle.entries.empty() && bundle.payloads.empty());
			frames.push_back(later_frame);
			frames.push_back(later_frame);
			assert(!dir::decode_host_ingress_transfer_bundle(
			    transfer_cut, both, frames, bundle) && errno == EPROTO &&
			    bundle.entries.empty() && bundle.payloads.empty());
			frames.pop_back();
			std::swap(frames[0], frames[1]);
			assert(!dir::decode_host_ingress_transfer_bundle(
			    transfer_cut, both, frames, bundle) && errno == EPROTO &&
			    bundle.entries.empty() && bundle.payloads.empty());
			std::swap(frames[0], frames[1]);
			frames[1].back() ^= 1;
			assert(!dir::decode_host_ingress_transfer_bundle(
			    transfer_cut, both, frames, bundle) && errno == EPROTO &&
			    bundle.entries.empty() && bundle.payloads.empty());
			frames[1].back() ^= 1;
			assert(!dir::decode_host_ingress_transfer_bundle(
			    wrong_ticket, both, frames, bundle) && errno == EPROTO &&
			    bundle.entries.empty() && bundle.payloads.empty());
			changed_manifest = both;
			memcpy(changed_manifest.data() + 50 + 143 + 4 + 159,
			    changed_manifest.data() + 50, 143 + 4 + 159);
			assert(SHA256(changed_manifest.data(),
			    changed_manifest.size() - 32,
			    changed_manifest.data() + changed_manifest.size() - 32));
			assert(!dir::validate_host_ingress_transfer_manifest(
			    transfer_cut, changed_manifest, &decoded) &&
			    errno == EPROTO && decoded.empty());
			int owner_scanfd = openat(transfer_inbound.dirfd, ".",
			    O_RDONLY | O_DIRECTORY);
			assert(owner_scanfd >= 0);
			DIR *owner_scan = fdopendir(owner_scanfd);
			assert(owner_scan != nullptr);
			std::string owner_name;
			while (dirent *entry = readdir(owner_scan))
				if (strncmp(entry->d_name, ".owner.", 7) == 0 &&
				    strncmp(entry->d_name, ".owner.tmp.", 11) != 0)
					owner_name = entry->d_name;
			assert(closedir(owner_scan) == 0 && !owner_name.empty());
			assert(renameat(transfer_inbound.dirfd, owner_name.c_str(),
			    transfer_inbound.dirfd, ".owner.hidden") == 0 &&
			    fsync(transfer_inbound.dirfd) == 0);
			bundle_manifest.clear();
			bundle_frames.clear();
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames) == -1 &&
			    errno == EBUSY && bundle_manifest.empty() &&
			    bundle_frames.empty());
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames, true) == 1 &&
			    bundle_manifest == program_manifest &&
			    bundle_frames.size() == 2);
			assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
			    errno == EOPNOTSUPP);
			assert(renameat(transfer_inbound.dirfd, ".owner.hidden",
			    transfer_inbound.dirfd, owner_name.c_str()) == 0 &&
			    fsync(transfer_inbound.dirfd) == 0);
			int owner_fd = openat(transfer_inbound.dirfd,
			    owner_name.c_str(), O_RDWR | O_NOFOLLOW);
			assert(owner_fd >= 0);
			std::array<uint8_t, 76> original_owner{}, altered_owner{};
			assert(pread(owner_fd, original_owner.data(),
			    original_owner.size(), 0) ==
			    (ssize_t)original_owner.size());
			altered_owner = original_owner;
			dtraced_wire_put_u32(altered_owner.data() + 20,
			    dtraced_wire_get_u32(original_owner.data() + 20) + 1);
			assert(SHA256(altered_owner.data(), 44,
			    altered_owner.data() + 44) != nullptr);
			assert(pwrite(owner_fd, altered_owner.data(),
			    altered_owner.size(), 0) ==
			    (ssize_t)altered_owner.size() && fsync(owner_fd) == 0);
			bundle_manifest.clear();
			bundle_frames.clear();
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames) == -1 &&
			    errno == EPROTO && bundle_manifest.empty() &&
			    bundle_frames.empty());
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames, true) == 1 &&
			    bundle_manifest == program_manifest &&
			    bundle_frames.size() == 2);
			assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
			    errno == EOPNOTSUPP);
			assert(pwrite(owner_fd, original_owner.data(),
			    original_owner.size(), 0) ==
			    (ssize_t)original_owner.size() && fsync(owner_fd) == 0);
			altered_owner = original_owner;
			altered_owner[28] ^= 1;
			assert(SHA256(altered_owner.data(), 44,
			    altered_owner.data() + 44) != nullptr);
			assert(pwrite(owner_fd, altered_owner.data(),
			    altered_owner.size(), 0) ==
			    (ssize_t)altered_owner.size() && fsync(owner_fd) == 0);
			bundle_manifest.clear();
			bundle_frames.clear();
			assert(transfer_inbound.host_ingress_transfer_bundle_export(
			    transfer_cut, bundle_manifest, bundle_frames, true) == 1 &&
			    bundle_manifest == program_manifest &&
			    bundle_frames.size() == 2);
			assert(pwrite(owner_fd, original_owner.data(),
			    original_owner.size(), 0) ==
			    (ssize_t)original_owner.size() && fsync(owner_fd) == 0 &&
			    close(owner_fd) == 0);
			transfer_cut.transfer_digest[0] ^= 1;
			assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
			    errno == EPROTO);
			transfer_cut.transfer_digest[0] ^= 1;
			assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
			    errno == EOPNOTSUPP);
            durable_handoff absent{};
            assert(transfer_outbound.handoff_status(transfer_cut.token,
                absent) == 0);
			/* A terminal D in HTM1 is insufficient when its durable
			 * derived claim and outbound publication are missing. */
			durable_delivery unproven = second;
			unproven.delivery_id = 97;
			unproven.program_id[0] = 0xad;
			unproven.source_id[0] = 0xbe;
			assert(transfer_inbound.write_identified_data(payload.data(),
			    payload.size(), unproven.program_id.data(), nullptr,
			    unproven.source_id.data()));
			assert(transfer_inbound.record_delivery(unproven,
			    delivery_phase::pending, true) &&
			    transfer_inbound.record_delivery(unproven,
			    delivery_phase::accepted));
			durable_consumer_receipt unproven_recipient = recipient;
			unproven_recipient.ingress = unproven;
			fixed.clear();
			assert(transfer_inbound.consumer_cohort(unproven,
			    {unproven_recipient}, fixed) == 1);
			assert(transfer_inbound.record_consumer_receipt(
			    unproven_recipient, consumer_receipt_phase::pending) ==
			    (int)consumer_receipt_phase::pending);
			assert(transfer_inbound.record_consumer_receipt(
			    unproven_recipient, consumer_receipt_phase::derived) ==
			    (int)consumer_receipt_phase::derived);
			assert(transfer_inbound.record_consumer_receipt(
			    unproven_recipient,
			    consumer_receipt_phase::executed_derived) ==
			    (int)consumer_receipt_phase::executed_derived);
			assert(!transfer_outbound.prepare_handoff(transfer_cut, false) &&
			    errno == EPROTO);
			assert(transfer_outbound.handoff_status(transfer_cut.token,
			    absent) == 0);
			std::vector<uint8_t> unproven_manifest;
			assert(transfer_inbound.host_ingress_transfer_manifest(
			    transfer_cut, unproven_manifest) == 1);
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, unproven_manifest, 0, exported) == -1 &&
			    errno == EPROTO && exported.empty());
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    transfer_cut, audited_manifest) == -1 &&
			    errno == EPROTO && audited_manifest.empty());
			/* Once committed, source export is closed even when the old
			 * manifest and spool remain available on disk. */
			transfer_outbound.state = nullptr;
			assert(transfer_outbound.prepare_handoff(transfer_cut, false));
			durable_handoff committed_cut = transfer_cut;
			committed_cut.checkpoint_digest[0] = 1;
			assert(transfer_outbound.commit_handoff(committed_cut));
			transfer_outbound.state = &transfer_host;
			assert(transfer_outbound.record_source_release(committed_cut));
			assert(transfer_inbound.host_ingress_transfer_snapshot(
			    transfer_cut, audited_manifest) == -1 &&
			    errno == EBUSY && audited_manifest.empty());
			assert(transfer_inbound.host_ingress_transfer_frame(
			    transfer_cut, both, 0, exported) == -1 &&
			    errno == EBUSY && exported.empty());
        }
        for (const char *directory : {transfer_in, transfer_out}) {
            DIR *scan = opendir(directory);
            assert(scan != nullptr);
            dirent *entry;
            while ((entry = readdir(scan)) != nullptr)
                if (strcmp(entry->d_name, ".") != 0 &&
                    strcmp(entry->d_name, "..") != 0) {
                    std::string file = std::string(directory) + "/" +
                        entry->d_name;
                    assert(unlink(file.c_str()) == 0);
                }
            assert(closedir(scan) == 0 && rmdir(directory) == 0);
        }
    }
    durable_consumer_receipt execution_target{};
    for (uint64_t i = 0; i < 24; ++i) {
        durable_delivery added = *base;
        added.delivery_id = 1000 + i;
        added.program_id[1] = (uint8_t)(i + 1);
        added.source_id[1] = (uint8_t)(i + 1);
        assert(inbound.record_delivery(added, delivery_phase::pending,
            true));
        assert(inbound.record_delivery(added, delivery_phase::accepted));
        durable_consumer_receipt receipt{};
        receipt.ingress = added;
        receipt.consumer_session = consumer.session_id;
        receipt.consumer_uid = 0;
        receipt.consumer_pid = 2;
        if (i == 2) {
            receipt.consumer_uid = (uint32_t)consumer.peer_uid;
            receipt.consumer_pid = (uint32_t)consumer.peer_pid;
            execution_target = receipt;
        }
        assert(inbound.record_consumer_receipt(receipt,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        if (i == 2)
            assert(inbound.record_consumer_program(receipt, consumer) == 1);
        if (i == 0) {
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::no_derived) ==
                (int)consumer_receipt_phase::no_derived);
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::executed_no_derived) ==
                (int)consumer_receipt_phase::executed_no_derived);
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::no_derived) ==
                (int)consumer_receipt_phase::executed_no_derived);
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::executed_no_derived) ==
                (int)consumer_receipt_phase::executed_no_derived);
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::derived) == -1 &&
                errno == EPROTO);
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::executed_derived) == -1 &&
                errno == EPROTO);
        } else if (i == 1) {
            assert(inbound.record_consumer_receipt(receipt,
                consumer_receipt_phase::executed_derived) == -1 &&
                errno == EPROTO);
        }
    }
    {
        std::vector<durable_consumer_receipt_state> receipts;
        assert(inbound.list_consumer_receipts(receipts));
        for (uint64_t i = 0; i < 24; ++i) {
            bool found = false;
            for (const auto &receipt : receipts)
                if (receipt.record.ingress.delivery_id == 1000 + i) {
                    assert(receipt.record.ingress.program_id[1] == i + 1 &&
                        receipt.record.ingress.source_id[1] == i + 1 &&
                        receipt.phase == (i == 0 ?
                        consumer_receipt_phase::executed_no_derived :
                        consumer_receipt_phase::pending));
                    assert(!found);
                    found = true;
                }
            assert(found);
        }
    }
    {
        int execution_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
            execution_sockets) == 0);
        dtd_initmsg_t execution_hello = consumer_hello;
        execution_hello.subs = DTD_SUB_READDATA;
        client_fd executor(kq, execution_sockets[0], execution_hello);
        dtraced_hdr_t execution_header{};
        execution_header.msg_type = DTRACED_MSG_CONSUMER_EXECUTION;
        execution_header.elf.len = DTRACED_CONSUMER_EXECUTION_WIRE_SIZE;
        dtraced_consumer_ack_t execution{};
        execution.delivery_id = execution_target.ingress.delivery_id;
        execution.vmid = execution_target.ingress.vmid;
        execution.epoch = execution_target.ingress.epoch;
        memcpy(execution.program_id,
            execution_target.ingress.program_id.data(), 16);
        memcpy(execution.source_id,
            execution_target.ingress.source_id.data(), 16);
        memcpy(execution.ingress_session,
            execution_target.ingress.session_id.data(), 16);
        execution.outcome = DTRACED_CONSUMER_ACK_NO_DERIVED;
        unsigned char wire[DTRACED_CONSUMER_EXECUTION_WIRE_SIZE];
        dtraced_wire_encode_consumer_execution(wire, &execution);
        durable_consumer_receipt_state exact{};
        assert(inbound.consumer_receipt_exact(
            execution_target.ingress.session_id,
            execution_target.ingress.delivery_id,
            consumer.session_id, (uint32_t)consumer.peer_uid,
            (uint32_t)consumer.peer_pid, exact) == 1 &&
            exact.phase == consumer_receipt_phase::pending);
        {
            std::lock_guard clients(host.sockfdsmtx);
            host.sockfds.insert(&consumer);
        }
        consumer.consumer_replay_pending = true;
        client_request not_replayed(host, execution_header, wire,
            sizeof(wire), &executor);
        assert(!not_replayed.handle() && errno == EAGAIN);
        consumer.consumer_replay_pending = false;
        consumer.consumer_birth[0] ^= 1;
        client_request wrong_birth(host, execution_header, wire,
            sizeof(wire), &executor);
        assert(!wrong_birth.handle() && errno == EAGAIN &&
            receipt_phase(1002) == consumer_receipt_phase::pending);
        consumer.consumer_birth[0] ^= 1;
        consumer.consumer_program_digest[0] ^= 1;
        client_request wrong_program(host, execution_header, wire,
            sizeof(wire), &executor);
        assert(!wrong_program.handle() && errno == EAGAIN &&
            receipt_phase(1002) == consumer_receipt_phase::pending);
        consumer.consumer_program_digest[0] ^= 1;
        client_request first(host, execution_header, wire, sizeof(wire),
            &executor);
        assert(first.handle());
        assert(receipt_phase(1002) ==
            consumer_receipt_phase::executed_no_derived);
        /* Simulate death after HCE1 publication but before HCR1 rename.
         * Startup recovery must finish even when the receipt is pending. */
        std::string execution_receipt;
        DIR *scan = opendir(path);
        assert(scan != nullptr);
        dirent *entry;
        while ((entry = readdir(scan)) != nullptr)
            if (strncmp(entry->d_name, ".consumer.", 10) == 0 &&
                strstr(entry->d_name, ".00000000000003ea.") != nullptr &&
                entry->d_name[strlen(entry->d_name) - 1] == 'N')
                execution_receipt = entry->d_name;
        assert(closedir(scan) == 0 && !execution_receipt.empty());
        std::string pending_receipt = execution_receipt;
        pending_receipt.back() = 'p';
        assert(rename((std::string(path) + "/" + execution_receipt).c_str(),
            (std::string(path) + "/" + pending_receipt).c_str()) == 0);
        std::vector<durable_consumer_receipt_state> interrupted;
        assert(inbound.list_consumer_receipts(interrupted));
        assert(receipt_phase(1002) == consumer_receipt_phase::pending);
        assert(inbound.recover_consumer_executions(interrupted));
        assert(receipt_phase(1002) ==
            consumer_receipt_phase::executed_no_derived);
        assert(inbound.record_consumer_receipt(execution_target,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::executed_no_derived);
        durable_delivery collision = execution_target.ingress;
        collision.session_id[0] ^= 0x5a;
        assert(inbound.record_delivery(collision,
            delivery_phase::pending, true));
        assert(inbound.record_delivery(collision,
            delivery_phase::accepted));
        durable_consumer_receipt collision_rec = execution_target;
        collision_rec.ingress = collision;
        assert(inbound.record_consumer_receipt(collision_rec,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(collision_rec,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(inbound.consumer_receipt_exact(
            execution_target.ingress.session_id,
            execution_target.ingress.delivery_id,
            consumer.session_id, (uint32_t)consumer.peer_uid,
            (uint32_t)consumer.peer_pid, exact) == 1 &&
            exact.phase == consumer_receipt_phase::executed_no_derived);
        assert(inbound.consumer_receipt_exact(collision.session_id,
            collision.delivery_id, consumer.session_id,
            (uint32_t)consumer.peer_uid,
            (uint32_t)consumer.peer_pid, exact) == 1 &&
            exact.phase == consumer_receipt_phase::no_derived);
        {
            std::lock_guard clients(host.sockfdsmtx);
            host.sockfds.erase(&consumer);
        }
        client_request retired(host, execution_header, wire, sizeof(wire),
            &executor);
        assert(!retired.handle() && errno == EAGAIN);
        {
            std::lock_guard clients(host.sockfdsmtx);
            host.sockfds.insert(&consumer);
        }
        client_request retry(host, execution_header, wire, sizeof(wire),
            &executor);
        assert(retry.handle());
        execution.ingress_session[0] ^= 1;
        dtraced_wire_encode_consumer_execution(wire, &execution);
        client_request wrong_ingress(host, execution_header, wire,
            sizeof(wire), &executor);
        assert(!wrong_ingress.handle() && errno == ENOENT);
        execution.ingress_session[0] ^= 1;
        execution.outcome = DTRACED_CONSUMER_ACK_DERIVED;
        dtraced_wire_encode_consumer_execution(wire, &execution);
        client_request conflict(host, execution_header, wire,
            sizeof(wire), &executor);
        assert(!conflict.handle() && errno == EPROTO);
        {
            std::lock_guard clients(host.sockfdsmtx);
            host.sockfds.erase(&consumer);
        }
        assert(close(execution_sockets[1]) == 0);
    }
    /* HCB1 publishes the whole recipient set first. Restart must recreate
     * an HCR1 entry omitted by a crash between individual receipt writes. */
    {
        durable_delivery cohort_ingress = pending;
        cohort_ingress.delivery_id = 5000;
        cohort_ingress.program_id[0] = 0x31;
        cohort_ingress.source_id[0] = 0x32;
        assert(inbound.record_delivery(cohort_ingress,
            delivery_phase::pending, true));
        assert(inbound.record_delivery(cohort_ingress,
            delivery_phase::accepted));
        durable_consumer_receipt first{}, second{};
        first.ingress = second.ingress = cohort_ingress;
        first.consumer_session[0] = 0x44;
        second.consumer_session[0] = 0x45;
        first.consumer_uid = second.consumer_uid = 0;
        first.consumer_pid = second.consumer_pid = 2;
        std::vector<durable_consumer_receipt> fixed;
        assert(inbound.consumer_cohort(cohort_ingress, {second, first},
            fixed) == 1 && fixed.size() == 2 &&
            fixed[0].consumer_session == first.consumer_session &&
            fixed[1].consumer_session == second.consumer_session);
        assert(inbound.record_consumer_receipt(first,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        durable_consumer_receipt rogue = first;
        rogue.consumer_session[0] = 0x46;
        fixed.clear();
        assert(inbound.consumer_cohort(cohort_ingress, {rogue}, fixed) == 1 &&
            fixed.size() == 2 &&
            fixed[0].consumer_session == first.consumer_session);
        assert(inbound.record_consumer_receipt(rogue,
            consumer_receipt_phase::pending) == -1 && errno == EPROTO);
        dir restarted(path, &process_inbound);
        std::vector<durable_delivery_state> ingresses;
        std::vector<durable_consumer_receipt_state> receipts;
        assert(restarted.list_deliveries(ingresses));
        assert(restarted.recover_consumer_cohorts(ingresses));
        assert(restarted.list_consumer_receipts(receipts));
        unsigned members = 0;
        for (const auto &entry : receipts)
            if (entry.record.ingress.delivery_id == 5000) {
                assert(entry.phase == consumer_receipt_phase::pending &&
                    (entry.record.consumer_session == first.consumer_session ||
                    entry.record.consumer_session == second.consumer_session));
                members++;
            }
        assert(members == 2);
        assert(restarted.recover_consumer_cohorts(ingresses));
        int cohort_scanfd = openat(inbound.dirfd, ".",
            O_RDONLY | O_DIRECTORY);
        assert(cohort_scanfd >= 0);
        DIR *cohort_scan = fdopendir(cohort_scanfd);
        assert(cohort_scan != nullptr);
        std::string cohort_name;
        while (dirent *entry = readdir(cohort_scan))
            if (strncmp(entry->d_name, ".cohort.", 8) == 0 &&
                strncmp(entry->d_name, ".cohort.tmp.", 12) != 0 &&
                strstr(entry->d_name, ".0000000000001388") != nullptr)
                cohort_name = entry->d_name;
        assert(closedir(cohort_scan) == 0 && !cohort_name.empty());
        int cohort_fd = openat(inbound.dirfd, cohort_name.c_str(), O_RDWR);
        assert(cohort_fd >= 0);
        unsigned char original = 0, changed;
        assert(pread(cohort_fd, &original, 1, 8) == 1);
        changed = original ^ 1;
        assert(pwrite(cohort_fd, &changed, 1, 8) == 1 &&
            fsync(cohort_fd) == 0);
        fixed.clear();
        assert(restarted.consumer_cohort(cohort_ingress, {}, fixed) == -1 &&
            errno == EPROTO);
        assert(pwrite(cohort_fd, &original, 1, 8) == 1 &&
            fsync(cohort_fd) == 0 && close(cohort_fd) == 0);
        assert(restarted.consumer_cohort(cohort_ingress, {}, fixed) == 1 &&
            fixed.size() == 2);
        const char *orphan_hcr1 =
            ".consumer.tmp.00000000000000000000000000000000";
        const char *orphan_hcb1 =
            ".cohort.tmp.00000000000000000000000000000000";
        const char *orphan_hco1 =
            ".owner.tmp.00000000000000000000000000000000";
        int orphan_fd = openat(inbound.dirfd, orphan_hcr1,
            O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(orphan_fd >= 0 && write(orphan_fd, "x", 1) == 1 &&
            close(orphan_fd) == 0);
        orphan_fd = openat(inbound.dirfd, orphan_hcb1,
            O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(orphan_fd >= 0 && write(orphan_fd, "x", 1) == 1 &&
            close(orphan_fd) == 0);
        orphan_fd = openat(inbound.dirfd, orphan_hco1,
            O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(orphan_fd >= 0 && write(orphan_fd, "x", 1) == 1 &&
            close(orphan_fd) == 0);
        assert(restarted.populate_existing() &&
            !restarted.file_exists(orphan_hcr1) &&
            !restarted.file_exists(orphan_hcb1) &&
            !restarted.file_exists(orphan_hco1));
        int owner_scanfd = openat(inbound.dirfd, ".",
            O_RDONLY | O_DIRECTORY);
        assert(owner_scanfd >= 0);
        DIR *owner_scan = fdopendir(owner_scanfd);
        assert(owner_scan != nullptr);
        std::string owner_name;
        while (dirent *entry = readdir(owner_scan))
            if (strncmp(entry->d_name, ".owner.", 7) == 0 &&
                strncmp(entry->d_name, ".owner.tmp.", 11) != 0)
                owner_name = entry->d_name;
        assert(closedir(owner_scan) == 0 && !owner_name.empty());
        int owner_fd = openat(inbound.dirfd, owner_name.c_str(), O_RDWR);
        assert(owner_fd >= 0);
        unsigned char owner_byte, corrupted;
        assert(pread(owner_fd, &owner_byte, 1, 28) == 1);
        corrupted = owner_byte ^ 1;
        assert(pwrite(owner_fd, &corrupted, 1, 28) == 1 &&
            fsync(owner_fd) == 0);
        assert(!restarted.populate_existing());
        assert(pwrite(owner_fd, &owner_byte, 1, 28) == 1 &&
            fsync(owner_fd) == 0 && close(owner_fd) == 0);
        assert(restarted.populate_existing());
    }
    /* Even a genuinely reaped child is not durable daemon retirement proof.
     * Settled legacy receipts without HPE1/HRE1 must retain their old owner. */
    {
        pid_t old_pid = fork();
        assert(old_pid >= 0);
        if (old_pid == 0)
            _exit(0);
        int status;
        assert(waitpid(old_pid, &status, 0) == old_pid && WIFEXITED(status));
        durable_delivery restart_ingress = *base;
        restart_ingress.delivery_id = 6000;
        restart_ingress.program_id[2] = 0x5f;
        restart_ingress.source_id[2] = 0x6f;
        assert(inbound.record_delivery(restart_ingress,
            delivery_phase::pending, true));
        assert(inbound.record_delivery(restart_ingress,
            delivery_phase::accepted));
        durable_consumer_receipt old{};
        old.ingress = restart_ingress;
        old.consumer_session[0] = 0xf5;
        old.consumer_uid = (uint32_t)consumer.peer_uid;
        old.consumer_pid = (uint32_t)old_pid;
        std::vector<durable_consumer_receipt> cohort;
        assert(inbound.consumer_cohort(restart_ingress, {old}, cohort) == 1);
        assert(inbound.record_consumer_receipt(old,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(old,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(inbound.record_consumer_receipt(old,
            consumer_receipt_phase::executed_no_derived) ==
            (int)consumer_receipt_phase::executed_no_derived);
        int restart_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, restart_sockets) == 0);
        dtd_initmsg_t restart_hello = consumer_hello;
        memcpy(restart_hello.session_id, old.consumer_session.data(), 16);
        client_fd replacement(kq, restart_sockets[0], restart_hello);
        /* Model a previously accepted HPI1 program registration. */
        replacement.consumer_program_valid = true;
        replacement.consumer_program_digest = announced_program;
        state replacement_host{};
        state_attestation_test::set_control(replacement_host);
        dir replacement_inbound(path, &process_inbound);
        replacement_host.inbounddir = &replacement_inbound;
        replacement_inbound.state = &replacement_host;
        assert(replacement_inbound.queue_recovered_consumer(&replacement) == -1 && errno == EAGAIN);
        assert(replacement_host.joblist.empty());
        restart_ingress.delivery_id++;
        restart_ingress.program_id[2]++;
        assert(inbound.record_delivery(restart_ingress,
            delivery_phase::pending, true));
        assert(inbound.record_delivery(restart_ingress,
            delivery_phase::accepted));
        old.ingress = restart_ingress;
        cohort.clear();
        assert(inbound.consumer_cohort(restart_ingress, {old}, cohort) == 1);
        assert(inbound.record_consumer_receipt(old,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(old,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(replacement_inbound.queue_recovered_consumer(&replacement) == -1 &&
            (errno == EBUSY || errno == EAGAIN));
        assert(replacement_host.joblist.empty());
        close(restart_sockets[1]);
    }
    /* Reusing a numeric PID does not authorize rotation without immutable
     * old-incarnation retirement evidence, even for settled legacy receipts. */
    {
        state owner_host{};
        state_attestation_test::set_control(owner_host);
        dir owner_inbound(path, &process_inbound);
        owner_host.inbounddir = &owner_inbound;
        owner_inbound.state = &owner_host;
        dtd_initmsg_t owner_hello = consumer_hello;
        owner_hello.session_id[0] = 0xf6;
        int old_sockets[2], new_sockets[2], later_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, old_sockets) == 0);
        client_fd old_owner(kq, old_sockets[0], owner_hello);
        /* Model a previously accepted HPI1 program registration. */
        old_owner.consumer_program_valid = true;
        old_owner.consumer_program_digest = announced_program;
        assert(old_owner.consumer_birth_valid &&
            owner_inbound.queue_recovered_consumer(&old_owner) == 0);
        durable_delivery owned_ingress = *base;
        owned_ingress.delivery_id = 7000;
        owned_ingress.program_id[3] = 0x77;
        owned_ingress.source_id[3] = 0x88;
        assert(inbound.record_delivery(owned_ingress,
            delivery_phase::pending, true) &&
            inbound.record_delivery(owned_ingress,
            delivery_phase::accepted));
        durable_consumer_receipt owned_receipt{};
        owned_receipt.ingress = owned_ingress;
        owned_receipt.consumer_session = old_owner.session_id;
        owned_receipt.consumer_uid = (uint32_t)old_owner.peer_uid;
        owned_receipt.consumer_pid = (uint32_t)old_owner.peer_pid;
        std::vector<durable_consumer_receipt> fixed;
        assert(inbound.consumer_cohort(owned_ingress,
            {owned_receipt}, fixed) == 1);
        assert(inbound.record_consumer_receipt(owned_receipt,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(owned_receipt,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(inbound.record_consumer_receipt(owned_receipt,
            consumer_receipt_phase::executed_no_derived) ==
            (int)consumer_receipt_phase::executed_no_derived);
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, new_sockets) == 0);
        dtd_initmsg_t new_hello = owner_hello;
        new_hello.ident[strlen(new_hello.ident) - 1] = '3';
        client_fd new_owner(kq, new_sockets[0], new_hello);
        /* Model a previously accepted HPI1 program registration. */
        new_owner.consumer_program_valid = true;
        new_owner.consumer_program_digest = announced_program;
        assert(new_owner.consumer_birth_valid);
        new_owner.peer_uid++;
        assert(owner_inbound.queue_recovered_consumer(&new_owner) == -1 &&
            errno == EPERM);
        new_owner.peer_uid--;
        assert(
            owner_inbound.queue_recovered_consumer(&new_owner) == -1 && errno == EAGAIN);
        assert(owner_inbound.queue_recovered_consumer(&new_owner) == -1 && errno == EAGAIN);
        owned_ingress.delivery_id++;
        owned_ingress.program_id[3]++;
        assert(inbound.record_delivery(owned_ingress,
            delivery_phase::pending, true) &&
            inbound.record_delivery(owned_ingress,
            delivery_phase::accepted));
        owned_receipt.ingress = owned_ingress;
        fixed.clear();
        assert(inbound.consumer_cohort(owned_ingress,
            {owned_receipt}, fixed) == 1);
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
            later_sockets) == 0);
        dtd_initmsg_t later_hello = owner_hello;
        later_hello.ident[strlen(later_hello.ident) - 1] = '5';
        client_fd later_owner(kq, later_sockets[0], later_hello);
        /* Model a previously accepted HPI1 program registration. */
        later_owner.consumer_program_valid = true;
        later_owner.consumer_program_digest = announced_program;
        assert(later_owner.consumer_birth_valid &&
            owner_inbound.queue_recovered_consumer(&later_owner) == -1 &&
            (errno == EBUSY || errno == EAGAIN));
        assert(inbound.record_consumer_receipt(owned_receipt,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(owned_receipt,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(owner_inbound.queue_recovered_consumer(&later_owner) == -1 &&
            (errno == EBUSY || errno == EAGAIN) && owner_host.joblist.empty());
        close(old_sockets[1]);
        close(new_sockets[1]);
        close(later_sockets[1]);
    }
    /* A committed cohort may predate both its HCR1 member and HCO1 owner.
     * A fresh consumer must not bind that session during this crash gap. */
    {
        state missing_host{};
        state_attestation_test::set_control(missing_host);
        dir missing_inbound(path, &process_inbound);
        missing_host.inbounddir = &missing_inbound;
        missing_inbound.state = &missing_host;
        dtd_initmsg_t missing_hello = consumer_hello;
        missing_hello.session_id[0] = 0xf7;
        int missing_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
            missing_sockets) == 0);
        client_fd missing_owner(kq, missing_sockets[0], missing_hello);
        /* Model a previously accepted HPI1 program registration. */
        missing_owner.consumer_program_valid = true;
        missing_owner.consumer_program_digest = announced_program;
        assert(missing_owner.consumer_birth_valid);
        durable_delivery missing_ingress = *base;
        missing_ingress.delivery_id = 7100;
        missing_ingress.program_id[3] = 0x79;
        missing_ingress.source_id[3] = 0x8a;
        assert(inbound.record_delivery(missing_ingress,
            delivery_phase::pending, true) &&
            inbound.record_delivery(missing_ingress,
            delivery_phase::accepted));
        durable_consumer_receipt missing_receipt{};
        missing_receipt.ingress = missing_ingress;
        missing_receipt.consumer_session = missing_owner.session_id;
        missing_receipt.consumer_uid = (uint32_t)missing_owner.peer_uid;
        missing_receipt.consumer_pid = (uint32_t)missing_owner.peer_pid;
        std::vector<durable_consumer_receipt> fixed;
        assert(inbound.consumer_cohort(missing_ingress,
            {missing_receipt}, fixed) == 1);
        assert(missing_inbound.queue_recovered_consumer(&missing_owner) == -1 &&
            errno == EBUSY && missing_host.joblist.empty());
        assert(inbound.record_consumer_receipt(missing_receipt,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(missing_receipt,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(missing_inbound.queue_recovered_consumer(&missing_owner) == -1 &&
            errno == EPROTO && missing_host.joblist.empty());
        assert(inbound.record_consumer_receipt(missing_receipt,
            consumer_receipt_phase::executed_no_derived) ==
            (int)consumer_receipt_phase::executed_no_derived);
        assert(missing_inbound.queue_recovered_consumer(&missing_owner) == -1 && errno == EAGAIN);
        close(missing_sockets[1]);
    }
    /* A replacement PID also inherits the session's unfinished cohort,
     * even when no HCR1 exists yet to appear in its receipt scan. */
    {
        pid_t old_pid = fork();
        assert(old_pid >= 0);
        if (old_pid == 0)
            _exit(0);
        int status;
        assert(waitpid(old_pid, &status, 0) == old_pid && WIFEXITED(status));
        state replacement_host{};
        state_attestation_test::set_control(replacement_host);
        dir replacement_inbound(path, &process_inbound);
        replacement_host.inbounddir = &replacement_inbound;
        replacement_inbound.state = &replacement_host;
        dtd_initmsg_t replacement_hello = consumer_hello;
        replacement_hello.session_id[0] = 0xf8;
        int replacement_sockets[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
            replacement_sockets) == 0);
        client_fd replacement(kq, replacement_sockets[0],
            replacement_hello);
        /* Model a previously accepted HPI1 program registration. */
        replacement.consumer_program_valid = true;
        replacement.consumer_program_digest = announced_program;
        durable_delivery replaced_ingress = *base;
        replaced_ingress.delivery_id = 7200;
        replaced_ingress.program_id[3] = 0x7b;
        replaced_ingress.source_id[3] = 0x8c;
        assert(inbound.record_delivery(replaced_ingress,
            delivery_phase::pending, true) &&
            inbound.record_delivery(replaced_ingress,
            delivery_phase::accepted));
        durable_consumer_receipt replaced_receipt{};
        replaced_receipt.ingress = replaced_ingress;
        replaced_receipt.consumer_session = replacement.session_id;
        replaced_receipt.consumer_uid = (uint32_t)replacement.peer_uid;
        replaced_receipt.consumer_pid = (uint32_t)old_pid;
        std::vector<durable_consumer_receipt> fixed;
        assert(inbound.consumer_cohort(replaced_ingress,
            {replaced_receipt}, fixed) == 1);
        assert(replacement_inbound.queue_recovered_consumer(&replacement) == -1 &&
            errno == EBUSY && replacement_host.joblist.empty());
        assert(inbound.record_consumer_receipt(replaced_receipt,
            consumer_receipt_phase::pending) ==
            (int)consumer_receipt_phase::pending);
        assert(inbound.record_consumer_receipt(replaced_receipt,
            consumer_receipt_phase::no_derived) ==
            (int)consumer_receipt_phase::no_derived);
        assert(inbound.record_consumer_receipt(replaced_receipt,
            consumer_receipt_phase::executed_no_derived) ==
            (int)consumer_receipt_phase::executed_no_derived);
        assert(replacement_inbound.queue_recovered_consumer(&replacement) == -1 && errno == EAGAIN);
        close(replacement_sockets[1]);
    }
    int scanfd = openat(inbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
    assert(scanfd >= 0);
    DIR *scan = fdopendir(scanfd); assert(scan);
    while (dirent *entry = readdir(scan))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            assert(unlinkat(inbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(scan) == 0);
    scanfd = openat(outbound.dirfd, ".", O_RDONLY | O_DIRECTORY);
    assert(scanfd >= 0);
    scan = fdopendir(scanfd); assert(scan);
    while (dirent *entry = readdir(scan))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, ".."))
            assert(unlinkat(outbound.dirfd, entry->d_name, 0) == 0);
    assert(closedir(scan) == 0);
    close(sockets[1]); close(consumer_sockets[1]); close(kq);
    assert(rmdir(path) == 0);
    assert(rmdir(outbound_path) == 0);
    puts("PASS: attested host ingest journal, exact retry, revocation and pending watcher fence");
}
