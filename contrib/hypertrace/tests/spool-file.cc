/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <sys/ioctl.h>
#include <openssl/sha.h>
#include <dttransport.h>
#include <amd64/include/vmm_dev.h>
#include <cassert>
#include <cstdarg>
#include <cstring>
#include <chrono>
#include <fcntl.h>
#include <future>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_io.h"
#include "dtraced_dttransport.h"
#include "dtraced_protocol.h"
using namespace dtraced;
namespace dtraced {
struct state_attestation_test {
    static void set_control(state &s) { s.ctrlmachine = 1; }
};
}
static int attestation_fd = -1;
static hypertrace_vm_attestation attested_vm{};

extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
    if (fd != attestation_fd || request != VM_GET_ATTESTATION) {
        errno = ENOTTY;
        return -1;
    }
    va_list args;
    va_start(args, request);
    void *data = va_arg(args, void *);
    va_end(args);
    memcpy(data, &attested_vm, sizeof(attested_vm));
    return 0;
}

int main() {
    alarm(15);
    char path[] = "/tmp/hypertrace-spool.XXXXXX"; assert(mkdtemp(path));
    int sv[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    int kq = kqueue(); assert(kq >= 0);
    {
        dtd_initmsg_t init{}; client_fd client(kq, sv[0], init);
        assert(client.enable_write(&client));
        state spool_state{};
        state_attestation_test::set_control(spool_state);
        dir directory(path, nullptr);
        directory.state = &spool_state;
        spool_state.outbounddir = &directory;
        int fd = openat(directory.dirfd, "file", O_CREAT | O_RDWR, 0600); assert(fd >= 0);
        assert(symlinkat("file", directory.dirfd, "link") == 0);
        assert(mkfifoat(directory.dirfd, "fifo", 0600) == 0);
        auto send_file = [&](const char *name) {
            job j(NOTIFY_ELFWRITE, &client);
            auto &ne = j.notify_elfwrite_get();
            ne.path = strdup(name); ne.pathlen = strlen(name); ne.dir = &directory; ne.nosha = true;
            assert(ne.path); return j.send_elf();
        };
        assert(!send_file("file")); /* Empty files have no contents to address. */
        assert(!send_file("link")); assert(!send_file("fifo")); assert(!send_file("."));
        assert(ftruncate(fd, max_request_bytes + 1) == 0);
        assert(!send_file("file"));
        assert(ftruncate(fd, 0) == 0); assert(write(fd, "\177ELFDATA", 8) == 8);
        client.kind = DTRACED_KIND_FORWARDER;
        client.vmid = 42;
        client.vm_epoch = 99;
        assert(!send_file("file") && errno == ESTALE);
        client.kind = 0;
        client.vmid = 0;
        client.vm_epoch = 0;
        assert(send_file("file"));
        dtraced_hdr_t hdr; size_t transferred;
        assert(dtraced_io_transfer(sv[1], &hdr, sizeof(hdr), false,
            dtraced_io_milliseconds() + 3000, &transferred) == 0);
        assert(hdr.msg_type == DTRACED_MSG_ELF && hdr.elf.len == 8);
        char data[8]; assert(dtraced_io_transfer(sv[1], data, sizeof(data), false,
            dtraced_io_milliseconds() + 3000, &transferred) == 0);
        assert(memcmp(data, "\177ELFDATA", 8) == 0);
	const char *spool = "elf.0123456789abcdef0123456789abcdef.55000000000000000000000000000000";
	int targeted = openat(directory.dirfd, "targeted", O_CREAT | O_RDWR, 0600);
	assert(targeted >= 0);
	hypertrace_vm_envelope target{};
	target.magic = HYPERTRACE_TARGET_MAGIC;
	target.version = HYPERTRACE_ENVELOPE_VERSION;
	target.vmid = 1;
	target.epoch = 42;
	unsigned char target_wire[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE];
	hypertrace_envelope_encode(target_wire, &target);
	assert(write(targeted, target_wire, sizeof(target_wire)) ==
	    sizeof(target_wire));
	assert(write(targeted, "\177ELFDATA", 8) == 8);
	assert(linkat(directory.dirfd, "targeted", directory.dirfd, spool, 0) == 0);
	const char *other_spool =
	    "elf.fedcba9876543210fedcba9876543210.55000000000000000000000000000000";
	int other = openat(directory.dirfd, "other", O_CREAT | O_RDWR, 0600);
	assert(other >= 0);
	hypertrace_vm_envelope other_target = target;
	other_target.vmid = 2;
	hypertrace_envelope_encode(target_wire, &other_target);
	assert(write(other, target_wire, sizeof(target_wire)) ==
	    sizeof(target_wire));
	assert(write(other, "\177ELFDATA", 8) == 8);
	assert(linkat(directory.dirfd, "other", directory.dirfd, other_spool, 0) == 0);
        int forward_pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, forward_pair) == 0);
        dtd_initmsg_t forward_init{};
        forward_init.kind = DTRACED_KIND_FORWARDER;
        forward_init.subs = DTD_SUB_ELFWRITE;
	forward_init.session_id[0] = 0xa5;
	strlcpy(forward_init.ident, "guest-a", sizeof(forward_init.ident));
        {
            client_fd forwarder(kq, forward_pair[0], forward_init);
            assert(forwarder.enable_write(&forwarder));
	    {
		job bad(NOTIFY_ELFWRITE, &forwarder);
		auto &ne = bad.notify_elfwrite_get();
		ne.path = strdup("file"); ne.pathlen = 4;
		ne.dir = &directory; ne.nosha = true;
		assert(ne.path && !bad.send_elf() && errno == EPROTO);
	    }
            auto forward_file = [&](const char *name = nullptr) {
                job j(NOTIFY_ELFWRITE, &forwarder);
                auto &ne = j.notify_elfwrite_get();
		if (name == nullptr) name = spool;
		ne.path = strdup(name); ne.pathlen = strlen(name);
                ne.dir = &directory; ne.nosha = true;
                assert(ne.path); return j.send_elf();
            };
            auto receive_and_ack = [&](bool valid, uint16_t vmid = 1) {
                dtraced_hdr_t frame{};
		char bytes[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 8]; size_t moved;
                int64_t until = dtraced_io_milliseconds() + 3000;
                assert(dtraced_io_transfer(forward_pair[1], &frame,
                    sizeof(frame), false, until, &moved) == 0);
                assert(frame.msg_type == DTRACED_MSG_ELF &&
		    frame.elf.len == sizeof(bytes));
		assert(frame.elf.program_id[0] == (vmid == 1 ? 0x01 : 0xfe) &&
		    frame.elf.program_id[15] == (vmid == 1 ? 0xef : 0x10));
		assert(frame.elf.source_id[0] == 0x55);
                assert(dtraced_io_transfer(forward_pair[1], bytes,
                    sizeof(bytes), false, until, &moved) == 0);
		hypertrace_vm_envelope expected = target;
		expected.vmid = vmid;
		unsigned char expected_wire[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE];
		hypertrace_envelope_encode(expected_wire, &expected);
                assert(memcmp(bytes, expected_wire, sizeof(expected_wire)) == 0);
		assert(memcmp(bytes + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
		    "\177ELFDATA", 8) == 0);
                dtraced_delivery_ack_t response{
                    valid ? frame.elf.delivery_id : frame.elf.delivery_id + 1};
                assert(frame.elf.delivery_id != 0);
                assert(dtraced_io_transfer(forward_pair[1], &response,
                    sizeof(response), true, until, &moved) == 0);
            };
            std::thread accepted(receive_and_ack, true);
            assert(forward_file());
            accepted.join();
            assert(forwarder.outbound_deliveries.size() == 1 &&
                forwarder.outbound_deliveries[0].accepted &&
                forwarder.outbound_deliveries[0].target_vmid == 1 &&
                forwarder.outbound_deliveries[0].target_epoch == 42);
	    std::vector<durable_delivery_state> handoff_records;
	    std::array<uint8_t, 32> bare_elf_digest{};
	    const uint8_t bare_elf[] = "\177ELFDATA";
	    assert(SHA256(bare_elf, sizeof(bare_elf) - 1,
	        bare_elf_digest.data()) != nullptr);
	    assert(directory.list_deliveries(handoff_records));
	    bool payload_bound = false;
	    for (const auto &entry : handoff_records)
	        if (entry.record.delivery_id ==
	            forwarder.outbound_deliveries[0].delivery_id &&
	            entry.record.scope == 0) {
	            assert(entry.record.journal_version == 4 &&
	                entry.record.payload_digest == bare_elf_digest);
	            payload_bound = true;
	        }
	    assert(payload_bound);
            std::thread rejected(receive_and_ack, false);
            assert(!forward_file() && errno == EPROTO);
            rejected.join();
            assert(forwarder.outbound_deliveries.size() == 1);
            durable_kill record{123, 1, 42, {}};
            record.source_id[0] = 0x55;
            assert(directory.record_kill(record));
            assert(directory.source_revoked(record.source_id.data()) == 1);
            assert(forward_file());
            char absent;
            assert(recv(forward_pair[1], &absent, 1, MSG_DONTWAIT) == -1 &&
                (errno == EAGAIN || errno == EWOULDBLOCK));
	    std::thread other_guest(receive_and_ack, true, 2);
	    assert(forward_file(other_spool));
	    other_guest.join();
            assert(forwarder.outbound_deliveries.size() == 2 &&
                forwarder.outbound_deliveries[1].accepted &&
                forwarder.outbound_deliveries[1].target_vmid == 2);
	    attestation_fd = dup(forward_pair[0]);
	    assert(attestation_fd >= 0);
	    forwarder.vm_attestation_fd = attestation_fd;
	    strlcpy(attested_vm.name, "guest-a", sizeof(attested_vm.name));
	    forwarder.vmid = 1;
	    forwarder.vm_epoch = 42;
	    attested_vm.vmid = 1;
	    attested_vm.epoch = 42;
	    assert(forward_file(other_spool));
	    assert(forwarder.outbound_deliveries.size() == 2);
	    assert(recv(forward_pair[1], &absent, 1, MSG_DONTWAIT) == -1 &&
	        (errno == EAGAIN || errno == EWOULDBLOCK));
	    forwarder.vmid = 2;
	    forwarder.vm_epoch = 43;
	    attested_vm.vmid = 2;
	    attested_vm.epoch = 43;
	    assert(forward_file(other_spool));
	    assert(forwarder.outbound_deliveries.size() == 2);
	    forwarder.vmid = 0;
	    forwarder.vm_epoch = 0;
            state replay{};
            replay.outbounddir = &directory;
	    forwarder.vmid = 2;
	    forwarder.vm_epoch = 42;
	    /* Admission cannot scan between live subscriber selection and the
	     * durable kill commit.  Both paths use the revocation lock. */
	    {
	        std::unique_lock held(replay.revocationmtx);
	        std::promise<void> entered;
	        std::future<void> at_scan = entered.get_future();
	        auto scan = std::async(std::launch::async, [&] {
	            entered.set_value();
	            return replay.queue_replay_kills(&forwarder);
	        });
	        at_scan.wait();
	        assert(scan.wait_for(std::chrono::milliseconds(30)) ==
	            std::future_status::timeout);
	        held.unlock();
	        assert(scan.get());
	    }
	    assert(replay.queue_replay_kills(&forwarder));
	    assert(replay.joblist.empty());
	    forwarder.vmid = 0;
	    forwarder.vm_epoch = 0;
            assert(replay.queue_replay_kills(&forwarder));
            assert(replay.joblist.size() == 1);
            auto *queued = replay.joblist.front();
            assert(queued->kind == KILL && queued->kill_get().pid == 123 &&
                queued->kill_get().vmid == 1 && queued->kill_get().epoch == 42 &&
                queued->kill_get().source_id[0] == 0x55);
            delete queued;
            replay.joblist.clear();
	    const char *template_spool =
	        "elf.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.66000000000000000000000000000000";
	    int template_fd = openat(directory.dirfd, template_spool,
	        O_CREAT | O_RDWR, 0600);
	    assert(template_fd >= 0);
	    assert(write(template_fd, "\177ELFDATA", 8) == 8);
	    close(template_fd);
	    forwarder.vmid = attested_vm.vmid = 1;
	    forwarder.vm_epoch = attested_vm.epoch = 42;
	    std::thread template_ack([&] {
	        dtraced_hdr_t frame{};
	        char bytes[8];
	        size_t moved;
	        int64_t until = dtraced_io_milliseconds() + 3000;
	        assert(dtraced_io_transfer(forward_pair[1], &frame,
	            sizeof(frame), false, until, &moved) == 0);
	        assert(frame.msg_type == DTRACED_MSG_ELF && frame.elf.len == 8 &&
	            frame.elf.program_id[0] == 0xaa &&
	            frame.elf.source_id[0] == 0x66);
	        assert(dtraced_io_transfer(forward_pair[1], bytes,
	            sizeof(bytes), false, until, &moved) == 0);
	        assert(memcmp(bytes, "\177ELFDATA", sizeof(bytes)) == 0);
	        dtraced_delivery_ack_t ack{frame.elf.delivery_id};
	        assert(dtraced_io_transfer(forward_pair[1], &ack,
	            sizeof(ack), true, until, &moved) == 0);
	    });
	    assert(forward_file(template_spool));
	    template_ack.join();
	    assert(forwarder.outbound_deliveries.size() == 3 &&
	        forwarder.outbound_deliveries[2].accepted &&
	        forwarder.outbound_deliveries[2].target_vmid == 1 &&
	        forwarder.outbound_deliveries[2].target_epoch == 42);
	    durable_kill template_kill{123, 1, 42, {}};
	    template_kill.source_id[0] = 0x66;
	    assert(directory.record_kill(template_kill));
	    assert(forward_file(template_spool));
	    assert(forwarder.outbound_deliveries.size() == 3);
	    assert(recv(forward_pair[1], &absent, 1, MSG_DONTWAIT) == -1 &&
	        (errno == EAGAIN || errno == EWOULDBLOCK));
        }
        close(forward_pair[1]);
	/* A guest forwarder has no host VM attestation or delivery ledger.
	 * Its device writer needs the raw ELF even with default SHA settings. */
	state guest_state{};
	guest_state.outbounddir = &directory;
	directory.state = &guest_state;
	int guest_dtt[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, guest_dtt) == 0);
	assert(fcntl(guest_dtt[0], F_SETFL, O_NONBLOCK) == 0);
	guest_state.dtt_fd = guest_dtt[0];
	std::thread guest_listener(listen_dttransport, &guest_state);
	std::thread identity_responder([&] {
	    for (int i = 0; i < 2; ++i) {
	        dtt_entry_t identity{};
	        size_t moved;
	        int64_t until = dtraced_io_milliseconds() + 10000;
	        assert(dtraced_io_transfer(guest_dtt[1], &identity,
	            sizeof(identity), false, until, &moved) == 0);
	        assert(identity.event_kind == DTT_VM_IDENTITY_QUERY &&
	            identity.u.installed.query_id != 0);
	        identity.event_kind = DTT_VM_IDENTITY;
	        identity.u.installed.vmid = 42;
	        identity.u.installed.epoch = 99;
	        assert(dtraced_io_transfer(guest_dtt[1], &identity,
	            sizeof(identity), true, until, &moved) == 0);
	    }
	});
	const char *guest_spool =
	    "elf.77777777777777777777777777777777.88000000000000000000000000000000";
	int guest_fd = openat(directory.dirfd, guest_spool,
	    O_CREAT | O_RDWR, 0600);
	assert(guest_fd >= 0);
	assert(write(guest_fd, "\177ELFGUEST", 9) == 9);
	close(guest_fd);
	int guest_pair[2];
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, guest_pair) == 0);
	dtd_initmsg_t guest_init{};
	guest_init.kind = DTRACED_KIND_FORWARDER;
	guest_init.subs = DTD_SUB_ELFWRITE;
	guest_init.session_id[0] = 0x5a;
	client_fd guest_forwarder(kq, guest_pair[0], guest_init);
	assert(guest_forwarder.enable_write(&guest_forwarder));
	auto guest_send = [&](const char *name) {
	    job j(NOTIFY_ELFWRITE, &guest_forwarder);
	    auto &ne = j.notify_elfwrite_get();
	    ne.path = strdup(name); ne.pathlen = strlen(name);
	    ne.dir = &directory; ne.nosha = false;
	    assert(ne.path); return j.send_elf();
	};
	assert(!guest_send(spool) && errno == EPROTO);
	uint64_t first_guest_id = 0;
	std::thread guest_ack([&] {
	    dtraced_hdr_t frame{};
	    char bytes[9];
	    size_t moved;
	    int64_t until = dtraced_io_milliseconds() + 3000;
	    assert(dtraced_io_transfer(guest_pair[1], &frame,
	        sizeof(frame), false, until, &moved) == 0);
	    assert(frame.msg_type == DTRACED_MSG_ELF && frame.elf.len == 9 &&
	        frame.elf.delivery_id != 0 && frame.elf.program_id[0] == 0x77 &&
	        frame.elf.source_id[0] == 0x88 && frame.elf.vmid == 42 &&
	        frame.elf.epoch == 99);
	    first_guest_id = frame.elf.delivery_id;
	    assert(dtraced_io_transfer(guest_pair[1], bytes,
	        sizeof(bytes), false, until, &moved) == 0);
	    assert(memcmp(bytes, "\177ELFGUEST", sizeof(bytes)) == 0);
	    dtraced_delivery_ack_t ack{frame.elf.delivery_id};
	    assert(dtraced_io_transfer(guest_pair[1], &ack,
	        sizeof(ack), true, until, &moved) == 0);
	});
	assert(guest_send(guest_spool));
	guest_ack.join();
	assert(first_guest_id != 0 &&
	    guest_forwarder.outbound_deliveries.empty());
	std::vector<durable_delivery_state> guest_records;
	assert(directory.list_deliveries(guest_records));
	for (const auto &entry : guest_records)
	    assert(entry.record.scope != 2);
	std::thread guest_bad_ack([&] {
	    dtraced_hdr_t frame{};
	    char bytes[9];
	    size_t moved;
	    int64_t until = dtraced_io_milliseconds() + 3000;
	    assert(dtraced_io_transfer(guest_pair[1], &frame,
	        sizeof(frame), false, until, &moved) == 0);
	    assert(frame.elf.len == sizeof(bytes) &&
	        frame.elf.delivery_id != first_guest_id);
	    assert(dtraced_io_transfer(guest_pair[1], bytes,
	        sizeof(bytes), false, until, &moved) == 0);
	    dtraced_delivery_ack_t wrong{frame.elf.delivery_id + 1};
	    assert(dtraced_io_transfer(guest_pair[1], &wrong,
	        sizeof(wrong), true, until, &moved) == 0);
	});
	assert(!guest_send(guest_spool) && errno == EPROTO);
	guest_bad_ack.join();
	guest_records.clear();
	assert(directory.list_deliveries(guest_records));
	unsigned guest_pending = 0;
	uint8_t guest_digest[SHA256_DIGEST_LENGTH];
	assert(SHA256((const unsigned char *)"\177ELFGUEST", 9,
	    guest_digest) != NULL);
	for (const auto &entry : guest_records)
	    if (entry.record.scope == 2 &&
	        entry.phase == delivery_phase::pending) {
	        assert(entry.record.journal_version == 4 &&
	            entry.record.vmid == 42 && entry.record.epoch == 99 &&
	            memcmp(entry.record.payload_digest.data(), guest_digest,
	            sizeof(guest_digest)) == 0);
	        guest_pending++;
	    }
	assert(guest_pending == 1);
	identity_responder.join();
	guest_state.shutdown.store(true);
	guest_listener.join();
	close(guest_dtt[0]); close(guest_dtt[1]);
	close(guest_pair[1]);
	directory.state = &spool_state;
	assert(unlinkat(directory.dirfd, guest_spool, 0) == 0);
        close(fd);
	close(targeted);
	close(other);
        assert(unlinkat(directory.dirfd, "file", 0) == 0);
	assert(unlinkat(directory.dirfd, "targeted", 0) == 0);
	assert(unlinkat(directory.dirfd, "other", 0) == 0);
	assert(unlinkat(directory.dirfd, spool, 0) == 0);
	assert(unlinkat(directory.dirfd, other_spool, 0) == 0);
	assert(unlinkat(directory.dirfd,
	    "elf.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.66000000000000000000000000000000",
	    0) == 0);
        assert(unlinkat(directory.dirfd,
            ".kill.0001.000000000000002a.0000007b.55000000000000000000000000000000",
            0) == 0);
	assert(unlinkat(directory.dirfd,
	    ".kill.0001.000000000000002a.0000007b.66000000000000000000000000000000",
	    0) == 0);
        assert(unlinkat(directory.dirfd, "link", 0) == 0);
        assert(unlinkat(directory.dirfd, "fifo", 0) == 0);
	DIR *records = fdopendir(openat(directory.dirfd, ".",
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC));
	assert(records != nullptr);
	while (struct dirent *entry = readdir(records))
		if (strncmp(entry->d_name, ".delivery.", 10) == 0)
			assert(unlinkat(directory.dirfd, entry->d_name, 0) == 0);
	assert(closedir(records) == 0);
	if (unlinkat(directory.dirfd, ".handoff.lock", 0) != 0)
		assert(errno == ENOENT);
    }
    close(sv[1]); close(kq); assert(rmdir(path) == 0);
    puts("PASS: actual spool forwarding, complete content, size bounds and nonregular/symlink rejection");
}
