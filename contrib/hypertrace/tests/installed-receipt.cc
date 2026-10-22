/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <openssl/sha.h>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_state.h"

using namespace dtraced;

namespace dtraced {
struct state_attestation_test {
    static void set_control(state &s) { s.ctrlmachine = 1; }
};
}

static int observer_attestation_fd = -1;
static int outbound_attestation_fd = -1;
static hypertrace_vm_attestation attested_vm{};

extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
    if ((fd != observer_attestation_fd &&
        fd != outbound_attestation_fd) || request != VM_GET_ATTESTATION) {
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

int main()
{
    state s{};
    state_attestation_test::set_control(s);
    char path[] = "/tmp/hypertrace-install-ledger.XXXXXX";
    assert(mkdtemp(path) != nullptr);
    {
    dir directory(path, nullptr);
    s.outbounddir = &directory;
    int kq = kqueue(), pair[2], outbound[2], consumer_pair[2];
    assert(kq >= 0 && socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, outbound) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, consumer_pair) == 0);
    dtd_initmsg_t hello{};
    hello.kind = DTRACED_KIND_FORWARDER;
    hello.subs = DTD_SUB_READDATA;
    hello.session_id[0] = 0xa5;
    strlcpy(hello.ident, "guest-a", sizeof(hello.ident));
    {
        client_fd sender(kq, pair[0], hello);
        hello.subs = DTD_SUB_ELFWRITE;
        client_fd receiver(kq, outbound[0], hello);
		hello.kind = DTRACED_KIND_CONSUMER;
		hello.subs = DTD_SUB_READDATA;
		client_fd killer(kq, consumer_pair[0], hello);
	observer_attestation_fd = dup(pair[0]);
	outbound_attestation_fd = dup(outbound[0]);
	assert(observer_attestation_fd >= 0 && outbound_attestation_fd >= 0);
	sender.vm_attestation_fd = observer_attestation_fd;
	receiver.vm_attestation_fd = outbound_attestation_fd;
	sender.vmid = receiver.vmid = attested_vm.vmid = 7;
	sender.vm_epoch = receiver.vm_epoch = attested_vm.epoch = 11;
	strlcpy(attested_vm.name, "guest-a", sizeof(attested_vm.name));
	assert(sender.peer_pid == getpid() && receiver.peer_pid == getpid());
	assert(sender.peer_uid == geteuid() && receiver.peer_uid == geteuid());
        s.sockfds.insert(&sender);
        s.sockfds.insert(&receiver);
	auto pending_record = [&](uint64_t token, uint16_t vmid,
	    uint64_t epoch, uint8_t source) {
		durable_delivery record{};
		record.session_id = sender.session_id;
		record.delivery_id = token;
		record.vmid = vmid;
		record.epoch = epoch;
		record.program_id[0] = 0x42;
		record.source_id[0] = source;
		record.peer_uid = sender.peer_uid;
		record.peer_pid = sender.peer_pid;
		assert(directory.record_delivery(record, delivery_phase::pending));
		return record;
	};
	auto first_record = pending_record(17, 7, 11, 0x55);
	assert(!directory.record_delivery(first_record, delivery_phase::pending,
	    true) && errno == EEXIST);
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty()); /* Pending is not an ACK. */
        outbound_delivery sent{};
        sent.delivery_id = 17;
        sent.program_id[0] = 0x42;
        sent.source_id[0] = 0x55;
        sent.target_vmid = 7;
        sent.target_epoch = 11;
        receiver.outbound_deliveries.push_back(sent);
        dtraced_hdr_t header{};
        header.msg_type = DTRACED_MSG_INSTALLED;
        header.installed.delivery_id = 17;
        header.installed.vmid = 7;
        header.installed.epoch = 11;
        header.installed.program_id[0] = 0x42;
        header.installed.source_id[0] = 0x55;
        strlcpy(header.installed.name, "guest-a",
            sizeof(header.installed.name));
        auto accept = [&]() {
            client_request request(s, header, nullptr, 0, &sender);
            return request.handle();
        };
	auto status_for = [&](dtraced_hdr_t request_header) {
		request_header.msg_type = DTRACED_MSG_STATUS;
		client_request request(s, request_header, nullptr, 0, &sender);
		assert(request.handle() && request.status_response() != nullptr);
		return *request.status_response();
	};
	auto status = status_for(header);
	assert(status.delivery_id == 17 &&
	    status.phase == (uint8_t)delivery_phase::pending &&
	    status.revoked == 0 && status.replay == 0);
	assert(sender.respond_with_status(true, &status));
	unsigned char status_ack = 0;
	dtraced_delivery_status_t wire_status{};
	assert(read(pair[1], &status_ack, 1) == 1 && status_ack == 1);
	assert(read(pair[1], &wire_status, sizeof(wire_status)) ==
	    sizeof(wire_status) && wire_status.delivery_id == 17 &&
	    wire_status.phase == (uint8_t)delivery_phase::pending);
	auto absent_header = header;
	absent_header.installed.delivery_id = 999;
	status = status_for(absent_header);
	assert(status.delivery_id == 999 && status.phase == 0 &&
	    status.revoked == 0);
        assert(accept() && receiver.outbound_deliveries[0].observed);
	status = status_for(header);
	assert(status.phase == 'u' &&
	    status.revoked == 0 && status.replay == 0);
	sender.vm_epoch = 12;
	{
		auto query_header = header;
		query_header.msg_type = DTRACED_MSG_STATUS;
		client_request rejected(s, query_header, nullptr, 0, &sender);
		assert(!rejected.handle() && errno == EPROTO &&
		    rejected.status_response() == nullptr);
	}
	sender.vm_epoch = 11;
	{
		auto query_header = header;
		query_header.msg_type = DTRACED_MSG_STATUS;
		query_header.installed.program_id[0] = 0x43;
		client_request rejected(s, query_header, nullptr, 0, &sender);
		assert(!rejected.handle() && errno == EPROTO);
	}
	assert(directory.delivery_status(first_record) ==
	    (int)delivery_phase::installed);
	attested_vm.epoch = 12;
	assert(!accept() && errno == EPROTO);
	attested_vm.epoch = 11;
	++sender.vmid;
	assert(!accept() && errno == EPROTO);
	--sender.vmid;
	++sender.peer_pid;
	assert(!accept() && errno == EPROTO);
	--sender.peer_pid;
	++receiver.peer_uid;
	assert(!accept() && errno == ENOENT);
	--receiver.peer_uid;
	assert(accept());
        assert(!receiver.outbound_deliveries[0].accepted);
        assert(accept() && receiver.outbound_deliveries.size() == 1);
        assert(receiver.outbound_deliveries[0].observation.vmid == 7 &&
            receiver.outbound_deliveries[0].observation.delivery_id == 17 &&
            receiver.outbound_deliveries[0].observation.epoch == 11 &&
            receiver.outbound_deliveries[0].observation.program_id[0] == 0x42 &&
            receiver.outbound_deliveries[0].observation.source_id[0] == 0x55);
        receiver.outbound_deliveries[0].accepted = true;
	bool replay_file_created = false;
	assert(directory.write_identified_data(
	    (const unsigned char *)"\177ELF", 4,
	    first_record.program_id.data(), &replay_file_created,
	    first_record.source_id.data()) && replay_file_created);
	status = status_for(header);
	assert(status.phase == (uint8_t)delivery_phase::installed &&
	    status.revoked == 0 && status.replay == 1);
	uint8_t replay_digest[SHA256_DIGEST_LENGTH];
	assert(SHA256((const unsigned char *)"\177ELF", 4,
	    replay_digest) != nullptr &&
	    memcmp(status.digest, replay_digest, sizeof(replay_digest)) == 0);
	/* A restarted host rebuilds only this attested, acknowledged owner. */
	receiver.outbound_deliveries.clear();
	receiver.session_id[0] ^= 1;
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty());
	receiver.session_id[0] ^= 1;
	++receiver.peer_pid;
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty());
	--receiver.peer_pid;
	++receiver.peer_uid;
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty());
	--receiver.peer_uid;
	receiver.vm_epoch = attested_vm.epoch = 12;
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty());
	receiver.vm_epoch = attested_vm.epoch = 11;
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.size() == 1 &&
	    receiver.outbound_deliveries[0].delivery_id == 17 &&
	    receiver.outbound_deliveries[0].accepted);
	assert(status_for(header).replay == 1);
	receiver.retired.store(true);
	status = status_for(header);
	assert(status.phase == 'u' && status.replay == 0);
	receiver.retired.store(false);
        header.installed.epoch = 0;
        assert(!accept()); header.installed.epoch = 11;
        header.installed.delivery_id = 0;
        assert(!accept()); header.installed.delivery_id = 17;
        header.installed.vmid = HYPERTRACE_MAX_VMS;
        assert(!accept()); header.installed.vmid = 7;
        header.installed.vmid = 8;
        assert(!accept()); header.installed.vmid = 7;
        header.installed.epoch = 12;
        assert(!accept()); header.installed.epoch = 11;
        header.installed.delivery_id = 18;
        assert(!accept()); header.installed.delivery_id = 17;
        header.installed.source_id[0] = 0;
        assert(!accept()); header.installed.source_id[0] = 0x55;
        header.installed.program_id[0] = 0;
        assert(!accept()); header.installed.program_id[0] = 0x42;
        strlcpy(header.installed.name, "guest-b",
            sizeof(header.installed.name));
        assert(!accept());
        memset(header.installed.name, 'x', sizeof(header.installed.name));
        assert(!accept());
        strlcpy(header.installed.name, "guest-a",
            sizeof(header.installed.name));
        client_request payload(s, header, (unsigned char *)"x", 1, &sender);
        assert(!payload.handle());
        sender.kind = DTRACED_KIND_CONSUMER;
        assert(!accept()); sender.kind = DTRACED_KIND_FORWARDER;
        sender.retired.store(true);
        assert(!accept()); sender.retired.store(false);
        sender.session_id[0] = 0x5a;
        assert(!accept()); sender.session_id[0] = 0xa5;
        receiver.retired.store(true);
        assert(accept()); receiver.retired.store(false);
        assert(receiver.outbound_deliveries.size() == 1);
        dtraced_hdr_t kill{};
        kill.msg_type = DTRACED_MSG_KILL;
        kill.kill.pid = 123;
        kill.kill.vmid = 7;
        kill.kill.epoch = 11;
        kill.kill.source_id[0] = 0x55;
		client_request wrong_sender(s, kill, nullptr, 0, &sender);
		assert(!wrong_sender.handle() && errno == EPROTO);
		unsigned char extra = 0;
		client_request extra_payload(s, kill, &extra, 1, &killer);
		assert(!extra_payload.handle() && errno == EPROTO);
		assert(directory.source_revoked_for_vm(
		    kill.kill.source_id, 7, 11) == 0);
        client_request revoke(s, kill, nullptr, 0, &killer);
        assert(revoke.handle());
	/* A receipt or retry from another daemon process must not advance the
	 * durable delivery after the KILL has reached the journal. */
	{
		dir reopened(path, nullptr);
		assert(!reopened.record_delivery(first_record,
		    delivery_phase::installed) && errno == ECANCELED);
		auto late = first_record;
		late.delivery_id = 500;
		assert(!reopened.record_delivery(late,
		    delivery_phase::pending, true) && errno == ECANCELED);
		assert(reopened.delivery_status(late) == 0);
	}
	status = status_for(header);
	assert(status.phase == (uint8_t)delivery_phase::installed &&
	    status.revoked == 1 && status.replay == 0);
        assert(receiver.outbound_deliveries.empty());
	assert(s.recover_outbound_deliveries(&receiver) &&
	    receiver.outbound_deliveries.empty());
        assert(!accept() && errno == ECANCELED);
        outbound_delivery second{};
        second.delivery_id = 18;
        second.program_id[0] = 0x42;
        second.source_id[0] = 0x56;
        second.target_vmid = 8;
        second.target_epoch = 12;
        receiver.outbound_deliveries.push_back(second);
	auto second_record = pending_record(18, 8, 12, 0x56);
        header.installed.delivery_id = 18;
        header.installed.vmid = 8;
        header.installed.epoch = 12;
        header.installed.source_id[0] = 0x56;
	sender.vmid = receiver.vmid = attested_vm.vmid = 8;
	sender.vm_epoch = receiver.vm_epoch = attested_vm.epoch = 12;
        assert(accept() && receiver.outbound_deliveries[0].observed);
        receiver.outbound_deliveries[0].accepted = true;
        header.msg_type = DTRACED_MSG_UNINSTALLED;
        header.installed.epoch = 13;
        assert(!accept()); header.installed.epoch = 12;
	attested_vm.epoch = 13;
	assert(!accept() && errno == EPROTO);
	attested_vm.epoch = 12;
        assert(accept() && receiver.outbound_deliveries.empty());
	assert(directory.delivery_status(second_record) ==
	    (int)delivery_phase::terminal);
        assert(accept()); /* A repeated child-exit event is harmless. */
	/* A restarted host can resolve an observation from the disk token. */
	auto recovered = pending_record(22, 8, 12, 0x5a);
	/* A pre-HTD3 host spool must remain readable across the upgrade. */
	char legacy_name[80], session_hex[33];
	static const char hex[] = "0123456789abcdef";
	for (size_t i = 0; i < recovered.session_id.size(); ++i) {
		session_hex[i * 2] = hex[recovered.session_id[i] >> 4];
		session_hex[i * 2 + 1] = hex[recovered.session_id[i] & 15];
	}
	session_hex[32] = '\0';
	assert(snprintf(legacy_name, sizeof(legacy_name),
	    ".delivery.%s.%016jx.p", session_hex,
	    (uintmax_t)recovered.delivery_id) > 0);
	int legacy_fd = openat(directory.dirfd, legacy_name, O_RDWR | O_NOFOLLOW);
	assert(legacy_fd >= 0);
	std::array<unsigned char, 111> legacy{};
	assert(pread(legacy_fd, legacy.data(), legacy.size(), 0) ==
	    (ssize_t)legacy.size());
	memcpy(legacy.data(), "HTD2", 4);
	(void)SHA256(legacy.data(), 78, legacy.data() + 78);
	assert(ftruncate(legacy_fd, 0) == 0);
	assert(write(legacy_fd, legacy.data(), 110) == 110);
	assert(fsync(legacy_fd) == 0 && close(legacy_fd) == 0);
	assert(directory.delivery_status(recovered) ==
	    (int)delivery_phase::pending);
	{
		dir reopened(path, nullptr);
		std::vector<durable_delivery_state> old_records;
		assert(reopened.list_deliveries(old_records) &&
		    old_records.size() == 3);
	}
	legacy_fd = openat(directory.dirfd, legacy_name, O_RDWR | O_NOFOLLOW);
	assert(legacy_fd >= 0);
	unsigned char bad_digest = legacy[78] ^ 0xff;
	assert(pwrite(legacy_fd, &bad_digest, 1, 78) == 1);
	assert(directory.delivery_status(recovered) == -1 && errno == EPROTO);
	assert(pwrite(legacy_fd, legacy.data() + 78, 1, 78) == 1);
	assert(fsync(legacy_fd) == 0 && close(legacy_fd) == 0);
	header.msg_type = DTRACED_MSG_INSTALLED;
	header.installed.delivery_id = 22;
	header.installed.source_id[0] = 0x5a;
	assert(accept() && directory.delivery_status(recovered) ==
	    (int)delivery_phase::installed);
	header.msg_type = DTRACED_MSG_UNINSTALLED;
	assert(accept() && directory.delivery_status(recovered) ==
	    (int)delivery_phase::terminal);
	{
		dir reopened(path, nullptr);
		std::vector<durable_delivery_state> recovered_records;
		assert(reopened.list_deliveries(recovered_records) &&
		    recovered_records.size() == 3);
		assert(reopened.delivery_status(recovered) ==
		    (int)delivery_phase::terminal);
		assert(reopened.delivery_status(first_record) ==
		    (int)delivery_phase::installed);
	}
	auto mismatched = recovered;
	mismatched.program_id[0] = 0x43;
	assert(directory.delivery_status(mismatched) == -1 && errno == EPROTO);
	assert(!directory.record_delivery(recovered, delivery_phase::installed) &&
	    errno == ECANCELED);
	/* HTD4 observations must resolve the stored payload digest rather than
	 * reconstructing an HTD3 record from the guest's identity fields. */
	durable_delivery bound = recovered;
	bound.delivery_id = 23;
	bound.program_id[0] = 0x43;
	bound.source_id[0] = 0x5b;
	bound.journal_version = 4;
	const unsigned char bare_elf[] = "\177ELFDATA";
	assert(SHA256(bare_elf, sizeof(bare_elf) - 1,
	    bound.payload_digest.data()) != nullptr);
	assert(directory.record_delivery(bound, delivery_phase::pending, true));
	assert(directory.record_delivery(bound, delivery_phase::accepted));
	outbound_delivery bound_sent{};
	bound_sent.delivery_id = bound.delivery_id;
	bound_sent.program_id = bound.program_id;
	bound_sent.source_id = bound.source_id;
	bound_sent.target_vmid = bound.vmid;
	bound_sent.target_epoch = bound.epoch;
	bound_sent.accepted = true;
	receiver.outbound_deliveries.push_back(bound_sent);
	header.msg_type = DTRACED_MSG_INSTALLED;
	header.installed.delivery_id = bound.delivery_id;
	header.installed.program_id[0] = bound.program_id[0];
	header.installed.source_id[0] = bound.source_id[0];
	status = status_for(header);
	assert(status.phase == 'a' && status.replay == 0);
	hypertrace_vm_envelope target{};
	target.magic = HYPERTRACE_TARGET_MAGIC;
	target.version = HYPERTRACE_ENVELOPE_VERSION;
	target.vmid = bound.vmid;
	target.epoch = bound.epoch;
	unsigned char targeted[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
	    sizeof(bare_elf) - 1]{};
	hypertrace_envelope_encode(targeted, &target);
	memcpy(targeted + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
	    bare_elf, sizeof(bare_elf) - 1);
	assert(directory.write_identified_data(targeted, sizeof(targeted),
	    bound.program_id.data(), nullptr, bound.source_id.data()));
	status = status_for(header);
	assert(status.phase == 'a' && status.replay == 1 &&
	    memcmp(status.digest, bound.payload_digest.data(),
	    sizeof(status.digest)) == 0);
	assert(accept() && directory.delivery_status(bound) ==
	    (int)delivery_phase::installed);
	header.msg_type = DTRACED_MSG_UNINSTALLED;
	assert(accept() && directory.delivery_status(bound) ==
	    (int)delivery_phase::terminal &&
	    receiver.outbound_deliveries.empty());
	{
		dir reopened(path, nullptr);
		durable_delivery_state on_disk{};
		assert(reopened.resolve_host_delivery(bound, on_disk) == 1 &&
		    on_disk.phase == delivery_phase::terminal &&
		    on_disk.record.journal_version == 4 &&
		    on_disk.record.payload_digest == bound.payload_digest);
	}
	header.installed.program_id[0] = 0x42;
        outbound_delivery third{};
        third.delivery_id = 19;
        third.program_id[0] = 0x42;
        third.source_id[0] = 0x57;
        third.target_vmid = 8;
        third.target_epoch = 12;
        receiver.outbound_deliveries.push_back(third);
	auto third_record = pending_record(19, 8, 12, 0x57);
        header.msg_type = DTRACED_MSG_INSTALLED;
        header.installed.delivery_id = 19;
		header.installed.source_id[0] = 0x57;
		assert(accept() && receiver.outbound_deliveries[0].observed);
		assert(directory.delivery_status(third_record) ==
		    (int)delivery_phase::installed);
	outbound_delivery untargeted{};
	untargeted.delivery_id = 20;
	untargeted.program_id[0] = 0x42;
	untargeted.source_id[0] = 0x58;
	receiver.outbound_deliveries.push_back(untargeted);
	auto untargeted_record = pending_record(20, 8, 12, 0x58);
	header.installed.delivery_id = 20;
	header.installed.source_id[0] = 0x58;
	header.installed.vmid = 7;
	header.installed.epoch = 11;
	assert(!accept() && errno == EPROTO);
	header.installed.vmid = 8;
	header.installed.epoch = 12;
	assert(accept() && receiver.outbound_deliveries[1].observed);
	assert(directory.delivery_status(untargeted_record) ==
	    (int)delivery_phase::installed);
	assert(receiver.outbound_deliveries[1].target_vmid == 8 &&
	    receiver.outbound_deliveries[1].target_epoch == 12);
	outbound_delivery no_install{};
	no_install.delivery_id = 21;
	no_install.program_id[0] = 0x42;
	no_install.source_id[0] = 0x59;
	no_install.target_vmid = 8;
	no_install.target_epoch = 12;
	no_install.accepted = true;
	receiver.outbound_deliveries.push_back(no_install);
	auto no_install_record = pending_record(21, 8, 12, 0x59);
	header.msg_type = DTRACED_MSG_UNINSTALLED;
	header.installed.delivery_id = 21;
	header.installed.source_id[0] = 0x59;
	assert(accept() && receiver.outbound_deliveries.size() == 2);
	assert(directory.delivery_status(no_install_record) ==
	    (int)delivery_phase::terminal);
	s.kq_hdl = kq;
        s.kill_socket(&sender);
        assert(!receiver.outbound_deliveries[0].observed);
	assert(receiver.outbound_deliveries[1].target_vmid == 8 &&
	    receiver.outbound_deliveries[1].target_epoch == 12);
	kill.kill.vmid = 8;
	kill.kill.epoch = 12;
	kill.kill.source_id[0] = 0x58;
	client_request revoke_bound(s, kill, nullptr, 0, &killer);
	assert(revoke_bound.handle());
	assert(receiver.outbound_deliveries.size() == 2 &&
	    receiver.outbound_deliveries[0].delivery_id == 19 &&
	    receiver.outbound_deliveries[1].delivery_id == 20 &&
	    receiver.outbound_deliveries[1].revoked &&
	    !receiver.outbound_deliveries[1].observed);
	DIR *markers = opendir(path);
	assert(markers != nullptr);
	bool corrupted = false;
	while (struct dirent *entry = readdir(markers)) {
		if (strncmp(entry->d_name, ".delivery.", 10) != 0 ||
		    entry->d_name[strlen(entry->d_name) - 1] != 'i')
			continue;
		int marker = openat(directory.dirfd, entry->d_name,
		    O_WRONLY | O_NOFOLLOW);
		assert(marker >= 0);
		const unsigned char changed = 0xff;
		assert(pwrite(marker, &changed, 1, 40) == 1);
		assert(fsync(marker) == 0 && close(marker) == 0);
		corrupted = true;
		break;
	}
	assert(closedir(markers) == 0 && corrupted);
	std::vector<durable_delivery_state> invalid_records;
	assert(!directory.list_deliveries(invalid_records) && errno == EPROTO);
        s.deadfds.erase(&sender);
        s.sockfds.erase(&receiver);
    }
    close(pair[1]); close(outbound[1]); close(consumer_pair[1]); close(kq);
    DIR *scan = opendir(path);
    assert(scan != nullptr);
    while (struct dirent *entry = readdir(scan)) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        assert(unlinkat(directory.dirfd, entry->d_name, 0) == 0);
    }
    assert(closedir(scan) == 0);
    }
    assert(rmdir(path) == 0);
    puts("PASS: installation and retirement bound to VMM-attested VM, peer, session and delivery token");
}
