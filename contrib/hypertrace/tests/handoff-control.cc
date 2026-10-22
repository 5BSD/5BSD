/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <sys/hypertrace_wire.h>
#include <sys/ioctl.h>
#include <amd64/include/vmm_dev.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <algorithm>
#include <cassert>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

#include "dtraced_clientrequest.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_job.h"
#include "dtraced_state.h"
#include "dtraced_wire.h"
#include "dtraced_transfer_wire.h"

using namespace dtraced;

static EVP_PKEY *
new_release_key(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	EVP_PKEY *key = nullptr;
	assert(ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

static void
write_release_key(const std::string &path, EVP_PKEY *key, bool private_key)
{
	int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != nullptr);
	assert(private_key ? PEM_write_PrivateKey(file, key, nullptr,
	    nullptr, 0, nullptr, nullptr) == 1 :
	    PEM_write_PUBKEY(file, key) == 1);
	assert(fflush(file) == 0 && fsync(fd) == 0 && fclose(file) == 0);
}

static void
bind_empty_transfer(durable_handoff &ticket)
{
	std::vector<uint8_t> bytes;
	assert(dtraced_transfer_wire_build(ticket.token.data(), {}, {}, bytes));
	memcpy(ticket.transfer_digest.data(), bytes.data() + bytes.size() - 32,
	    ticket.transfer_digest.size());
}

static std::string
test_kill_name(const durable_kill &record)
{
	static const char hex[] = "0123456789abcdef";
	char source[33], name[70];
	for (size_t i = 0; i < record.source_id.size(); i++) {
		source[i * 2] = hex[record.source_id[i] >> 4];
		source[i * 2 + 1] = hex[record.source_id[i] & 15];
	}
	source[32] = '\0';
	assert(snprintf(name, sizeof(name), ".kill.%04x.%016llx.%08x.%s",
	    (unsigned)record.vmid, (unsigned long long)record.epoch,
	    (unsigned)(uint32_t)record.pid, source) == 69);
	return (name);
}

static std::string
test_cleanup_name(const durable_cleanup &record, char phase)
{
	char name[50];
	assert(snprintf(name, sizeof(name),
	    ".cleanup.%04x.%016llx.%016llx.%c", (unsigned)record.vmid,
	    (unsigned long long)record.epoch,
	    (unsigned long long)record.delivery_id, phase) == 49);
	return (name);
}

namespace dtraced {
struct state_attestation_test {
	static void set_control(state &s) { s.ctrlmachine = 1; }
};
struct state_admission_test {
	static bool replay_cleanups(state &s, client_fd *client) {
		return (s.queue_replay_cleanups(client));
	}
};
}

static int source_attestation_fd = -1, destination_attestation_fd = -1;
static int destination_outbound_attestation_fd = -1;
static int rival_attestation_fd = -1;
static int epoch_query_fd = -1;
static bool epoch_query_live = true;
static bool destination_epoch_live = true;
static bool rival_epoch_live = true;
static hypertrace_vm_attestation source_vm{}, destination_vm{}, rival_vm{};
static int gate_fd = -1;
static bool gate_suspended;
static uint8_t gate_owner[16];

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		gate_fd = __real_open("/dev/null", flags);
		return (gate_fd);
	}
	va_list args;
	va_start(args, flags);
	mode_t mode = (flags & O_CREAT) ? (mode_t)va_arg(args, int) : 0;
	va_end(args);
	return (__real_open(path, flags, mode));
}

extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	if (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY ||
	    request == HYPERTRACE_IOC_EPOCH_SUSPEND ||
	    request == HYPERTRACE_IOC_EPOCH_RESUME) {
		va_list args;
		va_start(args, request);
		auto *gate = va_arg(args, hypertrace_epoch_gate *);
		va_end(args);
		assert(fd == gate_fd && gate->vmid == source_vm.vmid &&
		    gate->epoch == source_vm.epoch);
		if (request == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
			gate->suspended = gate_suspended ? 1 : 0;
			memcpy(gate->token, gate_owner, sizeof(gate_owner));
			return (0);
		}
		if (request == HYPERTRACE_IOC_EPOCH_SUSPEND &&
		    !gate_suspended && memcmp(gate->previous_token,
		    gate_owner, sizeof(gate_owner)) == 0) {
			memcpy(gate_owner, gate->token, sizeof(gate_owner));
			gate_suspended = true;
			return (0);
		}
		if (request == HYPERTRACE_IOC_EPOCH_RESUME &&
		    gate_suspended && memcmp(gate->token, gate_owner,
		    sizeof(gate_owner)) == 0) {
			gate_suspended = false;
			return (0);
		}
		errno = ESTALE;
		return (-1);
	}
	if (request == HYPERTRACE_IOC_EPOCH_QUERY) {
		va_list args;
		va_start(args, request);
		auto *query = va_arg(args, hypertrace_epoch_query *);
		va_end(args);
		if (fd == gate_fd && query->vmid == destination_vm.vmid &&
		    query->epoch == destination_vm.epoch && query->live == 0) {
			query->live = destination_epoch_live ? 1 : 0;
			return (0);
		}
		if (fd == gate_fd && query->vmid == rival_vm.vmid &&
		    query->epoch == rival_vm.epoch && query->live == 0) {
			query->live = rival_epoch_live ? 1 : 0;
			return (0);
		}
		assert(fd == epoch_query_fd && query->vmid == source_vm.vmid &&
		    query->epoch == source_vm.epoch && query->live == 0);
		query->live = epoch_query_live ? 1 : 0;
		return (0);
	}
	if (request != VM_GET_ATTESTATION ||
	    (fd != source_attestation_fd && fd != destination_attestation_fd &&
	    fd != destination_outbound_attestation_fd &&
	    fd != rival_attestation_fd)) {
		errno = ENOTTY;
		return (-1);
	}
	va_list args;
	va_start(args, request);
	void *output = va_arg(args, void *);
	va_end(args);
	memcpy(output, fd == source_attestation_fd ? &source_vm :
	    (fd == destination_attestation_fd ||
	    fd == destination_outbound_attestation_fd) ?
	    &destination_vm : &rival_vm,
	    sizeof(source_vm));
	return (0);
}

static void
test_cleanup_cut(state &host, dir &journal, client_fd &source,
    int peer_fd)
{
	/* A source cut must wait until bhyve has queued CLEANUP. */
	assert(source.enable_write(&source));
	job cleanup(CLEANUP, &source);
	cleanup.cleanup_get() = new cleanup_job;
	cleanup.cleanup_delivery_id = 0x8899;
	cleanup.cleanup_journaled = true;
	durable_cleanup pending{};
	pending.vmid = source.vmid;
	pending.epoch = source.vm_epoch;
	pending.delivery_id = cleanup.cleanup_delivery_id;
	assert(journal.record_cleanup_pending(pending));
	assert(journal.cleanup_status(pending) == 'p');
	std::vector<durable_cleanup> recovered;
	assert(journal.list_pending_cleanups(recovered) &&
	    recovered.size() == 1 &&
	    recovered.front().delivery_id == pending.delivery_id);
	{
		dir reopened(journal.full_path().c_str(), nullptr);
		std::vector<durable_cleanup> on_disk;
		assert(reopened.list_pending_cleanups(on_disk) &&
		    on_disk.size() == 1 &&
		    on_disk.front().delivery_id == pending.delivery_id);
	}
	assert(state_admission_test::replay_cleanups(host, &source));
	assert(host.joblist.size() == 1);
	job *replayed = host.joblist.front();
	assert(replayed->kind == CLEANUP && replayed->cleanup_journaled &&
	    replayed->cleanup_delivery_id == pending.delivery_id &&
	    replayed->cleanup_get()->empty());
	host.joblist.clear();
	delete replayed;
	durable_handoff cleanup_cut{};
	cleanup_cut.token[0] = 0xf0;
	cleanup_cut.source_session = source.session_id;
	cleanup_cut.source_vmid = source.vmid;
	cleanup_cut.source_epoch = source.vm_epoch;
	bind_empty_transfer(cleanup_cut);
	assert(!journal.prepare_handoff(cleanup_cut, false) && errno == EBUSY);
	std::atomic_bool cleanup_sent{false};
	std::thread cleanup_sender([&] {
		cleanup_sent.store(cleanup.send_cleanup(host));
	});
	unsigned char cleanup_wire[DTRACED_MSGHDRSIZE];
	size_t transferred = 0;
	int64_t deadline = dtraced_io_deadline_after(2000);
	assert(dtraced_io_transfer(peer_fd, cleanup_wire,
	    sizeof(cleanup_wire), false, deadline, &transferred) == 0);
	dtraced_hdr_t cleanup_header{};
	assert(dtraced_wire_decode_header(&cleanup_header, cleanup_wire) == 0 &&
	    cleanup_header.msg_type == DTRACED_MSG_CLEANUP &&
	    cleanup_header.cleanup.vmid == source.vmid &&
	    cleanup_header.cleanup.epoch == source.vm_epoch &&
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(cleanup_header) != 0);
	std::atomic_bool cut_returned{false};
	std::thread cut([&] {
		durable_handoff unused{};
		assert(journal.source_handoff_for_vm(source.vmid,
		    source.vm_epoch, unused) == 0);
		cut_returned.store(true);
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	assert(!cut_returned.load());
	dtraced_delivery_ack_t cleanup_ack{
	    DTRACED_MSG_CLEANUP_DELIVERY_ID(cleanup_header)};
	unsigned char ack_wire[DTRACED_ACK_WIRE_SIZE];
	dtraced_wire_encode_ack(ack_wire, &cleanup_ack);
	assert(dtraced_io_transfer(peer_fd, ack_wire,
	    sizeof(ack_wire), true, deadline, &transferred) == 0);
	cleanup_sender.join();
	cut.join();
	assert(cleanup_sent.load() && cut_returned.load());
	assert(journal.cleanup_status(pending) == 'a');
	assert(journal.record_cleanup_queued(pending));
	assert(!journal.record_cleanup_pending(pending) && errno == EALREADY);
	assert(journal.list_pending_cleanups(recovered) && recovered.empty());
	{
		dir reopened(journal.full_path().c_str(), nullptr);
		std::vector<durable_cleanup> on_disk;
		assert(reopened.list_pending_cleanups(on_disk) &&
		    on_disk.empty());
		assert(reopened.cleanup_status(pending) == 'a');
	}
	std::vector<uint8_t> cleanup_transfer;
	assert(journal.source_journal_transfer_wire_export(cleanup_cut,
	    cleanup_transfer));
	/* The production EXPORT handler must return the same journal-bearing
	 * HTX1 as the locked source-cut builder. */
	dtraced_handoff_request_t export_wire{};
	export_wire.op = DTRACED_HANDOFF_EXPORT;
	memcpy(export_wire.token, cleanup_cut.token.data(),
	    cleanup_cut.token.size());
	dtraced_hdr_t export_header{};
	export_header.msg_type = DTRACED_MSG_HANDOFF;
	client_request unguarded(host, export_header,
	    (unsigned char *)&export_wire, sizeof(export_wire), &source);
	assert(!unguarded.handle() && errno == EBUSY);
	assert(journal.source_gate_begin(cleanup_cut));
	client_request exported(host, export_header,
	    (unsigned char *)&export_wire, sizeof(export_wire), &source);
	assert(exported.handle() && exported.transfer_response() != nullptr &&
	    *exported.transfer_response() == cleanup_transfer);
	assert(journal.source_gate_abort(cleanup_cut));
	memcpy(cleanup_cut.transfer_digest.data(),
	    cleanup_transfer.data() + cleanup_transfer.size() -
	    SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
	/* The queued cleanup is now bound into HTX1, but nonempty restore
	 * remains fenced before PREPARE can release the source. */
	assert(!journal.prepare_handoff(cleanup_cut, false) &&
	    errno == EOPNOTSUPP);
	durable_cleanup applied_record = pending;
	applied_record.delivery_id = 0x889b;
	assert(journal.record_cleanup_pending(applied_record));
	assert(journal.record_cleanup_queued(applied_record));
	dtraced_hdr_t applied_header{};
	applied_header.msg_type = DTRACED_MSG_CLEANUP_APPLIED;
	applied_header.cleanup.vmid = applied_record.vmid;
	applied_header.cleanup.epoch = applied_record.epoch;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(applied_header) =
	    applied_record.delivery_id;
	client_request applied(host, applied_header, nullptr, 0, &source);
	assert(applied.handle());
	assert(journal.cleanup_status(applied_record) == 'g');
	assert(journal.record_cleanup_applied(applied_record));
	applied_header.cleanup.epoch++;
	client_request wrong_lifetime(host, applied_header, nullptr, 0,
	    &source);
	assert(!wrong_lifetime.handle() && errno == EPROTO);
	assert(!journal.record_cleanup_queued(applied_record) &&
	    errno == EALREADY);
	assert(!journal.record_cleanup_pending(applied_record) &&
	    errno == EALREADY);
	{
		dir reopened(journal.full_path().c_str(), nullptr);
		assert(reopened.cleanup_status(applied_record) == 'g');
		std::vector<durable_cleanup> on_disk;
		assert(reopened.list_pending_cleanups(on_disk) && on_disk.empty());
	}
}

int
main()
{
	/* This fixture fsyncs many independent journals; leave room for busy
	 * build hosts while still detecting a blocked handoff path. */
	alarm(30);
	char path[] = "/tmp/hypertrace-handoff-control.XXXXXX";
	char ingresspath[] = "/tmp/hypertrace-handoff-control-ingress.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	assert(mkdtemp(ingresspath) != nullptr);
	{
		dir journal(path, nullptr);
		dir incoming(ingresspath, nullptr);
		state host{};
		state_attestation_test::set_control(host);
		EVP_PKEY *source_key = new_release_key();
		EVP_PKEY *peer_key = new_release_key();
		std::string private_path = std::string(path) + "/private.pem";
		std::string peer_path = std::string(path) + "/peer.pem";
		std::string peer_private_path =
		    std::string(path) + "/peer-private.pem";
		std::string source_public_path =
		    std::string(path) + "/source-public.pem";
		write_release_key(private_path, source_key, true);
		write_release_key(peer_path, peer_key, false);
		write_release_key(peer_private_path, peer_key, true);
		write_release_key(source_public_path, source_key, false);
		assert(host.handoff_keys.load(private_path.c_str(),
		    peer_path.c_str()));
		EVP_PKEY_free(peer_key);
		EVP_PKEY_free(source_key);
		host.outbounddir = &journal;
		host.inbounddir = &incoming;
		journal.state = &host;
		incoming.state = &host;
		int kq = kqueue(), source_pair[2], destination_pair[2];
		int destination_outbound_pair[2], rival_pair[2];
		assert(kq >= 0);
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, source_pair) == 0);
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, destination_pair) == 0);
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
		    destination_outbound_pair) == 0);
		assert(socketpair(AF_UNIX, SOCK_STREAM, 0, rival_pair) == 0);
		{
			dtd_initmsg_t hello{};
			hello.kind = DTRACED_KIND_FORWARDER;
			hello.subs = DTD_SUB_READDATA | DTD_SUB_KILL;
			hello.protocol_version = DTRACED_PROTOCOL_VERSION;
			hello.session_id[0] = 0x31;
			strlcpy(hello.ident, "source-vm", sizeof(hello.ident));
			client_fd source(kq, source_pair[0], hello);
			hello.session_id[0] = 0x32;
			strlcpy(hello.ident, "destination-vm",
			    sizeof(hello.ident));
			client_fd destination(kq, destination_pair[0], hello);
			hello.session_id[0] = 0x33;
			strlcpy(hello.ident, "rival-vm", sizeof(hello.ident));
			client_fd rival(kq, rival_pair[0], hello);
			hello.session_id[0] = 0x32;
			hello.subs = DTD_SUB_ELFWRITE;
			strlcpy(hello.ident, "destination-vm",
			    sizeof(hello.ident));
			client_fd destination_outbound(kq,
			    destination_outbound_pair[0], hello);
			source_attestation_fd = source.vm_attestation_fd =
			    dup(source_pair[0]);
			destination_attestation_fd =
			    destination.vm_attestation_fd = dup(destination_pair[0]);
			assert(source_attestation_fd >= 0 &&
			    destination_attestation_fd >= 0);
			rival_attestation_fd = rival.vm_attestation_fd =
			    dup(rival_pair[0]);
			assert(rival_attestation_fd >= 0);
			destination_outbound_attestation_fd =
			    destination_outbound.vm_attestation_fd =
			    dup(destination_outbound_pair[0]);
			assert(destination_outbound_attestation_fd >= 0);
			source.vmid = source_vm.vmid = 7;
			source.vm_epoch = source_vm.epoch = 11;
			strlcpy(source_vm.name, "source-vm",
			    sizeof(source_vm.name));
			destination.vmid = destination_vm.vmid = 8;
			destination.vm_epoch = destination_vm.epoch = 22;
			destination_outbound.vmid = destination.vmid;
			destination_outbound.vm_epoch = destination.vm_epoch;
			strlcpy(destination_vm.name, "destination-vm",
			    sizeof(destination_vm.name));
			rival.vmid = rival_vm.vmid = 9;
			rival.vm_epoch = rival_vm.epoch = 33;
			strlcpy(rival_vm.name, "rival-vm", sizeof(rival_vm.name));
			test_cleanup_cut(host, journal, source, source_pair[1]);
			auto send = [&](client_fd &peer,
			    const dtraced_handoff_request_t &wire) {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF;
				client_request request(host, header,
				    (unsigned char *)&wire, sizeof(wire), &peer);
				return (request.handle());
			};
			auto migrated_status = [&]() {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_STATUS;
				header.installed.delivery_id = 77;
				header.installed.vmid = destination.vmid;
				header.installed.epoch = destination.vm_epoch;
				header.installed.program_id[0] = 1;
				header.installed.source_id[0] = 2;
				strlcpy(header.installed.name, "destination-vm",
				    sizeof(header.installed.name));
				client_request request(host, header, nullptr, 0,
				    &destination);
				assert(request.handle() &&
				    request.status_response() != nullptr);
				return (*request.status_response());
			};
			auto migrated_observation = [&](uint64_t kind) {
				dtraced_hdr_t header{};
				header.msg_type = kind;
				header.installed.delivery_id = 77;
				header.installed.vmid = destination.vmid;
				header.installed.epoch = destination.vm_epoch;
				header.installed.program_id[0] = 1;
				header.installed.source_id[0] = 2;
				strlcpy(header.installed.name, "destination-vm",
				    sizeof(header.installed.name));
				client_request request(host, header, nullptr, 0,
				    &destination);
				return (request.handle());
			};
			durable_delivery delivery{};
			delivery.session_id = source.session_id;
			delivery.delivery_id = 77;
			delivery.vmid = source.vmid;
			delivery.epoch = source.vm_epoch;
			delivery.program_id[0] = 1;
			delivery.source_id[0] = 2;
			delivery.peer_uid = source.peer_uid;
			delivery.peer_pid = source.peer_pid;
			delivery.journal_version = 4;
			const unsigned char bare_elf[] = "\177ELFDATA";
			assert(SHA256(bare_elf, sizeof(bare_elf) - 1,
			    delivery.payload_digest.data()) != nullptr);
			assert(journal.record_delivery(delivery,
			    delivery_phase::pending, true));
			assert(journal.record_delivery(delivery,
			    delivery_phase::accepted));
			durable_kill killed{};
			killed.pid = 123;
			killed.vmid = source.vmid;
			killed.epoch = source.vm_epoch;
			killed.source_id[0] = 3;
			durable_kill unsettled = killed;
			unsettled.source_id[0] = 4;
			assert(journal.record_kill(unsettled));
			dtraced_handoff_delivery_request_t lookup{};
			lookup.token[0] = 0xa1;
			lookup.digest[0] = 0xb2;
			lookup.delivery_id = 77;
			lookup.program_id[0] = 1;
			lookup.source_id[0] = 2;
			auto lookup_status = [&](client_fd &peer,
			    dtraced_delivery_status_t &reply) {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_DELIVERY;
				client_request request(host, header,
				    (unsigned char *)&lookup, sizeof(lookup), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				reply = *request.status_response();
				return (true);
			};
			auto bind_delivery = [&](client_fd &peer,
			    dtraced_delivery_status_t &reply) {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_BIND_DELIVERY;
				dtraced_handoff_bind_delivery_request_t bound{};
				bound.delivery = lookup;
				memcpy(bound.payload_digest,
				    delivery.payload_digest.data(), 32);
				unsigned char wire[
				    DTRACED_HANDOFF_BIND_DELIVERY_WIRE_SIZE];
				dtraced_wire_encode_handoff_bind_delivery(wire,
				    &bound);
				client_request request(host, header,
				    wire, sizeof(wire), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				reply = *request.status_response();
				return (true);
			};
			dtraced_delivery_status_t reply{};
			dtraced_handoff_kill_request_t kill_lookup{};
			kill_lookup.token[0] = 0xa1;
			kill_lookup.digest[0] = 0xb2;
			kill_lookup.pid = 123;
			kill_lookup.source_id[0] = 3;
			auto kill_status = [&](client_fd &peer,
			    dtraced_delivery_status_t &result) {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_KILL;
				client_request request(host, header,
				    (unsigned char *)&kill_lookup,
				    sizeof(kill_lookup), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				result = *request.status_response();
				return (true);
			};
			auto bind_kill = [&](client_fd &peer,
			    dtraced_delivery_status_t &result) {
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_BIND_KILL;
				client_request request(host, header,
				    (unsigned char *)&kill_lookup,
				    sizeof(kill_lookup), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				result = *request.status_response();
				return (true);
			};
			dtraced_handoff_cleanup_request_t cleanup_lookup{};
			cleanup_lookup.token[0] = 0xa1;
			cleanup_lookup.digest[0] = 0xb2;
			cleanup_lookup.delivery_id = 0x8899;
			auto cleanup_status = [&](client_fd &peer,
			    dtraced_delivery_status_t &result) {
				unsigned char body[DTRACED_HANDOFF_CLEANUP_WIRE_SIZE];
				dtraced_wire_encode_handoff_cleanup(body,
				    &cleanup_lookup);
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_CLEANUP;
				client_request request(host, header, body,
				    sizeof(body), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				result = *request.status_response();
				return (true);
			};
			dtraced_handoff_request_t wire{};
			wire.op = DTRACED_HANDOFF_PREPARE;
			wire.token[0] = 0xa1;
			auto bind_empty_bundle = [](dtraced_handoff_request_t &request) {
				std::vector<uint8_t> bytes;
				assert(dtraced_transfer_wire_build(request.token, {}, {}, bytes));
				memcpy(request.digest, bytes.data() + bytes.size() - 32, 32);
			};
			/* This source has deliberately unsettled journal records for the
			 * later PREPARE refusal. Exercise empty EXPORT on a clean VM. */
			source.vmid = source_vm.vmid = 27;
			source.vm_epoch = source_vm.epoch = 29;
			durable_handoff export_gate{};
			/* The fake VMM gate stores one token for all synthetic VMs;
			 * use a distinct token so its post-RESUME memory cannot collide
			 * with the real source VM's later handoff. */
			export_gate.token[0] = 0xe1;
			export_gate.source_session = source.session_id;
			export_gate.source_vmid = source.vmid;
			export_gate.source_epoch = source.vm_epoch;
			assert(journal.source_gate_begin(export_gate));
			{
				dtraced_handoff_request_t query = wire;
				query.op = DTRACED_HANDOFF_EXPORT;
				query.token[0] = export_gate.token[0];
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF;
				client_request exported(host, header,
				    (unsigned char *)&query, sizeof(query), &source);
				assert(exported.handle() &&
				    exported.transfer_response() != nullptr);
				const auto &bytes = *exported.transfer_response();
				assert(bytes.size() == DTRACED_TRANSFER_HEADER_SIZE +
				    DTRACED_TRANSFER_DIGEST_SIZE &&
				    dtraced_transfer_wire_valid(bytes.data(), bytes.size(),
				    query.token));
				memcpy(wire.digest, bytes.data() + bytes.size() - 32, 32);
				assert(source.respond_with_transfer(true,
				    exported.transfer_response()));
				uint8_t ack, size_wire[8], received[64];
				size_t transferred;
				int64_t deadline = dtraced_io_deadline_after(2000);
				assert(dtraced_io_transfer(source_pair[1], &ack, 1,
				    false, deadline, &transferred) == 0 && ack == 1);
				assert(dtraced_io_transfer(source_pair[1], size_wire, 8,
				    false, deadline, &transferred) == 0 &&
				    dtraced_wire_get_u64(size_wire) == sizeof(received));
				assert(dtraced_io_transfer(source_pair[1], received,
				    sizeof(received), false, deadline, &transferred) == 0 &&
				    dtraced_transfer_wire_valid(received,
				    sizeof(received), query.token));
				query.digest[0] = 1;
				client_request invalid(host, header,
				    (unsigned char *)&query, sizeof(query), &source);
				assert(!invalid.handle() && errno == EPROTO &&
				    invalid.transfer_response() == nullptr);
			}
			assert(journal.source_gate_abort(export_gate));
			source.vmid = source_vm.vmid = 7;
			source.vm_epoch = source_vm.epoch = 11;
			auto source_status = [&](client_fd &peer,
			    dtraced_delivery_status_t &result) {
				dtraced_handoff_request_t query = wire;
				query.op = DTRACED_HANDOFF_SOURCE_STATUS;
				memset(query.digest, 0, sizeof(query.digest));
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF;
				client_request request(host, header,
				    (unsigned char *)&query, sizeof(query), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				result = *request.status_response();
				return (true);
			};
			auto destination_status = [&](client_fd &peer,
			    dtraced_delivery_status_t &result) {
				dtraced_handoff_request_t query = wire;
				query.op = DTRACED_HANDOFF_DESTINATION_STATUS;
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF;
				client_request request(host, header,
				    (unsigned char *)&query, sizeof(query), &peer);
				if (!request.handle())
					return (false);
				assert(request.status_response() != nullptr);
				result = *request.status_response();
				return (true);
			};
			assert(source_status(source, reply) && reply.phase == 0);
			wire.digest[0] = 0xb2;
			assert(!destination_status(destination, reply) &&
			    errno == ENOENT);
			bind_empty_bundle(wire);
			/* PREPARE must be able to bind the accepted source ELF. */
			hypertrace_vm_envelope envelope{};
			envelope.magic = HYPERTRACE_TARGET_MAGIC;
			envelope.version = HYPERTRACE_ENVELOPE_VERSION;
			envelope.vmid = source.vmid;
			envelope.epoch = source.vm_epoch;
			unsigned char spool[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
			    sizeof(bare_elf) - 1]{};
			hypertrace_envelope_encode(spool, &envelope);
			memcpy(spool + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, bare_elf,
			    sizeof(bare_elf) - 1);
			std::vector<uint8_t> portable(spool,
			    spool + sizeof(spool));
			assert(dir::validate_host_delivery_payload(delivery,
			    portable));
			durable_delivery wrong_vm = delivery;
			wrong_vm.vmid++;
			assert(!dir::validate_host_delivery_payload(wrong_vm,
			    portable) && errno == EPROTO);
			assert(journal.write_identified_data(spool, sizeof(spool),
			    delivery.program_id.data(), nullptr,
			    delivery.source_id.data()));
			durable_delivery in_flight = delivery;
			in_flight.delivery_id = 78;
			in_flight.program_id[0] = 4;
			assert(journal.record_delivery(in_flight,
			    delivery_phase::pending, true));
			assert(!send(source, wire) && errno == EBUSY);
			assert(journal.record_kill_applied(unsettled));
			assert(!send(source, wire) && errno == EBUSY);
			assert(journal.record_delivery(in_flight,
			    delivery_phase::accepted));
			durable_delivery finished = in_flight;
			assert(journal.record_delivery(finished,
			    delivery_phase::terminal));
			durable_handoff unbound{};
			unbound.token[0] = wire.token[0];
			unbound.source_session = source.session_id;
			unbound.source_vmid = source.vmid;
			unbound.source_epoch = source.vm_epoch;
			assert(!journal.prepare_handoff(unbound, false) && errno == EPROTO);
			assert(!send(source, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_SOURCE_GATE_BEGIN;
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(send(source, wire));
			wire.op = DTRACED_HANDOFF_PREPARE;
			bind_empty_bundle(wire);
			wire.op = DTRACED_HANDOFF_SOURCE_DRAIN_STEP;
			{
				dtraced_hdr_t drain_header{};
				drain_header.msg_type = DTRACED_MSG_HANDOFF;
				client_request drain(host, drain_header,
				    (unsigned char *)&wire, sizeof(wire), &source);
				assert(drain.handle() &&
				    drain.drain_step_response() != nullptr &&
				    *drain.drain_step_response() == 0);
			}
			wire.op = DTRACED_HANDOFF_PREPARE;
			wire.digest[0] ^= 1;
			assert(!send(source, wire) && errno == EPROTO);
			wire.digest[0] ^= 1;
			/* Exercise the legacy ticket state machine separately from the
			 * control-machine HJX1 fence tested above. A modern accepted
			 * delivery cannot PREPARE with this empty HTX1 digest. */
			journal.state = nullptr;
			assert(send(source, wire));
			journal.state = &host;
			assert(source_status(source, reply) && reply.phase == 'p' &&
			    memcmp(reply.digest, wire.digest, 32) == 0);
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(!destination_status(destination, reply) &&
			    errno == EPROTO);
			wire.digest[0] = 0xb2;
			assert(!destination_status(destination, reply) &&
			    errno == EBUSY);
			wire.digest[0] = 0;
			assert(!source_status(destination, reply) && errno == EPERM);
			assert(journal.record_kill(killed));
			job deferred(KILL, &source);
			kill_job &target = deferred.kill_get();
			target.pid = killed.pid;
			target.vmid = killed.vmid;
			target.epoch = killed.epoch;
			memcpy(target.source_id, killed.source_id.data(), 16);
			assert(!deferred.send_kill(host) && errno == EBUSY &&
			    deferred.handoff_deferred);
			in_flight.delivery_id = 79;
			assert(!journal.record_delivery(in_flight,
			    delivery_phase::pending, true) && errno == EBUSY);
			assert(!journal.record_delivery(delivery,
			    delivery_phase::installed) && errno == EBUSY);
			bind_empty_bundle(wire);
			/* The historical ticket stays readable, but a modern PREPARE
			 * retry cannot reauthorize a cut with an unapplied KILL. */
			assert(!send(source, wire) && errno == EBUSY);
			assert(!send(destination, wire) && errno == EPROTO);
			durable_handoff observed{};
			std::array<uint8_t, 16> token{};
			token[0] = 0xa1;
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::prepared);
			assert(observed.source_session == source.session_id &&
			    observed.source_vmid == 7 && observed.source_epoch == 11);
			wire.op = DTRACED_HANDOFF_COMMIT;
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(!send(source, wire) && errno == EPROTO);
			wire.digest[0] = 0xb2;
			assert(!send(destination, wire) && errno == EPERM);
			/* This deliberately synthetic ticket used the legacy empty cut.
			 * The production COMMIT now rejects its changed journal. */
			journal.state = nullptr;
			assert(send(source, wire));
			assert(send(source, wire));
			journal.state = &host;
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::committed &&
			    observed.checkpoint_digest[0] == 0xb2);
			assert(source_status(source, reply) && reply.phase == 'c' &&
			    reply.digest[0] == 0xb2);
			{
				dtraced_handoff_request_t early = wire;
				early.op = DTRACED_HANDOFF_RESERVE;
				assert(!send(destination, early) && errno == EBUSY);
			}
			{
				int release_pair[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    release_pair) == 0);
				dtd_initmsg_t release_hello{};
				release_hello.kind = DTRACED_KIND_FORWARDER;
				release_hello.subs = DTD_SUB_SOURCE_RELEASE |
				    DTD_SUB_ADMISSION_ACK;
				release_hello.protocol_version =
				    DTRACED_PROTOCOL_VERSION;
				memcpy(release_hello.session_id,
				    source.session_id.data(), 16);
				strlcpy(release_hello.ident, "source-vm",
				    sizeof(release_hello.ident));
				client_fd release(kq, release_pair[0], release_hello);
				release.vmid = source.vmid;
				release.vm_epoch = source.vm_epoch;
				release.vm_attestation_fd = dup(source_pair[0]);
				release.vm_epoch_query_fd = dup(source_pair[0]);
				epoch_query_fd = release.vm_epoch_query_fd;
				assert(release.vm_attestation_fd >= 0 &&
				    release.vm_epoch_query_fd >= 0 &&
				    !release.current_vm_attestation());
				dtraced_handoff_request_t released = wire;
				released.op = DTRACED_HANDOFF_SOURCE_RELEASE;
				assert(!send(source, released) && errno == EPROTO);
				assert(!send(release, wire) && errno == EPROTO);
				assert(!send(release, released) && errno == EBUSY &&
				    journal.source_release_status(observed) == 0);
				epoch_query_live = false;
				released.digest[0]++;
				assert(!send(release, released) && errno == EPROTO);
				released.digest[0]--;
				dtraced_hdr_t release_header{};
				release_header.msg_type = DTRACED_MSG_HANDOFF;
				client_request release_request(host, release_header,
				    (unsigned char *)&released, sizeof(released),
				    &release);
				assert(release_request.handle() &&
				    release_request.release_response() != nullptr &&
				    release_request.release_response_signed());
				assert(release.respond_with_release(true,
				    release_request.release_response(), true));
				uint8_t ack, mode, response[DTRACED_RELEASE_ATTESTED_SIZE];
				assert(recv(release_pair[1], &ack, 1, MSG_WAITALL) == 1 &&
				    ack == 1);
				assert(recv(release_pair[1], &mode, 1, MSG_WAITALL) == 1 &&
				    mode == DTRACED_RELEASE_MODE_SIGNED);
				assert(recv(release_pair[1], response,
				    sizeof(response), MSG_WAITALL) ==
				    (ssize_t)sizeof(response));
				assert(memcmp(response, release_request.release_response(),
				    sizeof(response)) == 0);
				assert(journal.source_release_status(observed) == 1 &&
				    send(release, released));
				std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE>
				    signed_release{};
				assert(journal.read_source_release_attestation(observed,
				    host.handoff_keys.own_public().data(),
				    host.handoff_keys.peer_public().data(),
				    signed_release));
				assert(dir::verify_source_release_attestation(observed,
				    host.handoff_keys.own_public().data(),
				    host.handoff_keys.peer_public().data(),
				    signed_release.data()));
				{
					char foreign_path[] =
					    "/tmp/hypertrace-release-control.XXXXXX";
					assert(mkdtemp(foreign_path) != nullptr);
					{
						dir foreign_journal(foreign_path, nullptr);
						state foreign_host{};
						state_attestation_test::set_control(foreign_host);
						assert(foreign_host.handoff_keys.load(
						    peer_private_path.c_str(),
						    source_public_path.c_str()));
						foreign_host.outbounddir = &foreign_journal;
						foreign_journal.state = &foreign_host;
						std::array<uint8_t,
						    DTRACED_HANDOFF_RELEASE_IMPORT_SIZE> body{};
						memcpy(body.data(), observed.token.data(), 16);
						memcpy(body.data() + 16,
						    observed.checkpoint_digest.data(), 32);
						memcpy(body.data() + 48,
						    signed_release.data(), signed_release.size());
						dtraced_hdr_t import_header{};
						import_header.msg_type =
						    DTRACED_MSG_HANDOFF_RELEASE_IMPORT;
						client_request local_import(host,
						    import_header, body.data(), body.size(),
						    &destination);
						assert(local_import.handle());
						auto import = [&]() {
							client_request request(foreign_host,
							    import_header, body.data(), body.size(),
							    &destination);
							return (request.handle());
						};
						assert(import() && import());
						durable_handoff imported{};
						assert(foreign_journal.read_imported_source_release(
						    foreign_host.handoff_keys.peer_public().data(),
						    foreign_host.handoff_keys.own_public().data(),
						    observed.token.data(),
						    observed.checkpoint_digest.data(), imported) == 1);
						assert(foreign_journal.populate_existing());
						char imported_name[43];
						memcpy(imported_name, ".imported.", 10);
						static const char hex[] = "0123456789abcdef";
						for (size_t i = 0; i < observed.token.size(); i++) {
							imported_name[10 + i * 2] =
							    hex[observed.token[i] >> 4];
							imported_name[11 + i * 2] =
							    hex[observed.token[i] & 15];
						}
						imported_name[42] = '\0';
						int proof_fd = openat(foreign_journal.dirfd,
						    imported_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
						assert(proof_fd >= 0);
						uint8_t damaged = signed_release.back() ^ 1;
						assert(pwrite(proof_fd, &damaged, 1,
						    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
						    fsync(proof_fd) == 0 &&
						    !foreign_journal.populate_existing() &&
						    errno == EPROTO &&
						    pwrite(proof_fd, &signed_release.back(), 1,
						    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
						    fsync(proof_fd) == 0 && close(proof_fd) == 0 &&
						    foreign_journal.populate_existing());
						assert(foreign_journal.handoff_status(
						    observed.token, imported) == 0);
						dtraced_handoff_request_t foreign_reserve = wire;
						foreign_reserve.op = DTRACED_HANDOFF_RESERVE;
						auto reserve_foreign = [&]() {
							dtraced_hdr_t header{};
							header.msg_type = DTRACED_MSG_HANDOFF;
							client_request request(foreign_host, header,
							    (unsigned char *)&foreign_reserve,
							    sizeof(foreign_reserve), &destination);
							return (request.handle());
						};
						foreign_reserve.digest[0] ^= 1;
						assert(!reserve_foreign() && errno == EPROTO &&
						    foreign_journal.handoff_status(observed.token,
						    imported) == 0);
						foreign_reserve.digest[0] ^= 1;
						assert(reserve_foreign());
						assert(foreign_journal.handoff_status(
						    observed.token, imported) ==
						    (int)handoff_phase::reserved);
						assert(reserve_foreign());
						assert(foreign_journal.handoff_status(
						    observed.token, imported) ==
						    (int)handoff_phase::reserved);
						assert(imported.destination_vmid == destination.vmid &&
						    imported.destination_epoch == destination.vm_epoch);
						assert(foreign_journal.populate_existing());
						assert(!foreign_journal.begin_handoff_mutation(imported) &&
						    errno == EOPNOTSUPP);
						proof_fd = openat(foreign_journal.dirfd,
						    imported_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
						assert(proof_fd >= 0);
						assert(pwrite(proof_fd, &damaged, 1,
						    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
						    fsync(proof_fd) == 0 &&
						    !reserve_foreign() && errno == EPROTO &&
						    pwrite(proof_fd, &signed_release.back(), 1,
						    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
						    fsync(proof_fd) == 0 && close(proof_fd) == 0 &&
						    reserve_foreign());
						body.back() ^= 1;
						assert(!import() && errno == EPROTO);
						body.back() ^= 1;
						body[16] ^= 1;
						assert(!import() && errno == EPROTO);
						body[16] ^= 1;
						DIR *scan = opendir(foreign_path);
						assert(scan != nullptr);
						for (dirent *entry;
						    (entry = readdir(scan)) != nullptr; )
							if (strcmp(entry->d_name, ".") != 0 &&
							    strcmp(entry->d_name, "..") != 0)
								assert(unlinkat(foreign_journal.dirfd,
								    entry->d_name, 0) == 0);
						assert(closedir(scan) == 0);
					}
					assert(rmdir(foreign_path) == 0);
				}
				int recovery_pair[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    recovery_pair) == 0);
				dtd_initmsg_t recovery_hello{};
				recovery_hello.kind = DTRACED_KIND_RELEASE_RECOVERY;
				recovery_hello.subs = DTD_SUB_RELEASE_RECOVERY;
				recovery_hello.protocol_version =
				    DTRACED_PROTOCOL_VERSION;
				strlcpy(recovery_hello.ident,
				    "hypertrace-release-recovery",
				    sizeof(recovery_hello.ident));
				client_fd recovery(kq, recovery_pair[0],
				    recovery_hello);
				recovery.peer_uid = 0;
				recovery.peer_pid = 42;
				dtraced_handoff_request_t recover = released;
				recover.op = DTRACED_HANDOFF_RELEASE_RECOVER;
				client_request recover_request(host, release_header,
				    (unsigned char *)&recover, sizeof(recover),
				    &recovery);
				assert(recover_request.handle() &&
				    recover_request.release_response_signed() &&
				    memcmp(recover_request.release_response(),
				    signed_release.data(), signed_release.size()) == 0);
				recover.digest[0]++;
				client_request wrong_recovery(host, release_header,
				    (unsigned char *)&recover, sizeof(recover),
				    &recovery);
				assert(!wrong_recovery.handle() && errno == EPROTO);
				recover.digest[0]--;
				recover.op = DTRACED_HANDOFF_SOURCE_STATUS;
				client_request wrong_op(host, release_header,
				    (unsigned char *)&recover, sizeof(recover),
				    &recovery);
				assert(!wrong_op.handle() && errno == EPROTO);
				close(recovery_pair[1]);
				close(release_pair[1]);
				epoch_query_fd = -1;
			}
			assert(destination_status(destination, reply) &&
			    reply.phase == 'c' && reply.digest[0] == 0xb2);
			assert(destination_status(rival, reply) &&
			    reply.phase == 'c');
			wire.digest[0]++;
			assert(!destination_status(destination, reply) &&
			    errno == EPROTO);
			wire.digest[0]--;
			assert(!lookup_status(destination, reply) && errno == EBUSY);
			assert(!kill_status(destination, reply) && errno == EBUSY);
			wire.digest[0]++;
			assert(!send(source, wire) && errno == EPROTO);
			wire.digest[0]--;
			wire.op = DTRACED_HANDOFF_RESERVE;
			assert(!send(source, wire) && errno == EINVAL);
			assert(send(destination, wire));
			assert(send(destination, wire));
			assert(!send(rival, wire) && errno == EPERM);
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::reserved &&
			    observed.destination_vmid == 8 &&
			    observed.destination_epoch == 22);
			{
				std::vector<uint8_t> bundle;
				assert(dtraced_transfer_wire_build(token.data(),
				    {}, {}, bundle));
				std::vector<uint8_t> body(48 + bundle.size());
				memcpy(body.data(), token.data(), 16);
				memcpy(body.data() + 16, wire.digest, 32);
				memcpy(body.data() + 48, bundle.data(),
				    bundle.size());
				dtraced_hdr_t header{};
				header.msg_type = DTRACED_MSG_HANDOFF_IMPORT;
				uint8_t header_wire[DTRACED_MSGHDRSIZE];
				dtraced_wire_encode_header(header_wire, &header);
				dtraced_hdr_t decoded{};
				assert(dtraced_wire_decode_header(&decoded,
				    header_wire) == 0 &&
				    decoded.msg_type == DTRACED_MSG_HANDOFF_IMPORT);
				auto import = [&](client_fd &peer) {
					client_request request(host, decoded,
					    body.data(), body.size(), &peer);
					return (request.handle());
				};
				assert(!import(rival) && errno == EPERM);
				body[16]++;
				assert(!import(destination) && errno == EPERM);
				body[16]--;
				body.back()++;
				assert(!import(destination) && errno == EPROTO);
				body.back()--;
				assert(import(destination));
				assert(import(destination));
			}
			assert(journal.handoff_cleanup_status(observed, 0x8899) == 'a');
			assert(journal.handoff_cleanup_status(observed, 0x889a) == 0);
			assert(cleanup_status(destination, reply) &&
			    reply.delivery_id == 0x8899 && reply.phase == 'a' &&
			    reply.revoked == 0 && reply.replay == 0);
			cleanup_lookup.delivery_id++;
			assert(cleanup_status(destination, reply) && reply.phase == 0);
			cleanup_lookup.delivery_id--;
			assert(!cleanup_status(rival, reply) && errno == EPERM);
			durable_handoff wrong_cleanup_claim = observed;
			wrong_cleanup_claim.destination_vmid = rival.vmid;
			wrong_cleanup_claim.destination_epoch = rival.vm_epoch;
			assert(journal.handoff_cleanup_status(wrong_cleanup_claim,
			    0x8899) == -1 && errno == EPERM);
			assert(destination_status(destination, reply) &&
			    reply.phase == 'v' && reply.digest[0] == 0xb2);
			assert(!destination_status(rival, reply) && errno == EPERM);
			assert(lookup_status(destination, reply) &&
			    reply.delivery_id == 77 &&
			    reply.phase == (uint8_t)delivery_phase::accepted &&
			    reply.revoked == 0 && reply.replay == 0 &&
			    memcmp(reply.digest, delivery.payload_digest.data(),
			    sizeof(reply.digest)) == 0);
			durable_delivery upload = delivery;
			upload.scope = 3;
			upload.session_id[0] = 0x21; /* an earlier source socket */
			upload.delivery_id = 80;
			upload.payload_digest[0] = 0x88;
			assert(incoming.record_delivery(upload,
			    delivery_phase::pending, true));
			assert(incoming.record_delivery(upload,
			    delivery_phase::accepted));
			lookup.scope = 3;
			lookup.delivery_id = upload.delivery_id;
			assert(lookup_status(destination, reply) &&
			    reply.phase == 'a' && reply.revoked == 0 &&
			    reply.digest[0] == 0x88);
			assert(!bind_delivery(destination, reply) && errno == EPROTO);
			assert(!lookup_status(rival, reply) && errno == EPERM);
			lookup.scope = 0;
			assert(lookup_status(destination, reply) && reply.phase == 0);
			lookup.delivery_id = delivery.delivery_id;
			assert(lookup_status(destination, reply) &&
			    memcmp(reply.digest, delivery.payload_digest.data(),
			    sizeof(reply.digest)) == 0);
			lookup.delivery_id = 78;
			lookup.program_id[0] = 4;
			assert(lookup_status(destination, reply) &&
			    reply.phase == (uint8_t)delivery_phase::terminal &&
			    reply.replay == 0 && reply.digest[0] == 0);
			lookup.delivery_id = 77;
			lookup.program_id[0] = 1;
			assert(kill_status(destination, reply) &&
			    reply.delivery_id == 123 && reply.phase == 'p' &&
			    reply.revoked == 1 && reply.replay == 0);
			assert(!kill_status(rival, reply) && errno == EPERM);
			kill_lookup.digest[0]++;
			assert(!kill_status(destination, reply) && errno == EPROTO);
			kill_lookup.digest[0]--;
			kill_lookup.reserved[0] = 1;
			assert(!kill_status(destination, reply) && errno == EPROTO);
			kill_lookup.reserved[0] = 0;
			kill_lookup.pid++;
			assert(kill_status(destination, reply) &&
			    reply.delivery_id == 124 && reply.phase == 0 &&
			    reply.revoked == 1 && reply.replay == 0);
			const char *orphan =
			    ".killack.0007.000000000000000b.0000007c."
			    "03000000000000000000000000000000";
			int orphan_fd = openat(journal.dirfd, orphan,
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(orphan_fd >= 0 && close(orphan_fd) == 0);
			assert(!kill_status(destination, reply) && errno == EPROTO);
			assert(unlinkat(journal.dirfd, orphan, 0) == 0);
			kill_lookup.pid--;
			kill_lookup.source_id[0] = 5;
			assert(kill_status(destination, reply) &&
			    reply.phase == 0 && reply.revoked == 0 &&
			    reply.replay == 0);
			kill_lookup.source_id[0] = 3;
			assert(journal.record_kill_applied(killed));
			assert(kill_status(destination, reply) &&
			    reply.phase == 'a' && reply.replay == 0);
			assert(!lookup_status(rival, reply) && errno == EPERM);
			lookup.digest[0]++;
			assert(!lookup_status(destination, reply) && errno == EPROTO);
			lookup.digest[0]--;
			lookup.reserved[0] = 1;
			assert(!lookup_status(destination, reply) && errno == EPROTO);
			lookup.reserved[0] = 0;
			lookup.scope = 1;
			assert(!lookup_status(destination, reply) && errno == EPROTO);
			lookup.scope = 0;
			lookup.delivery_id++;
			assert(lookup_status(destination, reply) &&
			    reply.phase == 0 && reply.replay == 0);
			lookup.delivery_id--;
			assert(!bind_delivery(destination, reply) &&
			    errno == EBUSY);
			wire.digest[0]++;
			assert(!send(destination, wire) && errno == EPROTO);
			wire.digest[0]--;
			wire.op = DTRACED_HANDOFF_CANCEL;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::committed);
			wire.op = DTRACED_HANDOFF_RESERVE;
			assert(send(rival, wire));
			wire.op = DTRACED_HANDOFF_CANCEL;
			assert(send(rival, wire));
			wire.op = DTRACED_HANDOFF_MUTATE;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_CLAIM;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_RESERVE;
			assert(send(destination, wire));
			wire.op = DTRACED_HANDOFF_CLAIM;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_PROMOTE_IMPORT;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_MUTATE;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::mutating &&
			    observed.destination_vmid == 8 &&
			    observed.destination_epoch == 22);
			assert(destination_status(destination, reply) &&
			    reply.phase == 'm');
			assert(!bind_kill(destination, reply) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_BIND_KILLS_ALL;
			assert(!send(destination, wire) && errno == EBUSY);
			durable_delivery_state migrated{};
			assert(!bind_delivery(rival, reply) && errno == EPERM);
			assert(bind_delivery(destination, reply) &&
			    reply.delivery_id == 77 && reply.phase == 'a' &&
			    reply.replay == 0 && reply.revoked == 0 &&
			    memcmp(reply.digest, delivery.payload_digest.data(), 32) == 0);
			durable_delivery migrated_key = delivery;
			migrated_key.session_id = destination.session_id;
			migrated_key.vmid = destination.vmid;
			migrated_key.epoch = destination.vm_epoch;
			assert(journal.resolve_host_delivery(migrated_key,
			    migrated) == 1);
			bool bound_revoked = false;
			assert(journal.bound_handoff_status(migrated.record,
			    bound_revoked) == 0 && !bound_revoked);
			assert(host.recover_outbound_deliveries(
			    &destination_outbound) &&
			    destination_outbound.outbound_deliveries.empty());
			assert(migrated_status().phase == 'u');
			assert(!migrated_observation(DTRACED_MSG_INSTALLED) &&
			    errno == EBUSY);
			assert(migrated.phase == delivery_phase::accepted &&
			    migrated.record.journal_version == 5 &&
			    migrated.record.vmid == destination.vmid &&
			    migrated.record.epoch == destination.vm_epoch &&
			    migrated.record.handoff_token == token &&
			    migrated.record.source_session == source.session_id &&
			    migrated.record.payload_vmid == source.vmid &&
			    migrated.record.payload_epoch == source.vm_epoch &&
			    journal.verify_host_delivery_payload(migrated.record) == 1);
			assert(journal.bind_handoff_delivery(observed, 77,
			    delivery.program_id, delivery.source_id,
			    delivery.payload_digest.data(),
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid, migrated));
			std::array<uint8_t, 16> wrong_session =
			    destination.session_id;
			wrong_session[0]++;
			assert(!journal.bind_handoff_delivery(observed, 77,
			    delivery.program_id, delivery.source_id,
			    delivery.payload_digest.data(), wrong_session,
			    destination.peer_uid, destination.peer_pid, migrated) &&
			    errno == EEXIST);
			{
				dir reopened(path, nullptr);
				durable_delivery_state restored{};
				assert(reopened.resolve_host_delivery(migrated.record,
				    restored) == 1 &&
				    restored.record.journal_version == 5 &&
				    restored.record.handoff_token == token &&
				    reopened.verify_host_delivery_payload(
				    restored.record) == 1);
			}
			wire.op = DTRACED_HANDOFF_CANCEL;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_RESERVE;
			assert(!send(rival, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_CLAIM;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::claimed &&
			    observed.destination_vmid == 8 &&
			    observed.destination_epoch == 22);
			durable_kill old_kill = killed;
			old_kill.vmid = destination.vmid;
			old_kill.epoch = destination.vm_epoch;
			assert(journal.bind_handoff_kills_all(observed));
			wire.op = DTRACED_HANDOFF_REBIND_BEGIN;
			assert(!send(destination, wire) && errno == EALREADY);
			assert(!send(rival, wire) && errno == EBUSY);
			destination_epoch_live = false;
			wire.digest[0]++;
			assert(!send(rival, wire) && errno == EPROTO);
			wire.digest[0]--;
			durable_delivery collision = delivery;
			collision.session_id = rival.session_id;
			collision.vmid = rival.vmid;
			collision.epoch = rival.vm_epoch;
			collision.peer_uid = rival.peer_uid;
			collision.peer_pid = rival.peer_pid;
			assert(journal.record_delivery(collision,
			    delivery_phase::pending, true));
			assert(!send(rival, wire) && errno == EEXIST);
			char collision_name[80];
			static const char collision_hex[] = "0123456789abcdef";
			memcpy(collision_name, ".delivery.", 10);
			for (size_t i = 0; i < collision.session_id.size(); i++) {
				collision_name[10 + i * 2] =
				    collision_hex[collision.session_id[i] >> 4];
				collision_name[11 + i * 2] =
				    collision_hex[collision.session_id[i] & 15];
			}
			assert(snprintf(collision_name + 42,
			    sizeof(collision_name) - 42, ".%016jx.%c",
			    (uintmax_t)collision.delivery_id,
			    (char)delivery_phase::pending) > 0);
			assert(unlinkat(journal.dirfd, collision_name, 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			durable_kill kill_collision = killed;
			kill_collision.vmid = rival.vmid;
			kill_collision.epoch = rival.vm_epoch;
			assert(journal.record_kill(kill_collision));
			assert(!send(rival, wire) && errno == EEXIST);
			const std::string kill_collision_name =
			    test_kill_name(kill_collision);
			assert(unlinkat(journal.dirfd,
			    kill_collision_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(journal.record_kill(old_kill) &&
			    journal.record_kill_applied(old_kill));
			assert(!send(rival, wire) && errno == EBUSY);
			const std::string old_ack_name =
			    ".killack." + test_kill_name(old_kill).substr(6);
			assert(unlinkat(journal.dirfd, old_ack_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			durable_cleanup cleanup_source{};
			cleanup_source.vmid = source.vmid;
			cleanup_source.epoch = source.vm_epoch;
			cleanup_source.delivery_id = 0x8899;
			assert(journal.cleanup_status(cleanup_source) == 'a');
			durable_cleanup old_cleanup = cleanup_source;
			old_cleanup.vmid = destination.vmid;
			old_cleanup.epoch = destination.vm_epoch;
			assert(journal.record_cleanup_pending(old_cleanup) &&
			    journal.record_cleanup_queued(old_cleanup));
			durable_cleanup cleanup_collision = cleanup_source;
			cleanup_collision.vmid = rival.vmid;
			cleanup_collision.epoch = rival.vm_epoch;
			assert(journal.record_cleanup_pending(cleanup_collision));
			assert(!send(rival, wire) && errno == EEXIST);
			const std::string cleanup_collision_name =
			    test_cleanup_name(cleanup_collision, 'p');
			assert(unlinkat(journal.dirfd,
			    cleanup_collision_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			durable_cleanup unexpected_cleanup = cleanup_source;
			unexpected_cleanup.vmid = destination.vmid;
			unexpected_cleanup.epoch = destination.vm_epoch;
			unexpected_cleanup.delivery_id++;
			assert(journal.record_cleanup_pending(unexpected_cleanup) &&
			    journal.record_cleanup_queued(unexpected_cleanup));
			assert(!send(rival, wire) && errno == EPROTO);
			const std::string unexpected_cleanup_name =
			    test_cleanup_name(unexpected_cleanup, 'a');
			assert(unlinkat(journal.dirfd,
			    unexpected_cleanup_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(journal.record_cleanup_applied(old_cleanup));
			assert(!send(rival, wire) && errno == EBUSY);
			const std::string old_cleanup_name =
			    test_cleanup_name(old_cleanup, 'g');
			assert(unlinkat(journal.dirfd,
			    old_cleanup_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			/* HJB1 still names this cleanup.  A disappeared old
			 * receipt cannot be silently remapped to the new VM. */
			assert(!send(rival, wire) && errno == EPROTO);
			assert(journal.record_cleanup_pending(old_cleanup) &&
			    journal.record_cleanup_queued(old_cleanup));
			/* The source cut still names this KILL. Rebind must refuse
			 * while its old claimed incarnation has lost the bound file. */
			const std::string old_kill_name = test_kill_name(old_kill);
			assert(unlinkat(journal.dirfd, old_kill_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(!send(rival, wire) && errno == EPROTO);
			assert(journal.record_kill(old_kill));
			assert(send(rival, wire));
			assert(send(rival, wire));
			wire.op = DTRACED_HANDOFF_EXECUTION_START;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_REKEY_APPLIED;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_REBIND_BEGIN;
			const char *rebind_name =
			    ".handoff-rebind.a1000000000000000000000000000000";
			{
				dir recovered(path, nullptr);
				assert(recovered.populate_existing());
			}
			int rebind_fd = openat(journal.dirfd, rebind_name, O_RDWR);
			assert(rebind_fd >= 0);
			uint8_t rebind_byte;
			assert(pread(rebind_fd, &rebind_byte, 1, 170) == 1);
			uint8_t corrupt_rebind = rebind_byte ^ 1;
			assert(pwrite(rebind_fd, &corrupt_rebind, 1, 170) == 1 &&
			    fsync(rebind_fd) == 0);
			assert(!send(rival, wire) && errno == EPROTO);
			wire.op = DTRACED_HANDOFF_EXECUTION_START;
			assert(!send(destination, wire) && errno == EPROTO);
			wire.op = DTRACED_HANDOFF_REKEY_APPLIED;
			assert(!send(destination, wire) && errno == EPROTO);
			wire.op = DTRACED_HANDOFF_REBIND_BEGIN;
			{
				dir recovered(path, nullptr);
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
			}
			assert(pwrite(rebind_fd, &rebind_byte, 1, 170) == 1 &&
			    fsync(rebind_fd) == 0 && close(rebind_fd) == 0);
			assert(send(rival, wire));
			std::array<uint8_t, 16> replacement_session =
			    rival.session_id;
			replacement_session[0]++;
			assert(!journal.begin_handoff_rebind(observed, 10, 44,
			    replacement_session, rival.peer_uid, rival.peer_pid) &&
			    errno == EBUSY);
			rival_epoch_live = false;
			assert(journal.begin_handoff_rebind(observed, 10, 44,
			    replacement_session, rival.peer_uid, rival.peer_pid));
			assert(journal.begin_handoff_rebind(observed, 10, 44,
			    replacement_session, rival.peer_uid, rival.peer_pid));
			assert(!journal.begin_handoff_rebind(observed, 11, 45,
			    replacement_session, rival.peer_uid, rival.peer_pid) &&
			    errno == EEXIST);
			const auto original_rival_session = rival.session_id;
			rival.session_id = replacement_session;
			rival.vmid = rival_vm.vmid = 10;
			rival.vm_epoch = rival_vm.epoch = 44;
			wire.op = DTRACED_HANDOFF_REBIND_STAGE;
			std::vector<durable_kill> existing_kills;
			assert(journal.list_kills(existing_kills) &&
			    existing_kills.size() < 16384);
			std::vector<std::string> filler_kills;
			filler_kills.reserve(16384 - existing_kills.size());
			durable_kill filler{};
			filler.vmid = 900;
			filler.epoch = 1;
			filler.source_id.fill(0x6d);
			for (size_t i = 0; i < 16384 - existing_kills.size(); i++) {
				filler.pid = (pid_t)(2000 + i);
				filler_kills.push_back(test_kill_name(filler));
				int fd = openat(journal.dirfd,
				    filler_kills.back().c_str(),
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
				    O_CLOEXEC, 0600);
				assert(fd >= 0 && close(fd) == 0);
			}
			assert(fsync(journal.dirfd) == 0 &&
			    !send(rival, wire) && errno == ENOSPC);
			for (const auto &name : filler_kills)
				assert(unlinkat(journal.dirfd,
				    name.c_str(), 0) == 0);
			assert(fsync(journal.dirfd) == 0);
			assert(send(rival, wire));
			assert(send(rival, wire));
			wire.op = DTRACED_HANDOFF_REBIND_EMPTY_READY;
			assert(!send(rival, wire) && errno == EOPNOTSUPP);
			wire.op = DTRACED_HANDOFF_REBIND_COMMIT_EMPTY;
			assert(!send(rival, wire) && errno == EOPNOTSUPP);
			wire.op = DTRACED_HANDOFF_REBIND_PENDING;
			assert(unlinkat(journal.dirfd, old_kill_name.c_str(), 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(!send(rival, wire) && errno == EPROTO);
			{
				dir recovered(path, nullptr);
				recovered.state = &host;
				host.outbounddir = &recovered;
				assert(!recovered.populate_existing() && errno == EPROTO);
				host.outbounddir = &journal;
			}
			assert(journal.record_kill(old_kill));
			wire.op = DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT;
			assert(!send(rival, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_REBIND_PENDING;
			assert(send(rival, wire));
			assert(send(rival, wire));
			/* A lost STAGE reply may be retried after PENDING has
			 * already published its inert HTD5 receipts. */
			assert(journal.stage_handoff_rebind(observed, 10, 44,
			    replacement_session, rival.peer_uid, rival.peer_pid));
			assert(journal.begin_handoff_rebind(observed, 10, 44,
			    replacement_session, rival.peer_uid, rival.peer_pid));
			durable_delivery proposed_delivery = migrated.record;
			proposed_delivery.session_id = replacement_session;
			proposed_delivery.vmid = 10;
			proposed_delivery.epoch = 44;
			proposed_delivery.peer_uid = rival.peer_uid;
			proposed_delivery.peer_pid = rival.peer_pid;
			assert(journal.delivery_status(proposed_delivery) ==
			    (int)delivery_phase::pending);
			wire.op = DTRACED_HANDOFF_REBIND_NONEMPTY_PREFLIGHT;
			assert(send(rival, wire) && send(rival, wire));
			destination_epoch_live = true;
			assert(!send(rival, wire) && errno == EBUSY);
			destination_epoch_live = false;
			assert(!journal.record_delivery(proposed_delivery,
			    delivery_phase::accepted) && errno == EPROTO);
			char proposed_name[80];
			memcpy(proposed_name, ".delivery.", 10);
			for (size_t i = 0; i < replacement_session.size(); i++) {
				proposed_name[10 + 2 * i] =
				    collision_hex[replacement_session[i] >> 4];
				proposed_name[11 + 2 * i] =
				    collision_hex[replacement_session[i] & 15];
			}
			assert(snprintf(proposed_name + 42,
			    sizeof(proposed_name) - 42, ".%016jx.p",
			    (uintmax_t)proposed_delivery.delivery_id) > 0);
			assert(unlinkat(journal.dirfd, proposed_name, 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(!send(rival, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_REBIND_PENDING;
			{
				dir recovered(path, nullptr);
				recovered.state = &host;
				host.outbounddir = &recovered;
				assert(recovered.populate_existing());
				host.outbounddir = &journal;
			}
			assert(send(rival, wire));
			assert(journal.delivery_status(proposed_delivery) ==
			    (int)delivery_phase::pending);
			int proposed_fd = openat(journal.dirfd,
			    proposed_name, O_RDWR);
			assert(proposed_fd >= 0);
			uint8_t proposed_byte;
			assert(pread(proposed_fd, &proposed_byte, 1, 70) == 1);
			uint8_t changed_proposed = proposed_byte ^ 1;
			assert(pwrite(proposed_fd, &changed_proposed, 1, 70) == 1 &&
			    fsync(proposed_fd) == 0);
			{
				dir recovered(path, nullptr);
				recovered.state = &host;
				host.outbounddir = &recovered;
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
				host.outbounddir = &journal;
			}
			assert(pwrite(proposed_fd, &proposed_byte, 1, 70) == 1 &&
			    fsync(proposed_fd) == 0 && close(proposed_fd) == 0);
			rival.session_id = original_rival_session;
			rival.vmid = rival_vm.vmid = 9;
			rival.vm_epoch = rival_vm.epoch = 33;
			wire.op = DTRACED_HANDOFF_REBIND_BEGIN;
			const char *plan_name =
			    ".handoff-rebind-plan.a1000000000000000000000000000000";
			int plan_fd = openat(journal.dirfd, plan_name, O_RDWR);
			assert(plan_fd >= 0);
			uint8_t plan_header[256];
			assert(pread(plan_fd, plan_header, sizeof(plan_header), 0) ==
			    (ssize_t)sizeof(plan_header));
			assert(memcmp(plan_header, "HRP1", 4) == 0 &&
			    dtraced_wire_get_u32(plan_header + 236) == 1 &&
			    dtraced_wire_get_u32(plan_header + 240) == 2 &&
			    dtraced_wire_get_u32(plan_header + 244) == 1);
			rival_vm.vmid = 10;
			rival_vm.epoch = 44;
			rival_epoch_live = true;
			assert(!journal.cancel_handoff_rebind_pending(observed) &&
			    errno == EBUSY);
			rival_vm.vmid = 9;
			rival_vm.epoch = 33;
			rival_epoch_live = false;
			{
				dir recovered(path, nullptr);
				assert(recovered.populate_existing());
			}
			uint8_t plan_byte;
			assert(pread(plan_fd, &plan_byte, 1, 248) == 1);
			uint8_t corrupt_plan = plan_byte ^ 1;
			assert(pwrite(plan_fd, &corrupt_plan, 1, 248) == 1 &&
			    fsync(plan_fd) == 0);
			{
				dir recovered(path, nullptr);
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
			}
			assert(pwrite(plan_fd, &plan_byte, 1, 248) == 1 &&
			    fsync(plan_fd) == 0 && close(plan_fd) == 0);
			plan_fd = openat(journal.dirfd, plan_name, O_RDWR);
			assert(plan_fd >= 0);
			struct stat plan_stat{};
			assert(fstat(plan_fd, &plan_stat) == 0 &&
			    plan_stat.st_size > 256 + 186 + 32);
			std::vector<uint8_t> original_plan(plan_stat.st_size);
			assert(pread(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size());
			std::vector<uint8_t> forged_plan = original_plan;
			forged_plan[256 + 70] ^= 1; /* HTD5 destination uid */
			assert(SHA256(forged_plan.data() + 256, 153,
			    forged_plan.data() + 256 + 153) != nullptr);
			assert(SHA256(forged_plan.data(), forged_plan.size() - 32,
			    forged_plan.data() + forged_plan.size() - 32) != nullptr);
			assert(pwrite(plan_fd, forged_plan.data(),
			    forged_plan.size(), 0) ==
			    (ssize_t)forged_plan.size() && fsync(plan_fd) == 0);
			{
				dir recovered(path, nullptr);
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
			}
			assert(pwrite(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size() &&
			    fsync(plan_fd) == 0);
			/* Each inventory entry must be a usable journal identity,
			 * even if both its inner and outer digests are recomputed. */
			forged_plan = original_plan;
			memset(forged_plan.data() + 256 + 20, 0, 8);
			assert(SHA256(forged_plan.data() + 256, 153,
			    forged_plan.data() + 256 + 153) != nullptr &&
			    SHA256(forged_plan.data(), forged_plan.size() - 32,
			    forged_plan.data() + forged_plan.size() - 32) != nullptr &&
			    pwrite(plan_fd, forged_plan.data(), forged_plan.size(), 0) ==
			    (ssize_t)forged_plan.size() && fsync(plan_fd) == 0 &&
			    !journal.cancel_handoff_rebind_pending(observed) &&
			    errno == EPROTO);
			assert(pwrite(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size() && fsync(plan_fd) == 0);
			forged_plan = original_plan;
			dtraced_wire_put_u32(forged_plan.data() + 256 + 186,
			    UINT32_MAX);
			assert(SHA256(forged_plan.data(), forged_plan.size() - 32,
			    forged_plan.data() + forged_plan.size() - 32) != nullptr &&
			    pwrite(plan_fd, forged_plan.data(), forged_plan.size(), 0) ==
			    (ssize_t)forged_plan.size() && fsync(plan_fd) == 0 &&
			    !journal.cancel_handoff_rebind_pending(observed) &&
			    errno == EPROTO);
			assert(pwrite(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size() && fsync(plan_fd) == 0);
			forged_plan = original_plan;
			memset(forged_plan.data() + 256 + 186 + 2 * 30 + 10,
			    0, 8);
			assert(SHA256(forged_plan.data(), forged_plan.size() - 32,
			    forged_plan.data() + forged_plan.size() - 32) != nullptr &&
			    pwrite(plan_fd, forged_plan.data(), forged_plan.size(), 0) ==
			    (ssize_t)forged_plan.size() && fsync(plan_fd) == 0 &&
			    !journal.cancel_handoff_rebind_pending(observed) &&
			    errno == EPROTO);
			assert(pwrite(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size() && fsync(plan_fd) == 0);
			forged_plan = original_plan;
			memset(forged_plan.data() + 256 + 186 + 14, 0xff, 16);
			assert(SHA256(forged_plan.data(), forged_plan.size() - 32,
			    forged_plan.data() + forged_plan.size() - 32) != nullptr);
			assert(pwrite(plan_fd, forged_plan.data(),
			    forged_plan.size(), 0) ==
			    (ssize_t)forged_plan.size() && fsync(plan_fd) == 0);
			{
				dir recovered(path, nullptr);
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
			}
			assert(pwrite(plan_fd, original_plan.data(),
			    original_plan.size(), 0) ==
			    (ssize_t)original_plan.size() &&
			    fsync(plan_fd) == 0 && close(plan_fd) == 0);
			assert(renameat(journal.dirfd, rebind_name,
			    journal.dirfd, ".rebind-test-held") == 0 &&
			    fsync(journal.dirfd) == 0);
			{
				dir recovered(path, nullptr);
				assert(!recovered.populate_existing() &&
				    errno == EPROTO);
			}
			assert(renameat(journal.dirfd, ".rebind-test-held",
			    journal.dirfd, rebind_name) == 0 &&
			    fsync(journal.dirfd) == 0);
			rival_vm.vmid = 10;
			rival_vm.epoch = 44;
			std::string accepted_name = proposed_name;
			accepted_name.back() = 'a';
			assert(renameat(journal.dirfd, proposed_name,
			    journal.dirfd, accepted_name.c_str()) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(!journal.cancel_handoff_rebind_pending(observed) &&
			    errno == EBUSY);
			assert(renameat(journal.dirfd, accepted_name.c_str(),
			    journal.dirfd, proposed_name) == 0 &&
			    fsync(journal.dirfd) == 0);
			assert(journal.cancel_handoff_rebind_pending(observed));
			assert(journal.cancel_handoff_rebind_pending(observed));
			assert(journal.delivery_status(proposed_delivery) == 0);
			assert(journal.begin_handoff_rebind(observed, 9, 33,
			    original_rival_session, rival.peer_uid,
			    rival.peer_pid));
			assert(faccessat(journal.dirfd, plan_name, F_OK, 0) != 0 &&
			    errno == ENOENT);
			rival_vm.vmid = 9;
			rival_vm.epoch = 33;
			assert(journal.stage_handoff_rebind(observed, 9, 33,
			    original_rival_session, rival.peer_uid, rival.peer_pid) &&
			    journal.publish_handoff_rebind_pending(observed, 9, 33,
			    original_rival_session, rival.peer_uid, rival.peer_pid));
			durable_delivery retired_proposal = migrated.record;
			retired_proposal.session_id = original_rival_session;
			retired_proposal.vmid = 9;
			retired_proposal.epoch = 33;
			retired_proposal.peer_uid = rival.peer_uid;
			retired_proposal.peer_pid = rival.peer_pid;
			assert(journal.delivery_status(retired_proposal) ==
			    (int)delivery_phase::pending);
			std::array<uint8_t, 16> superseding_session =
			    original_rival_session;
			superseding_session[0] += 2;
			rival_epoch_live = true;
			assert(!journal.begin_handoff_rebind(observed, 11, 45,
			    superseding_session, rival.peer_uid, rival.peer_pid) &&
			    errno == EBUSY &&
			    journal.delivery_status(retired_proposal) ==
			    (int)delivery_phase::pending);
			rival_epoch_live = false;
			assert(journal.begin_handoff_rebind(observed, 11, 45,
			    superseding_session, rival.peer_uid, rival.peer_pid));
			assert(journal.delivery_status(retired_proposal) == 0 &&
			    faccessat(journal.dirfd, plan_name, F_OK, 0) != 0 &&
			    errno == ENOENT);
			assert(journal.begin_handoff_rebind(observed, 11, 45,
			    superseding_session, rival.peer_uid, rival.peer_pid));
			assert(journal.handoff_status(token, observed) ==
			    (int)handoff_phase::claimed &&
			    observed.destination_vmid == destination.vmid &&
			    observed.destination_epoch == destination.vm_epoch);
			assert(unlinkat(journal.dirfd, rebind_name, 0) == 0 &&
			    fsync(journal.dirfd) == 0);
			destination_epoch_live = true;
			assert(destination_status(destination, reply) &&
			    reply.phase == 'r');
			wire.op = DTRACED_HANDOFF_PROMOTE_IMPORT;
			assert(!send(rival, wire) && errno == EPERM);
			wire.digest[0]++;
			assert(!send(destination, wire) && errno == EPROTO);
			wire.digest[0]--;
			assert(send(destination, wire));
			assert(send(destination, wire));
			std::vector<durable_kill> promoted_kills;
			assert(journal.list_kills(promoted_kills));
			assert(std::any_of(promoted_kills.begin(),
			    promoted_kills.end(), [&](const durable_kill &entry) {
				return (entry.pid == killed.pid &&
				    entry.vmid == destination.vmid &&
				    entry.epoch == destination.vm_epoch &&
				    entry.source_id == killed.source_id);
			}));
			wire.op = DTRACED_HANDOFF_BIND_KILLS_ALL;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			wire.op = DTRACED_HANDOFF_ACTIVATE_IMPORT;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_REKEY_APPLIED;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			wire.op = DTRACED_HANDOFF_REBIND_BEGIN;
			assert(!send(rival, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_EXECUTION_START;
			assert(!send(rival, wire) && errno == EPERM);
			wire.digest[0]++;
			assert(!send(destination, wire) && errno == EPROTO);
			wire.digest[0]--;
			assert(send(destination, wire));
			assert(send(destination, wire));
			assert(journal.handoff_execution_start_status(observed) == 1);
			wire.op = DTRACED_HANDOFF_ACTIVATE_IMPORT;
			assert(!send(rival, wire) && errno == EPERM);
			assert(send(destination, wire));
			assert(send(destination, wire));
			wire.op = DTRACED_HANDOFF_BIND_KILLS_ALL;
			assert(!bind_kill(rival, reply) && errno == EPERM);
			assert(bind_kill(destination, reply) &&
			    reply.delivery_id == 123 && reply.phase == 'p' &&
			    reply.revoked == 1 && reply.replay == 0);
			assert(bind_kill(destination, reply) && reply.phase == 'p');
			durable_kill destination_kill = killed;
			destination_kill.vmid = destination.vmid;
			destination_kill.epoch = destination.vm_epoch;
			assert(journal.kill_applied(destination_kill) == 0);
			assert(journal.record_kill_applied(destination_kill));
			assert(bind_kill(destination, reply) && reply.phase == 'a');
			durable_kill destination_unsettled = unsettled;
			destination_unsettled.vmid = destination.vmid;
			destination_unsettled.epoch = destination.vm_epoch;
			assert(journal.kill_applied(destination_unsettled) == 0);
			assert(journal.record_kill_applied(destination_unsettled));
			assert(bind_delivery(destination, reply) &&
			    reply.phase == 'a' &&
			    memcmp(reply.digest, delivery.payload_digest.data(), 32) == 0);
			assert(journal.bind_handoff_delivery(observed, 77,
			    delivery.program_id, delivery.source_id,
			    delivery.payload_digest.data(),
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid, migrated) &&
			    migrated.phase == delivery_phase::accepted);
			assert(journal.bound_handoff_status(migrated.record,
			    bound_revoked) == 1 && !bound_revoked);
			assert(host.recover_outbound_deliveries(
			    &destination_outbound) &&
			    destination_outbound.outbound_deliveries.size() == 1 &&
			    destination_outbound.outbound_deliveries[0].accepted);
			host.sockfds.insert(&destination_outbound);
			dtraced_delivery_status_t live_status = migrated_status();
			assert(live_status.phase == 'a' &&
			    live_status.revoked == 0 && live_status.replay == 1 &&
			    memcmp(live_status.digest,
			    delivery.payload_digest.data(), 32) == 0);
			assert(migrated_observation(DTRACED_MSG_INSTALLED) &&
			    journal.delivery_status(migrated.record) ==
			    (int)delivery_phase::installed);
			/* A second migration retains the original payload identity and
			 * must carry revocation through both claimed tickets. */
			durable_handoff second_handoff{};
			second_handoff.token[0] = 0xa4;
			second_handoff.source_session = destination.session_id;
			second_handoff.source_vmid = destination.vmid;
			second_handoff.source_epoch = destination.vm_epoch;
			bind_empty_transfer(second_handoff);
			second_handoff.checkpoint_digest[0] = 0xc4;
			second_handoff.destination_vmid = rival.vmid;
			second_handoff.destination_epoch = rival.vm_epoch;
			durable_handoff second_prepared = second_handoff;
			second_prepared.checkpoint_digest.fill(0);
			second_prepared.destination_vmid = 0;
			second_prepared.destination_epoch = 0;
			journal.state = nullptr; /* Legacy empty-transfer lineage. */
			assert(journal.prepare_handoff(second_prepared, false));
			durable_handoff second_committed = second_handoff;
			second_committed.destination_vmid = 0;
			second_committed.destination_epoch = 0;
			assert(journal.commit_handoff(second_committed));
			journal.state = &host;
			assert(journal.record_source_release(second_committed));
			assert(journal.reserve_handoff(second_handoff));
			assert(journal.begin_handoff_mutation(second_handoff));
			durable_delivery_state twice_migrated{};
			assert(journal.bind_handoff_delivery(second_handoff, 77,
			    delivery.program_id, delivery.source_id,
			    delivery.payload_digest.data(),
			    rival.session_id, rival.peer_uid, rival.peer_pid,
			    twice_migrated) &&
			    twice_migrated.record.journal_version == 5 &&
			    twice_migrated.record.payload_vmid == source.vmid &&
			    twice_migrated.record.payload_epoch == source.vm_epoch &&
			    twice_migrated.phase == delivery_phase::installed);
			assert(journal.claim_handoff(second_handoff));
			assert(journal.bound_handoff_status(
			    twice_migrated.record, bound_revoked) == 1 &&
			    !bound_revoked);
			std::string spool_name = "elf.";
			static const char hex[] = "0123456789abcdef";
			for (uint8_t byte : delivery.program_id) {
				spool_name += hex[byte >> 4];
				spool_name += hex[byte & 15];
			}
			spool_name += '.';
			for (uint8_t byte : delivery.source_id) {
				spool_name += hex[byte >> 4];
				spool_name += hex[byte & 15];
			}
			int payload_fd = openat(journal.dirfd, spool_name.c_str(),
			    O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
			assert(payload_fd >= 0);
			const char altered = 'X';
			assert(pwrite(payload_fd, &altered, 1,
			    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 4) == 1);
			assert(fsync(payload_fd) == 0 && close(payload_fd) == 0);
			assert(!lookup_status(destination, reply) && errno == EPROTO);
			durable_kill payload_revoked{};
			payload_revoked.pid = 126;
			payload_revoked.vmid = delivery.vmid;
			payload_revoked.epoch = delivery.epoch;
			payload_revoked.source_id = delivery.source_id;
			int consumer_pair[2];
			assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
			    consumer_pair) == 0);
			{
				dtd_initmsg_t hello{};
				hello.kind = DTRACED_KIND_CONSUMER;
				hello.subs = DTD_SUB_READDATA;
				hello.protocol_version = DTRACED_PROTOCOL_VERSION;
				client_fd consumer(kq, consumer_pair[0], hello);
				assert(destination.enable_rw(nullptr));
				assert(rival.enable_rw(nullptr));
				host.sockfds.insert(&destination);
				host.sockfds.insert(&rival);
				dtraced_hdr_t revoke{};
				revoke.msg_type = DTRACED_MSG_KILL;
				revoke.kill.pid = payload_revoked.pid;
				revoke.kill.vmid = payload_revoked.vmid;
				revoke.kill.epoch = payload_revoked.epoch;
				memcpy(revoke.kill.source_id,
				    payload_revoked.source_id.data(), 16);
				client_request request(host, revoke, nullptr, 0,
				    &consumer);
				assert(request.handle());
				std::vector<job *> live_kills;
				{
					std::lock_guard jobs(host.joblistmtx);
					for (auto it = host.joblist.begin();
					    it != host.joblist.end();) {
						job *pending = *it;
						if (pending->kind != KILL ||
						    pending->kill_get().pid !=
						    payload_revoked.pid) {
							++it;
							continue;
						}
						live_kills.push_back(pending);
						it = host.joblist.erase(it);
					}
				}
				assert(live_kills.size() == 2);
				for (job *pending : live_kills) {
					if (pending->connsockfd == &destination) {
						assert(pending->kill_get().vmid ==
						    destination.vmid);
						assert(!pending->send_kill(host) &&
						    errno == EBUSY &&
						    pending->handoff_deferred);
					} else {
						assert(pending->connsockfd == &rival &&
						    pending->kill_get().vmid ==
						    rival.vmid);
						assert(pending->send_kill(host));
					}
					delete pending;
				}
				dtraced_hdr_t delivered{};
				assert(recv(rival_pair[1], &delivered,
				    DTRACED_MSGHDRSIZE, MSG_WAITALL) ==
				    DTRACED_MSGHDRSIZE);
				assert(DTRACED_MSG_TYPE(delivered) ==
				    DTRACED_MSG_KILL &&
				    DTRACED_MSG_KILLVMID(delivered) == rival.vmid &&
				    DTRACED_MSG_KILLEPOCH(delivered) == rival.vm_epoch);
				host.sockfds.erase(&destination);
				host.sockfds.erase(&rival);
			}
			close(consumer_pair[1]);
			payload_revoked.vmid = destination.vmid;
			payload_revoked.epoch = destination.vm_epoch;
			assert(journal.kill_applied(payload_revoked) == 0);
			assert(journal.record_kill_applied(payload_revoked));
			payload_revoked.vmid = rival.vmid;
			payload_revoked.epoch = rival.vm_epoch;
			assert(journal.kill_applied(payload_revoked) == 0);
			assert(journal.record_kill_applied(payload_revoked));
			assert(journal.bound_handoff_status(migrated.record,
			    bound_revoked) == 1 && bound_revoked);
			assert(journal.bound_handoff_status(
			    twice_migrated.record, bound_revoked) == 1 &&
			    bound_revoked);
			/* A later bind must reject a revoked ancestor before it
			 * creates another durable destination receipt. */
			durable_handoff third_handoff{};
			third_handoff.token[0] = 0xa5;
			third_handoff.source_session = rival.session_id;
			third_handoff.source_vmid = rival.vmid;
			third_handoff.source_epoch = rival.vm_epoch;
			bind_empty_transfer(third_handoff);
			third_handoff.checkpoint_digest[0] = 0xc5;
			third_handoff.destination_vmid = 10;
			third_handoff.destination_epoch = 44;
			durable_handoff third_prepared = third_handoff;
			third_prepared.checkpoint_digest.fill(0);
			third_prepared.destination_vmid = 0;
			third_prepared.destination_epoch = 0;
			journal.state = nullptr; /* Legacy empty-transfer lineage. */
			assert(journal.prepare_handoff(third_prepared, false));
			durable_handoff third_committed = third_handoff;
			third_committed.destination_vmid = 0;
			third_committed.destination_epoch = 0;
			assert(journal.commit_handoff(third_committed));
			journal.state = &host;
			assert(journal.record_source_release(third_committed));
			assert(journal.reserve_handoff(third_handoff));
			assert(journal.begin_handoff_mutation(third_handoff));
			std::array<uint8_t, 16> third_session{};
			third_session[0] = 0x45;
			durable_delivery_state third_delivery{};
			assert(!journal.bind_handoff_delivery(third_handoff, 77,
			    delivery.program_id, delivery.source_id,
			    delivery.payload_digest.data(), third_session,
			    rival.peer_uid, rival.peer_pid, third_delivery) &&
			    errno == ECANCELED);
			destination_outbound.outbound_deliveries.clear();
			assert(host.recover_outbound_deliveries(
			    &destination_outbound) &&
			    destination_outbound.outbound_deliveries.empty());
			live_status = migrated_status();
			assert(live_status.phase == 'i' && live_status.revoked == 1 &&
			    live_status.replay == 0 &&
			    live_status.digest[0] == 0);
			assert(migrated_observation(DTRACED_MSG_UNINSTALLED) &&
			    journal.delivery_status(migrated.record) ==
			    (int)delivery_phase::terminal);
			assert(lookup_status(destination, reply) &&
			    reply.revoked == 1 && reply.digest[0] == 0);
			assert(!destination_status(rival, reply) && errno == EPERM);
			wire.op = DTRACED_HANDOFF_CANCEL;
			assert(!send(destination, wire) && errno == EBUSY);
			wire.op = DTRACED_HANDOFF_ABORT;
			assert(!send(source, wire) && errno == EPROTO);
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(!send(source, wire) && errno == EBUSY);
			wire.token[0] = 0xa2;
			wire.op = DTRACED_HANDOFF_PREPARE;
			bind_empty_bundle(wire);
			assert(!send(source, wire) && errno == EBUSY);
			/* A new VMM incarnation can prepare its own ticket. */
			source.vm_epoch++;
			source_vm.epoch++;
			gate_suspended = false;
			memset(gate_owner, 0, sizeof(gate_owner));
			wire.op = DTRACED_HANDOFF_SOURCE_GATE_BEGIN;
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(send(source, wire));
			wire.op = DTRACED_HANDOFF_PREPARE;
			bind_empty_bundle(wire);
			assert(send(source, wire));
			/* A worker must keep a fenced revocation until ABORT wakes it. */
			durable_kill resumed = killed;
			resumed.pid = 125;
			resumed.epoch = source.vm_epoch;
			resumed.source_id[0] = 6;
			assert(journal.record_kill(resumed));
			assert(source.enable_write(&source));
			host.kq_hdl = kq;
			host.sockfds.insert(&source);
			auto *waiting = new job(KILL, &source);
			kill_job &pending_kill = waiting->kill_get();
			pending_kill.pid = resumed.pid;
			pending_kill.vmid = resumed.vmid;
			pending_kill.epoch = resumed.epoch;
			memcpy(pending_kill.source_id, resumed.source_id.data(), 16);
			{
				std::lock_guard jobs(host.dispatched_jobsmtx);
				host.dispatched_jobs.push_back(waiting);
			}
			std::thread worker(&state::process_joblist, &host);
			host.dispatched_jobscv.notify_one();
			bool deferred_in_queue = false;
			for (unsigned attempt = 0; attempt < 100; attempt++) {
				{
					std::lock_guard jobs(host.joblistmtx);
					deferred_in_queue = !host.joblist.empty();
				}
				if (deferred_in_queue)
					break;
				usleep(10000);
			}
			assert(deferred_in_queue && !source.retired.load());
			pollfd before{source_pair[1], POLLIN, 0};
			assert(poll(&before, 1, 0) == 0);
			wire.op = DTRACED_HANDOFF_ABORT;
			memset(wire.digest, 0, sizeof(wire.digest));
			assert(send(source, wire));
			struct kevent write_event;
			EV_SET(&write_event, source_pair[0], EVFILT_WRITE, 0, 0, 0,
			    &source);
			{
				std::lock_guard jobs(host.joblistmtx);
				assert(host.dispatch_event(write_event));
			}
			pollfd after{source_pair[1], POLLIN, 0};
			assert(poll(&after, 1, 2000) == 1 &&
			    (after.revents & POLLIN) != 0);
			dtraced_hdr_t revocation{};
			assert(recv(source_pair[1], &revocation,
			    DTRACED_MSGHDRSIZE, MSG_WAITALL) == DTRACED_MSGHDRSIZE);
			assert(DTRACED_MSG_TYPE(revocation) == DTRACED_MSG_KILL &&
			    DTRACED_MSG_KILLPID(revocation) == resumed.pid &&
			    DTRACED_MSG_KILLVMID(revocation) == resumed.vmid &&
			    DTRACED_MSG_KILLEPOCH(revocation) == resumed.epoch &&
			    memcmp(revocation.kill.source_id, resumed.source_id.data(),
			    16) == 0);
			host.shutdown.store(1);
			host.dispatched_jobscv.notify_all();
			worker.join();
			host.sockfds.erase(&source);
			host.sockfds.erase(&destination_outbound);
			{
				char journal_path[] =
				    "/tmp/hypertrace-import-handler-out.XXXXXX";
				char ingress_path[] =
				    "/tmp/hypertrace-import-handler-in.XXXXXX";
				char source_path[] =
				    "/tmp/hypertrace-import-handler-source.XXXXXX";
				assert(mkdtemp(journal_path) != nullptr &&
				    mkdtemp(ingress_path) != nullptr &&
				    mkdtemp(source_path) != nullptr);
				{
					dir transfer_out(journal_path, nullptr);
					dir transfer_in(ingress_path, nullptr);
					dir source_dir(source_path, nullptr);
					durable_handoff imported_ticket{};
					imported_ticket.token[0] = 0xa6;
					imported_ticket.source_session[0] = 0x60;
					imported_ticket.source_vmid = 12;
					imported_ticket.source_epoch = 57;
					source_journal_cut source_cut;
					source_journal_delivery item{};
					item.state.record.session_id =
					    imported_ticket.source_session;
					item.state.record.delivery_id = 91;
					item.state.record.vmid =
					    imported_ticket.source_vmid;
					item.state.record.epoch =
					    imported_ticket.source_epoch;
					item.state.record.program_id[0] = 0x61;
					item.state.record.source_id[0] = 0x62;
					item.state.record.peer_uid = 100;
					item.state.record.peer_pid = 200;
					item.state.record.journal_version = 4;
					item.state.phase = delivery_phase::accepted;
					const uint8_t payload[] = "\177ELFhandler";
					std::vector<uint8_t> bare_payload(payload,
					    payload + sizeof(payload) - 1);
					hypertrace_vm_envelope target{};
					target.magic = HYPERTRACE_TARGET_MAGIC;
					target.version = HYPERTRACE_ENVELOPE_VERSION;
					target.vmid = imported_ticket.source_vmid;
					target.epoch = imported_ticket.source_epoch;
					item.payload.resize(HYPERTRACE_VM_ENVELOPE_WIRE_SIZE +
					    bare_payload.size());
					hypertrace_envelope_encode(item.payload.data(), &target);
					memcpy(item.payload.data() +
					    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE,
					    bare_payload.data(), bare_payload.size());
					assert(SHA256(bare_payload.data(), bare_payload.size(),
					    item.state.record.payload_digest.data()) != nullptr);
					source_cut.deliveries.push_back(item);
					std::vector<uint8_t> archive, manifest, transfer;
					std::vector<std::vector<uint8_t>> frames;
					assert(dir::encode_source_journal_archive(
					    imported_ticket, source_cut, archive) &&
					    dtraced_transfer_journal_wrap(
					    imported_ticket.token.data(), {}, {}, archive,
					    manifest, frames) &&
					    dtraced_transfer_wire_build(
					    imported_ticket.token.data(), manifest, frames,
					    transfer));
					memcpy(imported_ticket.transfer_digest.data(),
					    transfer.data() + transfer.size() - 32, 32);
					assert(source_dir.prepare_handoff(
					    imported_ticket, false));
					imported_ticket.checkpoint_digest[0] = 0xc7;
					assert(source_dir.commit_handoff(imported_ticket) &&
					    source_dir.record_source_release(imported_ticket));
					std::array<uint8_t,
					    DTRACED_RELEASE_ATTESTED_SIZE> signed_cut{};
					assert(source_dir.attest_source_release(imported_ticket,
					    host.handoff_keys.private_key(),
					    host.handoff_keys.peer_public().data(), signed_cut));
					state foreign_host{};
					state_attestation_test::set_control(foreign_host);
					assert(foreign_host.handoff_keys.load(
					    peer_private_path.c_str(),
					    source_public_path.c_str()));
					foreign_host.outbounddir = &transfer_out;
					foreign_host.inbounddir = &transfer_in;
					transfer_out.state = &foreign_host;
					transfer_in.state = &foreign_host;
					assert(transfer_out.stage_imported_source_release(
					    signed_cut.data(),
					    foreign_host.handoff_keys.peer_public().data(),
					    foreign_host.handoff_keys.own_public().data(),
					    imported_ticket.token.data(),
					    imported_ticket.checkpoint_digest.data()) &&
					    transfer_out.adopt_imported_source_release(
					    imported_ticket.token,
					    imported_ticket.checkpoint_digest.data()));
					imported_ticket.destination_vmid = destination.vmid;
					imported_ticket.destination_epoch =
					    destination.vm_epoch;
					assert(transfer_out.reserve_handoff(imported_ticket));
					std::vector<uint8_t> body(48 + transfer.size());
					memcpy(body.data(), imported_ticket.token.data(), 16);
					memcpy(body.data() + 16,
					    imported_ticket.checkpoint_digest.data(), 32);
					memcpy(body.data() + 48, transfer.data(),
					    transfer.size());
					auto import_journal = [&]() {
						dtraced_hdr_t header{};
						header.msg_type = DTRACED_MSG_HANDOFF_IMPORT;
						client_request request(foreign_host, header, body.data(),
						    body.size(), &destination);
						return (request.handle());
					};
					auto journal_phase = [&](client_fd &peer, uint8_t op) {
						dtraced_handoff_request_t wire{};
						wire.op = op;
						memcpy(wire.token, imported_ticket.token.data(), 16);
						memcpy(wire.digest,
						    imported_ticket.checkpoint_digest.data(), 32);
						dtraced_hdr_t header{};
						header.msg_type = DTRACED_MSG_HANDOFF;
						client_request request(foreign_host, header,
						    (unsigned char *)&wire, sizeof(wire), &peer);
						return (request.handle());
					};
					char imported_name[43];
					memcpy(imported_name, ".imported.", 10);
					static const char hex[] = "0123456789abcdef";
					for (size_t i = 0; i < imported_ticket.token.size(); i++) {
						imported_name[10 + i * 2] =
						    hex[imported_ticket.token[i] >> 4];
						imported_name[11 + i * 2] =
						    hex[imported_ticket.token[i] & 15];
					}
					imported_name[42] = '\0';
					int proof_fd = openat(transfer_out.dirfd,
					    imported_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
					assert(proof_fd >= 0);
					uint8_t damaged = signed_cut.back() ^ 1;
					assert(pwrite(proof_fd, &damaged, 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0 && !import_journal() &&
					    errno == EPROTO &&
					    pwrite(proof_fd, &signed_cut.back(), 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0);
					source_journal_cut unstaged_cut;
					host_ingress_transfer_bundle unstaged_ingress;
					assert(transfer_out.load_source_journal_destination_stage(
					    imported_ticket, unstaged_cut,
					    unstaged_ingress) == 0);
					source_journal_destination_plan staged_plan;
					durable_handoff still_reserved{};
					assert(import_journal() && import_journal() &&
					    transfer_out.source_journal_pending_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, staged_plan) == 2 &&
					    staged_plan.deliveries.size() == 1 &&
					    transfer_out.handoff_status(imported_ticket.token,
					    still_reserved) ==
					    (int)handoff_phase::reserved &&
					    transfer_out.populate_existing());
					assert(!journal_phase(destination,
					    DTRACED_HANDOFF_PROMOTE_IMPORT) && errno == EBUSY);
					assert(!transfer_out.record_delivery(
					    staged_plan.deliveries.front().state.record,
					    delivery_phase::terminal) && errno == EOPNOTSUPP);
					std::vector<uint8_t> replay_bytes{0xff};
					assert(transfer_out.claimed_source_journal_replay_payload(
					    staged_plan.deliveries.front().state.record,
					    replay_bytes) == -1 && errno == EBUSY &&
					    replay_bytes.empty() &&
					    !transfer_out.accept_claimed_source_journal_replay(
					    staged_plan.deliveries.front().state.record) &&
					    errno == EBUSY);
					/* A watcher send cannot mint a new HTD4 from the
					 * imported program while its HTD5 is still inert. */
					durable_delivery duplicate =
					    staged_plan.deliveries.front().state.record;
					duplicate.delivery_id++;
					duplicate.journal_version = 4;
					duplicate.handoff_token = {};
					duplicate.source_session = {};
					duplicate.payload_vmid = 0;
					duplicate.payload_epoch = 0;
					assert(!transfer_out.record_delivery(duplicate,
					    delivery_phase::pending, true) && errno == EBUSY);
					duplicate.source_id[0]++;
					assert(!transfer_out.record_delivery(duplicate,
					    delivery_phase::pending, true) && errno == EBUSY);
					assert(pwrite(proof_fd, &damaged, 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0 &&
					    transfer_out.source_journal_pending_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, staged_plan) == -1 &&
					    errno == EPROTO &&
					    !transfer_out.begin_handoff_mutation(
					    imported_ticket) && errno == EPROTO);
					durable_delivery_state source_status{};
					bool source_revoked = false, source_payload = false;
					assert(transfer_out.handoff_delivery_status(imported_ticket,
					    0, item.state.record.delivery_id,
					    item.state.record.program_id,
					    item.state.record.source_id, source_status,
					    source_revoked, source_payload) == -1 &&
					    errno == EPROTO);
					assert(transfer_out.handoff_kill_status(imported_ticket,
					    123, item.state.record.source_id,
					    source_revoked) == -1 && errno == EPROTO);
					assert(transfer_out.handoff_cleanup_status(imported_ticket,
					    item.state.record.delivery_id) == -1 &&
					    errno == EPROTO);
					assert(!import_journal() && errno == EPROTO &&
					    pwrite(proof_fd, &signed_cut.back(), 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0 && close(proof_fd) == 0);
					assert(transfer_out.handoff_delivery_status(imported_ticket,
					    0, item.state.record.delivery_id,
					    item.state.record.program_id,
					    item.state.record.source_id, source_status,
					    source_revoked, source_payload) == 1 &&
					    source_status.phase == delivery_phase::accepted &&
					    !source_revoked && source_payload &&
					    transfer_out.source_journal_pending_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, staged_plan) == 2 &&
					    staged_plan.deliveries.size() == 1);
					std::string reserved_name = ".handoff." +
					    std::string(imported_name + 10) + ".v";
					std::string claimed_name = reserved_name;
					claimed_name.back() = 'r';
					assert(renameat(transfer_out.dirfd,
					    reserved_name.c_str(), transfer_out.dirfd,
					    claimed_name.c_str()) == 0 &&
					    fsync(transfer_out.dirfd) == 0);
					const durable_delivery &imported_record =
					    staged_plan.deliveries.front().state.record;
					assert(transfer_out.claimed_source_journal_replay_payload(
					    imported_record, replay_bytes) == 1 &&
					    replay_bytes == bare_payload);
					assert(!transfer_out.record_delivery(imported_record,
					    delivery_phase::accepted) && errno == EOPNOTSUPP &&
					    transfer_out.delivery_status(imported_record) ==
					    (int)delivery_phase::pending);
					proof_fd = openat(transfer_out.dirfd,
					    imported_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
					assert(proof_fd >= 0 &&
					    pwrite(proof_fd, &damaged, 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0 &&
					    !transfer_out.record_delivery(imported_record,
					    delivery_phase::accepted) && errno == EPROTO &&
					    transfer_out.claimed_source_journal_replay_payload(
					    imported_record, replay_bytes) == -1 &&
					    errno == EPROTO && replay_bytes.empty() &&
					    !transfer_out.accept_claimed_source_journal_replay(
					    imported_record) && errno == EPROTO &&
					    transfer_out.handoff_delivery_status(imported_ticket,
					    0, item.state.record.delivery_id,
					    item.state.record.program_id,
					    item.state.record.source_id, source_status,
					    source_revoked, source_payload) == -1 &&
					    errno == EPROTO &&
					    pwrite(proof_fd, &signed_cut.back(), 1,
					    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
					    fsync(proof_fd) == 0 && close(proof_fd) == 0 &&
					    transfer_out.handoff_delivery_status(imported_ticket,
					    0, item.state.record.delivery_id,
					    item.state.record.program_id,
					    item.state.record.source_id, source_status,
					    source_revoked, source_payload) == 1 &&
					    renameat(transfer_out.dirfd,
					    claimed_name.c_str(), transfer_out.dirfd,
					    reserved_name.c_str()) == 0 &&
					    fsync(transfer_out.dirfd) == 0);
					assert(import_journal() &&
					    transfer_out.cancel_handoff_reservation(
					    imported_ticket));
					/* A fresh foreign HSA1 with complete HJB1/HJR1 can cross
					 * both real phase transitions. Exact retries preserve them. */
					assert(transfer_out.reserve_handoff(imported_ticket) &&
					    import_journal() &&
					    transfer_out.source_journal_pending_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, staged_plan) == 2 &&
					    staged_plan.deliveries.size() == 1 &&
					    transfer_out.begin_handoff_mutation(imported_ticket) &&
					    transfer_out.begin_handoff_mutation(imported_ticket) &&
					    transfer_out.claim_handoff(imported_ticket) &&
					    transfer_out.claim_handoff(imported_ticket) &&
					    transfer_out.populate_existing());
					assert(transfer_out.claimed_source_journal_status(
					    imported_ticket, destination.session_id, 101, 200) == -1 &&
					    errno == EPERM &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_PROMOTE_IMPORT) &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_PROMOTE_IMPORT) &&
					    !journal_phase(destination,
					    DTRACED_HANDOFF_REPLAY_READY) &&
					    errno == EBUSY &&
					    !journal_phase(destination,
					    DTRACED_HANDOFF_ACTIVATE_IMPORT) &&
					    errno == EBUSY &&
					    transfer_out.claimed_source_journal_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, true) == 1 &&
					    transfer_out.delivery_status(
					    staged_plan.deliveries.front().state.record) ==
					    (int)delivery_phase::pending);
					const durable_delivery &accepted_record =
					    staged_plan.deliveries.front().state.record;
					assert(destination_outbound.session_id ==
					    accepted_record.session_id &&
					    destination_outbound.peer_uid ==
					    accepted_record.peer_uid &&
					    (uint32_t)destination_outbound.peer_pid ==
					    accepted_record.peer_pid);
					assert(destination_outbound.enable_write(
					    &destination_outbound));
					foreign_host.sockfds.insert(&destination_outbound);
					assert(foreign_host.queue_claimed_source_journal_replays(
					    &destination_outbound) &&
					    foreign_host.queue_claimed_source_journal_replays(
					    &destination_outbound) &&
					    foreign_host.joblist.size() == 1);
					job *replay = foreign_host.joblist.front();
					foreign_host.joblist.clear();
					std::thread replay_receiver([&] {
						uint8_t header_wire[DTRACED_MSGHDRSIZE];
						assert(recv(destination_outbound_pair[1], header_wire,
						    sizeof(header_wire), MSG_WAITALL) ==
						    (ssize_t)sizeof(header_wire));
						dtraced_hdr_t header{};
						assert(dtraced_wire_decode_header(&header,
						    header_wire) == 0 &&
						    DTRACED_MSG_TYPE(header) == DTRACED_MSG_ELF &&
						    header.elf.delivery_id == accepted_record.delivery_id &&
						    header.elf.len == bare_payload.size() +
						    SHA256_DIGEST_LENGTH &&
						    memcmp(header.elf.program_id,
						    accepted_record.program_id.data(), 16) == 0 &&
						    memcmp(header.elf.source_id,
						    accepted_record.source_id.data(), 16) == 0);
						std::vector<uint8_t> received(header.elf.len);
						assert(recv(destination_outbound_pair[1], received.data(),
						    received.size(), MSG_WAITALL) ==
						    (ssize_t)received.size() &&
						    memcmp(received.data(), accepted_record.payload_digest.data(),
						    SHA256_DIGEST_LENGTH) == 0 &&
						    memcmp(received.data() + SHA256_DIGEST_LENGTH,
						    bare_payload.data(), bare_payload.size()) == 0);
						dtraced_delivery_ack_t ack{};
						ack.delivery_id = accepted_record.delivery_id;
						uint8_t ack_wire[DTRACED_ACK_WIRE_SIZE];
						dtraced_wire_encode_ack(ack_wire, &ack);
						assert(::send(destination_outbound_pair[1], ack_wire,
						    sizeof(ack_wire), 0) == (ssize_t)sizeof(ack_wire));
					});
					assert(replay->send_elf());
					replay_receiver.join();
					delete replay;
					assert(destination_outbound.outbound_deliveries.size() == 1 &&
					    destination_outbound.outbound_deliveries.front().accepted &&
					    transfer_out.delivery_status(accepted_record) ==
					    (int)delivery_phase::accepted &&
					    foreign_host.queue_claimed_source_journal_replays(
					    &destination_outbound) &&
					    foreign_host.joblist.empty() &&
					    transfer_out.accept_claimed_source_journal_replay(
					    accepted_record) &&
					    transfer_out.claimed_source_journal_replay_payload(
					    accepted_record, replay_bytes) == -1 &&
					    errno == EBUSY && replay_bytes.empty());
					assert(transfer_out.mark_handoff_rekey_applied(
					    imported_ticket) &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_ACTIVATE_IMPORT) &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_ACTIVATE_IMPORT) &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_REPLAY_READY) &&
					    journal_phase(destination,
					    DTRACED_HANDOFF_REPLAY_READY) &&
					    transfer_out.delivery_status(accepted_record) ==
					    (int)delivery_phase::accepted &&
					    transfer_out.claimed_source_journal_status(
					    imported_ticket, destination.session_id,
					    (uint32_t)destination.peer_uid,
					    (uint32_t)destination.peer_pid, true) == 2);
					foreign_host.sockfds.erase(&destination_outbound);
				}
				for (const char *temp_path : {journal_path, ingress_path,
				    source_path}) {
					DIR *scan = opendir(temp_path);
					assert(scan != nullptr);
					for (dirent *entry;
					    (entry = readdir(scan)) != nullptr; )
						if (strcmp(entry->d_name, ".") != 0 &&
						    strcmp(entry->d_name, "..") != 0)
							assert(unlinkat(dirfd(scan),
							    entry->d_name, 0) == 0);
					assert(closedir(scan) == 0 &&
					    rmdir(temp_path) == 0);
				}
			}
			assert(send(source, wire));
			token[0] = 0xa2;
			assert(journal.handoff_status(token, observed) == 0);
			assert(source_status(source, reply) && reply.phase == 0 &&
			    reply.digest[0] == 0);
			wire.op = DTRACED_HANDOFF_SOURCE_GATE_ABORT;
			assert(send(source, wire) && !gate_suspended);
			wire.op = DTRACED_HANDOFF_PREPARE;
			bind_empty_bundle(wire);
			source_vm.epoch++;
			assert(!send(source, wire) && errno == EPROTO);
			source_vm.epoch--;
			wire.token[0] = 0;
			assert(!send(source, wire) && errno == EPROTO);
			/* A journal-free claimed ticket can transfer ownership after
			 * HRI1 and HRP1. The old incarnation has no execution lease
			 * after HRC1 commits, and an exact control retry is harmless. */
			destination.vmid = destination_vm.vmid = 14;
			destination.vm_epoch = destination_vm.epoch = 57;
			rival.vmid = rival_vm.vmid = 15;
			rival.vm_epoch = rival_vm.epoch = 58;
			destination_epoch_live = true;
			rival_epoch_live = true;
			durable_handoff empty_handoff{};
			empty_handoff.token[0] = 0xa7;
			empty_handoff.source_session[0] = 0x77;
			empty_handoff.source_vmid = 12;
			empty_handoff.source_epoch = 55;
			bind_empty_transfer(empty_handoff);
			empty_handoff.checkpoint_digest[0] = 0xc7;
			empty_handoff.destination_vmid = destination.vmid;
			empty_handoff.destination_epoch = destination.vm_epoch;
			durable_handoff empty_prepared = empty_handoff;
			empty_prepared.checkpoint_digest.fill(0);
			empty_prepared.destination_vmid = 0;
			empty_prepared.destination_epoch = 0;
			journal.state = nullptr;
			assert(journal.prepare_handoff(empty_prepared, false));
			durable_handoff empty_committed = empty_handoff;
			empty_committed.destination_vmid = 0;
			empty_committed.destination_epoch = 0;
			assert(journal.commit_handoff(empty_committed));
			journal.state = &host;
			assert(journal.record_source_release(empty_committed));
			assert(journal.reserve_handoff(empty_handoff));
			assert(journal.begin_handoff_mutation(empty_handoff));
			assert(journal.claim_handoff(empty_handoff));
			destination_epoch_live = false;
			rival_epoch_live = true;
			assert(journal.begin_handoff_rebind(empty_handoff,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid) &&
			    journal.stage_handoff_rebind(empty_handoff,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid) &&
			    journal.publish_handoff_rebind_pending(empty_handoff,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid));
			dtraced_handoff_request_t empty_ready{};
			empty_ready.op = DTRACED_HANDOFF_REBIND_EMPTY_READY;
			memcpy(empty_ready.token, empty_handoff.token.data(), 16);
			memcpy(empty_ready.digest,
			    empty_handoff.checkpoint_digest.data(), 32);
			assert(send(rival, empty_ready));
			durable_handoff still_old{};
			assert(journal.handoff_status(empty_handoff.token,
			    still_old) == (int)handoff_phase::claimed &&
			    still_old.destination_vmid == destination.vmid &&
			    still_old.destination_epoch == destination.vm_epoch);
			assert(!journal.mark_handoff_execution_start(empty_handoff) &&
			    errno == EBUSY);
			assert(journal.commit_handoff_rebind_empty(empty_handoff,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid));
			durable_handoff rebound{};
			assert(journal.handoff_status(empty_handoff.token,
			    rebound) == (int)handoff_phase::claimed &&
			    rebound.destination_vmid == rival.vmid &&
			    rebound.destination_epoch == rival.vm_epoch);
			dtraced_handoff_request_t commit_retry{};
			commit_retry.op = DTRACED_HANDOFF_REBIND_COMMIT_EMPTY;
			memcpy(commit_retry.token, empty_handoff.token.data(), 16);
			memcpy(commit_retry.digest,
			    empty_handoff.checkpoint_digest.data(), 32);
			assert(send(rival, commit_retry) &&
			    journal.handoff_rebind_empty_done(rebound,
			    rival.session_id, rival.peer_uid, rival.peer_pid));
			std::array<uint8_t, 16> wrong_rebind_session =
			    rival.session_id;
			wrong_rebind_session[0]++;
			assert(!journal.handoff_rebind_empty_done(rebound,
			    wrong_rebind_session, rival.peer_uid,
			    rival.peer_pid) && errno == EPERM);
			assert(!journal.mark_handoff_execution_start(empty_handoff) &&
			    errno == EBUSY);
			{
				dir reopened(path, nullptr);
				reopened.state = &host;
				host.outbounddir = &reopened;
				assert(reopened.populate_existing());
				host.outbounddir = &journal;
			}
			assert(journal.mark_handoff_execution_start(rebound));
			/* Simulate a crash after HRC1 and the capability replacement,
			 * but before the claimed HTH2 is replaced. Startup must finish
			 * that exact decision before its capability audit. */
			durable_handoff interrupted = empty_handoff;
			interrupted.token[0] = 0xa8;
			interrupted.source_session[0] = 0x78;
			interrupted.source_vmid = 13;
			interrupted.source_epoch = 56;
			interrupted.checkpoint_digest[0] = 0xc8;
			bind_empty_transfer(interrupted);
			durable_handoff interrupted_prepared = interrupted;
			interrupted_prepared.checkpoint_digest.fill(0);
			interrupted_prepared.destination_vmid = 0;
			interrupted_prepared.destination_epoch = 0;
			journal.state = nullptr;
			assert(journal.prepare_handoff(interrupted_prepared, false));
			durable_handoff interrupted_committed = interrupted;
			interrupted_committed.destination_vmid = 0;
			interrupted_committed.destination_epoch = 0;
			assert(journal.commit_handoff(interrupted_committed));
			journal.state = &host;
			assert(journal.record_source_release(interrupted_committed));
			assert(journal.reserve_handoff(interrupted));
			assert(journal.begin_handoff_mutation(interrupted));
			assert(journal.claim_handoff(interrupted));
			assert(journal.begin_handoff_rebind(interrupted,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid) &&
			    journal.stage_handoff_rebind(interrupted,
			    rival.vmid, rival.vm_epoch, rival.session_id,
			    rival.peer_uid, rival.peer_pid));
			const char *interrupted_intent =
			    ".handoff-rebind.a8000000000000000000000000000000";
			const char *interrupted_plan =
			    ".handoff-rebind-plan.a8000000000000000000000000000000";
			const char *interrupted_commit =
			    ".handoff-rebind-commit.a8000000000000000000000000000000";
			const char *interrupted_claimed =
			    ".handoff.a8000000000000000000000000000000.r";
			const char *interrupted_capable =
			    ".handoff-capable.a8000000000000000000000000000000";
			std::array<uint8_t, 228> saved_intent{};
			std::array<uint8_t, 288> saved_plan{};
			int fd = openat(journal.dirfd, interrupted_intent,
			    O_RDONLY | O_NOFOLLOW);
			assert(fd >= 0 && read(fd, saved_intent.data(),
			    saved_intent.size()) == (ssize_t)saved_intent.size() &&
			    close(fd) == 0);
			fd = openat(journal.dirfd, interrupted_plan,
			    O_RDONLY | O_NOFOLLOW);
			assert(fd >= 0 && read(fd, saved_plan.data(),
			    saved_plan.size()) == (ssize_t)saved_plan.size() &&
			    close(fd) == 0);
			assert(memcmp(saved_plan.data(), "HRP1", 4) == 0 &&
			    dtraced_wire_get_u32(saved_plan.data() + 236) == 0 &&
			    dtraced_wire_get_u32(saved_plan.data() + 240) == 0 &&
			    dtraced_wire_get_u32(saved_plan.data() + 244) == 0);
			std::array<uint8_t, 300> commit_wire{};
			memcpy(commit_wire.data(), "HRC1", 4);
			dtraced_wire_put_u32(commit_wire.data() + 4, 1);
			memcpy(commit_wire.data() + 8, saved_intent.data(),
			    saved_intent.size());
			memcpy(commit_wire.data() + 8 + saved_intent.size(),
			    saved_plan.data() + saved_plan.size() - 32, 32);
			assert(SHA256(commit_wire.data(), commit_wire.size() - 32,
			    commit_wire.data() + commit_wire.size() - 32) != nullptr);
			fd = openat(journal.dirfd, interrupted_commit,
			    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
			assert(fd >= 0 && write(fd, commit_wire.data(),
			    commit_wire.size()) == (ssize_t)commit_wire.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(journal.dirfd) == 0);
			std::array<uint8_t, 152> new_capable{};
			fd = openat(journal.dirfd, interrupted_claimed,
			    O_RDONLY | O_NOFOLLOW);
			assert(fd >= 0 && read(fd, new_capable.data(),
			    new_capable.size()) == (ssize_t)new_capable.size() &&
			    close(fd) == 0);
			dtraced_wire_put_u16(new_capable.data() + 78, rival.vmid);
			dtraced_wire_put_u64(new_capable.data() + 80, rival.vm_epoch);
			assert(SHA256(new_capable.data(), 120,
			    new_capable.data() + 120) != nullptr);
			fd = openat(journal.dirfd, interrupted_capable,
			    O_WRONLY | O_NOFOLLOW);
			assert(fd >= 0 && pwrite(fd, new_capable.data(),
			    new_capable.size(), 0) == (ssize_t)new_capable.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(journal.dirfd) == 0);
			{
				dir reopened(path, nullptr);
				reopened.state = &host;
				host.outbounddir = &reopened;
				assert(reopened.populate_existing());
				host.outbounddir = &journal;
			}
			assert(journal.handoff_status(interrupted.token,
			    rebound) == (int)handoff_phase::claimed &&
			    rebound.destination_vmid == rival.vmid &&
			    rebound.destination_epoch == rival.vm_epoch &&
			    faccessat(journal.dirfd, interrupted_commit, F_OK, 0) != 0 &&
			    errno == ENOENT);
			assert(journal.handoff_rebind_empty_done(rebound,
			    rival.session_id, rival.peer_uid, rival.peer_pid));
			/* A later retired proposal replaces the completion witness;
			 * the previous incarnation can no longer claim retry success. */
			rival_epoch_live = false;
			destination.vmid = destination_vm.vmid = 16;
			destination.vm_epoch = destination_vm.epoch = 59;
			destination_epoch_live = true;
			assert(journal.begin_handoff_rebind(rebound,
			    destination.vmid, destination.vm_epoch,
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid));
			assert(journal.stage_handoff_rebind(rebound,
			    destination.vmid, destination.vm_epoch,
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid));
			assert(journal.publish_handoff_rebind_pending(rebound,
			    destination.vmid, destination.vm_epoch,
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid));
			assert(journal.commit_handoff_rebind_empty(rebound,
			    destination.vmid, destination.vm_epoch,
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid));
			assert(journal.handoff_status(interrupted.token,
			    rebound) == (int)handoff_phase::claimed &&
			    rebound.destination_vmid == destination.vmid &&
			    rebound.destination_epoch == destination.vm_epoch &&
			    journal.handoff_rebind_empty_done(rebound,
			    destination.session_id, destination.peer_uid,
			    destination.peer_pid));
			assert(!journal.handoff_rebind_empty_done(rebound,
			    rival.session_id, rival.peer_uid, rival.peer_pid) &&
			    errno == EPERM);
			const char *done_name =
			    ".handoff-rebind-done.a8000000000000000000000000000000";
			fd = openat(journal.dirfd, done_name, O_RDWR | O_NOFOLLOW);
			assert(fd >= 0);
			uint8_t done_byte;
			assert(pread(fd, &done_byte, 1, 268) == 1);
			uint8_t damaged_done = done_byte ^ 1;
			assert(pwrite(fd, &damaged_done, 1, 268) == 1 &&
			    fsync(fd) == 0);
			{
				dir reopened(path, nullptr);
				reopened.state = &host;
				host.outbounddir = &reopened;
				assert(!reopened.populate_existing() && errno == EPROTO);
				host.outbounddir = &journal;
			}
			assert(pwrite(fd, &done_byte, 1, 268) == 1 &&
			    fsync(fd) == 0 && close(fd) == 0);
			{
				dir reopened(path, nullptr);
				reopened.state = &host;
				host.outbounddir = &reopened;
				assert(reopened.populate_existing());
				host.outbounddir = &journal;
			}
		}
		/* A retired, never-capable MUTATE can be reset. A durable reset
		 * marker also makes a crash with both m and c phase files replayable. */
		destination_vm.vmid = 21;
		destination_vm.epoch = 501;
		for (uint8_t suffix : { (uint8_t)0xb0, (uint8_t)0xb1 }) {
			durable_handoff reset{};
			reset.token[0] = suffix;
			reset.source_session[0] = suffix;
			reset.source_vmid = 20;
			reset.source_epoch = 61 + suffix;
			reset.checkpoint_digest[0] = suffix;
			reset.destination_vmid = destination_vm.vmid;
			reset.destination_epoch = destination_vm.epoch;
			bind_empty_transfer(reset);
			durable_handoff prepared = reset;
			prepared.checkpoint_digest.fill(0);
			prepared.destination_vmid = 0;
			prepared.destination_epoch = 0;
			journal.state = nullptr;
			assert(journal.prepare_handoff(prepared, false));
			durable_handoff committed = reset;
			committed.destination_vmid = 0;
			committed.destination_epoch = 0;
			assert(journal.commit_handoff(committed));
			journal.state = &host;
			assert(journal.record_source_release(committed));
			assert(journal.reserve_handoff(reset));
			assert(journal.begin_handoff_mutation(reset));
			assert(!journal.reset_handoff_mutation(reset.token,
			    reset.checkpoint_digest, reset.destination_vmid,
			    reset.destination_epoch) && errno == EPERM);
			destination_epoch_live = true;
			assert(!journal.reset_handoff_mutation(reset.token,
			    reset.checkpoint_digest, rival_vm.vmid,
			    rival_vm.epoch) && errno == EBUSY);
			destination_epoch_live = false;
			if (suffix == 0xb0) {
				int reset_pair[2];
				assert(socketpair(AF_UNIX, SOCK_STREAM, 0,
				    reset_pair) == 0);
				dtd_initmsg_t hello{};
				hello.kind = DTRACED_KIND_FORWARDER;
				hello.subs = DTD_SUB_READDATA;
				hello.protocol_version =
				    DTRACED_PROTOCOL_VERSION;
				hello.session_id[0] = 0x91;
				strlcpy(hello.ident, "rival-vm",
				    sizeof(hello.ident));
				{
					client_fd replacement(kq,
					    reset_pair[0], hello);
					replacement.vmid = rival_vm.vmid;
					replacement.vm_epoch = rival_vm.epoch;
					rival_attestation_fd =
					    replacement.vm_attestation_fd =
					    dup(reset_pair[0]);
					assert(rival_attestation_fd >= 0);
					dtraced_handoff_request_t wire{};
					wire.op = DTRACED_HANDOFF_RESET_MUTATION;
					memcpy(wire.token, reset.token.data(), 16);
					memcpy(wire.digest,
					    reset.checkpoint_digest.data(), 32);
					for (int retry = 0; retry < 2; retry++) {
						dtraced_hdr_t header{};
						header.msg_type =
						    DTRACED_MSG_HANDOFF;
						client_request request(host, header,
						    (unsigned char *)&wire,
						    sizeof(wire), &replacement);
						assert(request.handle());
					}
				}
				assert(close(reset_pair[1]) == 0);
			} else {
				char mutating_name[44], committed_name[44],
				    marker_name[48];
				assert(snprintf(mutating_name,
				    sizeof(mutating_name), ".handoff.%02x%030x.m",
				    suffix, 0) == 43);
				assert(snprintf(committed_name,
				    sizeof(committed_name), ".handoff.%02x%030x.c",
				    suffix, 0) == 43);
				assert(snprintf(marker_name, sizeof(marker_name),
				    ".handoff-reset.%02x%030x", suffix, 0) == 47);
				uint8_t wire[152];
				int fd = openat(journal.dirfd, mutating_name,
				    O_RDONLY | O_NOFOLLOW);
				assert(fd >= 0 && read(fd, wire, sizeof(wire)) ==
				    (ssize_t)sizeof(wire) && close(fd) == 0);
				fd = openat(journal.dirfd, marker_name,
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
				assert(fd >= 0 && write(fd, wire, sizeof(wire)) ==
				    (ssize_t)sizeof(wire) && fsync(fd) == 0 &&
				    close(fd) == 0 && fsync(journal.dirfd) == 0);
				memset(wire + 78, 0, 10);
				assert(SHA256(wire, 120, wire + 120) != nullptr);
				fd = openat(journal.dirfd, committed_name,
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
				assert(fd >= 0 && write(fd, wire, sizeof(wire)) ==
				    (ssize_t)sizeof(wire) && fsync(fd) == 0 &&
				    close(fd) == 0 && fsync(journal.dirfd) == 0);
				durable_handoff blocked{};
				assert(journal.handoff_status(reset.token, blocked) < 0 &&
				    errno == EBUSY);
				{
					dir reopened(path, nullptr);
					reopened.state = &host;
					host.outbounddir = &reopened;
					assert(reopened.populate_existing());
					host.outbounddir = &journal;
				}
				assert(faccessat(journal.dirfd, marker_name,
				    F_OK, 0) != 0 && errno == ENOENT);
			}
			durable_handoff after{};
			assert(journal.handoff_status(reset.token, after) ==
			    (int)handoff_phase::committed &&
			    after.checkpoint_digest == reset.checkpoint_digest);
		}
		close(source_pair[1]);
		close(destination_pair[1]);
		close(destination_outbound_pair[1]);
		close(rival_pair[1]);
		close(kq);
		DIR *scan = opendir(path);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; )
			if (strcmp(entry->d_name, ".") != 0 &&
			    strcmp(entry->d_name, "..") != 0)
				assert(unlinkat(journal.dirfd, entry->d_name, 0) == 0);
		assert(closedir(scan) == 0);
		scan = opendir(ingresspath);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; )
			if (strcmp(entry->d_name, ".") != 0 &&
			    strcmp(entry->d_name, "..") != 0)
				assert(unlinkat(incoming.dirfd, entry->d_name,
				    0) == 0);
		assert(closedir(scan) == 0);
	}
	assert(rmdir(path) == 0);
	assert(rmdir(ingresspath) == 0);
	puts("PASS: attested source handoff and destination lease control");
}
