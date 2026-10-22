/* SPDX-License-Identifier: BSD-2-Clause */
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/hypertrace.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <openssl/sha.h>

/* Exercise the private HRC2 recovery reader in this translation unit. */
#include "dtraced_directory.cc"
#include "dtraced_state.h"
#include "dtraced_transfer_wire.h"

using namespace dtraced;

static int rebind_epoch_fd = -1;

extern "C" int __real_open(const char *, int, ...);
extern "C" int
__wrap_open(const char *path, int flags, ...)
{
	if (strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		rebind_epoch_fd = __real_open("/dev/null", flags);
		return (rebind_epoch_fd);
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
	if (fd != rebind_epoch_fd || request != HYPERTRACE_IOC_EPOCH_QUERY) {
		errno = ENOTTY;
		return (-1);
	}
	va_list args;
	va_start(args, request);
	auto *query = va_arg(args, hypertrace_epoch_query *);
	va_end(args);
	assert(query->vmid != 0 && query->epoch != 0 && query->live == 0);
	return (0); /* both staged owners are retired in this fixture */
}

namespace dtraced {
struct state_attestation_test {
	static void set_control(state &s) { s.ctrlmachine = 1; }
};
}

static std::string
find_stage(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(scanfd >= 0);
	DIR *scan = fdopendir(scanfd);
	assert(scan != nullptr);
	std::string found;
	for (dirent *entry; (entry = readdir(scan)) != nullptr;)
		if (strncmp(entry->d_name, ".hjb1.", 6) == 0) {
			assert(found.empty());
			found = entry->d_name;
		}
	assert(closedir(scan) == 0);
	return (found);
}

static std::string
find_ready(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(scanfd >= 0);
	DIR *scan = fdopendir(scanfd);
	assert(scan != nullptr);
	std::string found;
	for (dirent *entry; (entry = readdir(scan)) != nullptr;)
		if (strncmp(entry->d_name, ".hjr1.", 6) == 0) {
			assert(found.empty());
			found = entry->d_name;
		}
	assert(closedir(scan) == 0);
	return (found);
}

static std::string
find_pending_delivery(int directory)
{
	int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(scanfd >= 0);
	DIR *scan = fdopendir(scanfd);
	assert(scan != nullptr);
	std::string found;
	for (dirent *entry; (entry = readdir(scan)) != nullptr;) {
		const std::string name(entry->d_name);
		if (name.compare(0, 10, ".delivery.") != 0 ||
		    name.size() < 3 || name.substr(name.size() - 2) != ".p")
			continue;
		assert(found.empty());
		found = name;
	}
	assert(closedir(scan) == 0);
	return (found);
}

static void
remove_directory(const char *path)
{
	DIR *scan = opendir(path);
	assert(scan != nullptr);
	for (dirent *entry; (entry = readdir(scan)) != nullptr;)
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0)
			assert(unlinkat(dirfd(scan), entry->d_name, 0) == 0);
	assert(closedir(scan) == 0 && rmdir(path) == 0);
}

static void
reseal(std::vector<uint8_t> &wire)
{
	assert(wire.size() >= SHA256_DIGEST_LENGTH);
	assert(SHA256(wire.data(), wire.size() - SHA256_DIGEST_LENGTH,
	    wire.data() + wire.size() - SHA256_DIGEST_LENGTH) != nullptr);
}

int
main()
{
	durable_handoff ticket{};
	ticket.token[0] = 0xa1;
	ticket.source_session[0] = 0xb2;
	ticket.source_vmid = 7;
	ticket.source_epoch = 11;
	ticket.transfer_digest[0] = 0xc3;
	source_journal_cut cut{};
	source_journal_delivery delivery{};
	auto &record = delivery.state.record;
	record.session_id = ticket.source_session;
	record.delivery_id = 77;
	record.vmid = ticket.source_vmid;
	record.epoch = ticket.source_epoch;
	record.program_id[0] = 1;
	record.source_id[0] = 2;
	record.peer_uid = 0;
	record.peer_pid = 123;
	record.journal_version = 4;
	const uint8_t elf[] = "\177ELFjournal";
	assert(SHA256(elf, sizeof(elf) - 1,
	    record.payload_digest.data()) != nullptr);
	delivery.state.phase = delivery_phase::accepted;
	delivery.payload.assign(elf, elf + sizeof(elf) - 1);
	cut.deliveries.push_back(delivery);
	source_journal_kill kill{};
	kill.record.pid = 321;
	kill.record.vmid = ticket.source_vmid;
	kill.record.epoch = ticket.source_epoch;
	kill.record.source_id[0] = 3;
	kill.applied = true;
	cut.kills.push_back(kill);
	source_journal_cleanup cleanup{};
	cleanup.record.vmid = ticket.source_vmid;
	cleanup.record.epoch = ticket.source_epoch;
	cleanup.record.delivery_id = 88;
	cleanup.phase = 'a';
	cut.cleanups.push_back(cleanup);
	std::vector<uint8_t> wire;
	assert(dir::encode_source_journal_archive(ticket, cut, wire));
	assert(wire.size() > 64 + 32 &&
	    memcmp(wire.data(), "HJX1", 4) == 0);
	std::vector<uint8_t> manifest, transfer;
	std::vector<std::vector<uint8_t>> frames;
	assert(dtraced_transfer_journal_wrap(ticket.token.data(), {}, {},
	    wire, manifest, frames) &&
	    dtraced_transfer_wire_build(ticket.token.data(), manifest,
	    frames, transfer));
	int has_ingress = -1, has_journal = -1;
	int requires_import = -1;
	assert(dtraced_transfer_wire_inspect(transfer.data(),
	    transfer.size(), ticket.token.data(), &has_ingress,
	    &has_journal) && has_ingress == 0 && has_journal == 1);
	size_t replay_controls = 0;
	assert(dtraced_transfer_wire_replay_controls(transfer.data(),
	    transfer.size(), ticket.token.data(), 24, 2048,
	    &replay_controls) && replay_controls == 3);
	/* A correctly rehashed archive with malformed KILL or CLEANUP fields
	 * must not pass the queue planner before the full import decoder runs. */
	const size_t kill_offset = 64 + 12 +
	    dtraced_wire_get_u16(wire.data() + 64 + 4) +
	    dtraced_wire_get_u32(wire.data() + 64 + 8);
	const size_t cleanup_offset = kill_offset + 24;
	for (size_t offset : {kill_offset + 2, kill_offset + 4,
	    kill_offset + 8, cleanup_offset + 2, cleanup_offset + 8}) {
		auto malformed = wire;
		if (offset == kill_offset + 4)
			dtraced_wire_put_u32(malformed.data() + offset, 1);
		else if (offset == kill_offset + 8)
			memset(malformed.data() + offset, 0, 16);
		else if (offset == cleanup_offset + 8)
			dtraced_wire_put_u64(malformed.data() + offset, 0);
		else
			malformed[offset] = 1;
		reseal(malformed);
		assert(dtraced_transfer_journal_wrap(ticket.token.data(), {},
		    {}, malformed, manifest, frames) &&
		    dtraced_transfer_wire_build(ticket.token.data(), manifest,
		    frames, transfer) &&
		    !dtraced_transfer_wire_replay_controls(transfer.data(),
		    transfer.size(), ticket.token.data(), 24, 2048,
		    &replay_controls) && errno == EPROTO);
	}
	assert(dtraced_transfer_journal_wrap(ticket.token.data(), {}, {},
	    wire, manifest, frames) &&
	    dtraced_transfer_wire_build(ticket.token.data(), manifest,
	    frames, transfer));
	durable_handoff reserved = ticket;
	reserved.checkpoint_digest[0] = 1;
	reserved.destination_vmid = 8;
	reserved.destination_epoch = 12;
	memcpy(reserved.transfer_digest.data(), transfer.data() +
	    transfer.size() - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
	source_journal_cut destination_journal;
	host_ingress_transfer_bundle destination_ingress;
	assert(dir::decode_source_journal_transfer_wire(reserved, transfer,
	    destination_journal, destination_ingress) &&
	    destination_journal.deliveries.size() == 1 &&
	    destination_journal.kills.size() == 1 &&
	    destination_journal.cleanups.size() == 1 &&
	    destination_ingress.entries.empty());
	{
		char outbound_path[] = "/tmp/hypertrace-hjx1-export-out.XXXXXX";
		char inbound_path[] = "/tmp/hypertrace-hjx1-export-in.XXXXXX";
		assert(mkdtemp(outbound_path) != nullptr &&
		    mkdtemp(inbound_path) != nullptr);
		{
			dir outbound(outbound_path, nullptr);
			dir inbound(inbound_path, nullptr);
			state control{};
			state_attestation_test::set_control(control);
			control.outbounddir = &outbound;
			control.inbounddir = &inbound;
			outbound.state = &control;
			inbound.state = &control;
			std::vector<uint8_t> exported, empty;
			assert(outbound.source_journal_transfer_wire_export(ticket,
			    exported) &&
			    dtraced_transfer_wire_build(ticket.token.data(), {}, {},
			    empty) && exported == empty);
			durable_handoff prepared = ticket;
			memcpy(prepared.transfer_digest.data(), empty.data() +
			    empty.size() - SHA256_DIGEST_LENGTH,
			    SHA256_DIGEST_LENGTH);
			assert(outbound.prepare_handoff(prepared, false) &&
			    outbound.source_journal_transfer_wire_export(prepared,
			    exported) && exported == empty);
			assert(outbound.prepare_handoff(prepared, false));
			assert(outbound.record_kill(kill.record) &&
			    outbound.record_kill_applied(kill.record));
			assert(!outbound.prepare_handoff(prepared, false) &&
			    errno == EPROTO);
			assert(!outbound.source_journal_transfer_wire_export(prepared,
			    exported) && errno == EPROTO && exported.empty());
			durable_handoff committed = prepared;
			committed.checkpoint_digest[0] = 1;
			assert(!outbound.commit_handoff(committed) && errno == EPROTO);
			assert(outbound.abort_handoff(prepared));
			assert(outbound.source_journal_transfer_wire_export(ticket,
			    exported) && exported != empty &&
			    dtraced_transfer_wire_inspect(exported.data(),
			    exported.size(), ticket.token.data(), &has_ingress,
			    &has_journal) && has_ingress == 0 && has_journal == 1);
			assert(!outbound.prepare_handoff(prepared, false) &&
			    errno == EPROTO); /* The former empty HTX1 is stale. */
			durable_handoff journal_ticket = ticket;
			memcpy(journal_ticket.transfer_digest.data(),
			    exported.data() + exported.size() - SHA256_DIGEST_LENGTH,
			    SHA256_DIGEST_LENGTH);
			assert(!outbound.prepare_handoff(journal_ticket, false) &&
			    errno == EOPNOTSUPP);
			durable_handoff destination = reserved;
			memcpy(destination.transfer_digest.data(),
			    exported.data() + exported.size() - SHA256_DIGEST_LENGTH,
			    SHA256_DIGEST_LENGTH);
			assert(dir::decode_source_journal_transfer_wire(destination,
			    exported, destination_journal, destination_ingress) &&
			    destination_journal.deliveries.empty() &&
			    destination_journal.kills.size() == 1 &&
			    destination_journal.cleanups.empty());
		}
		remove_directory(outbound_path);
		remove_directory(inbound_path);
	}
	{
		char outbound_path[] = "/tmp/hypertrace-hjb1-out.XXXXXX";
		char inbound_path[] = "/tmp/hypertrace-hjb1-in.XXXXXX";
		assert(mkdtemp(outbound_path) != nullptr &&
		    mkdtemp(inbound_path) != nullptr);
		{
			dir outbound(outbound_path, nullptr);
			dir inbound(inbound_path, nullptr);
			durable_handoff source = ticket;
			source.transfer_digest = reserved.transfer_digest;
			assert(outbound.prepare_handoff(source, false));
			source.checkpoint_digest = reserved.checkpoint_digest;
			assert(outbound.commit_handoff(source) &&
			    outbound.record_source_release(source));
			assert(outbound.reserve_handoff(reserved));
			state control{};
			state_attestation_test::set_control(control);
			control.outbounddir = &outbound;
			control.inbounddir = &inbound;
			outbound.state = &control;
			inbound.state = &control;
			assert(outbound.load_source_journal_destination_stage(
			    reserved, destination_journal, destination_ingress) == 0);
			std::array<uint8_t, 16> destination_session{};
			destination_session[0] = 0xf1;
			source_journal_destination_plan mapped;
			assert(outbound.plan_source_journal_destination(reserved,
			    destination_session, 100, 200, mapped) == 0 &&
			    mapped.deliveries.empty());
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 0 &&
			    mapped.deliveries.empty());
			host_ingress_destination_plan plan;
			assert(inbound.stage_host_ingress_destination_wire_reserved(
			    reserved, transfer, destination_session, 100, 200,
			    "guest-b", plan) == 2 && plan.deliveries.empty());
			assert(inbound.stage_host_ingress_destination_wire_reserved(
			    reserved, transfer, destination_session, 100, 200,
			    "guest-b", plan) == 2 && plan.deliveries.empty());
			const std::string stage_name = find_stage(outbound.dirfd);
			assert(!stage_name.empty());
			std::array<uint8_t, 16> wrong_session =
			    destination_session;
			wrong_session[0] ^= 1;
			assert(inbound.stage_host_ingress_destination_wire_reserved(
			    reserved, transfer, wrong_session, 100, 200,
			    "guest-b", plan) == -1 && errno == EEXIST);
			durable_handoff observed{};
			assert(!outbound.begin_handoff_mutation(reserved) &&
			    errno == EBUSY &&
			    outbound.handoff_status(reserved.token, observed) ==
			    (int)handoff_phase::reserved);
			assert(outbound.load_source_journal_destination_stage(
			    reserved, destination_journal, destination_ingress) == 1 &&
			    destination_journal.deliveries.size() == 1);
			durable_delivery_state staged_delivery{};
			bool staged_revoked = false, staged_payload = false;
			assert(outbound.handoff_delivery_status(reserved, 0,
			    record.delivery_id, record.program_id, record.source_id,
			    staged_delivery, staged_revoked, staged_payload, nullptr) == 1 &&
			    staged_delivery.phase == delivery_phase::accepted &&
			    !staged_revoked && staged_payload);
			assert(outbound.handoff_kill_status(reserved, kill.record.pid,
			    kill.record.source_id, staged_revoked) == 'a' &&
			    staged_revoked);
			assert(outbound.handoff_cleanup_status(reserved,
			    cleanup.record.delivery_id) == 'a');
			assert(outbound.handoff_cleanup_status(reserved,
			    cleanup.record.delivery_id + 1) == 0);
			assert(outbound.plan_source_journal_destination(reserved,
			    destination_session, 100, 200, mapped) == 1 &&
			    !mapped.has_ingress && mapped.deliveries.size() == 1 &&
			    mapped.pending_kills.size() == 1 &&
			    mapped.queued_cleanups.size() == 1 &&
			    mapped.revoked_sources.size() == 1);
			const durable_delivery mapped_delivery =
			    mapped.deliveries[0].state.record;
			assert(mapped_delivery.session_id == destination_session &&
			    mapped_delivery.vmid == reserved.destination_vmid &&
			    mapped_delivery.epoch == reserved.destination_epoch &&
			    mapped_delivery.source_session == ticket.source_session &&
			    mapped_delivery.payload_vmid == ticket.source_vmid &&
			    mapped_delivery.payload_epoch == ticket.source_epoch &&
			    mapped_delivery.handoff_token == ticket.token &&
			    mapped.deliveries[0].payload == delivery.payload &&
			    mapped.pending_kills[0].vmid == reserved.destination_vmid &&
			    mapped.pending_kills[0].epoch == reserved.destination_epoch &&
			    mapped.queued_cleanups[0].vmid ==
			    reserved.destination_vmid &&
			    mapped.revoked_sources[0] == kill.record.source_id);
			assert(outbound.plan_source_journal_destination(reserved,
			    ticket.source_session, 100, 200, mapped) == -1 &&
			    errno == EINVAL && mapped.deliveries.empty());
			assert(outbound.plan_source_journal_destination(reserved,
			    wrong_session, 100, 200, mapped) == -1 &&
			    errno == EPERM && mapped.deliveries.empty());
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 1 &&
			    mapped.deliveries.size() == 1 &&
			    mapped.pending_kills.size() == 1);
			assert(!outbound.import_source_journal_pending(reserved,
			    wrong_session, 100, 200) && errno == EPERM);
			assert(outbound.import_source_journal_pending(reserved,
			    destination_session, 100, 200) &&
			    outbound.import_source_journal_pending(reserved,
			    destination_session, 100, 200));
			std::vector<durable_delivery_state> pending_records;
			assert(outbound.list_deliveries(pending_records) &&
			    pending_records.size() == 1 &&
			    pending_records[0].phase == delivery_phase::pending &&
			    pending_records[0].record.handoff_token == reserved.token &&
			    pending_records[0].record.payload_digest ==
			    mapped_delivery.payload_digest);
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 2 &&
			    mapped.deliveries.size() == 1);
			const std::string ready_name = find_ready(outbound.dirfd);
			assert(!ready_name.empty());
			std::array<uint8_t, 128> saved_ready{};
			{
				int marker_fd = openat(outbound.dirfd,
				    ready_name.c_str(), O_RDWR | O_NOFOLLOW |
				    O_CLOEXEC);
				assert(marker_fd >= 0 && pread(marker_fd,
				    saved_ready.data(), saved_ready.size(), 0) ==
				    (ssize_t)saved_ready.size());
				uint8_t changed = saved_ready[88] ^ 1;
				assert(pwrite(marker_fd, &changed, 1, 88) == 1 &&
				    fsync(marker_fd) == 0);
				assert(outbound.source_journal_pending_status(reserved,
				    destination_session, 100, 200, mapped) == -1 &&
				    errno == EPROTO);
				{
					dir audit(outbound_path, nullptr);
					audit.state = &control;
					control.outbounddir = &audit;
					assert(!audit.populate_existing() &&
					    errno == EPROTO);
					control.outbounddir = &outbound;
				}
				assert(pwrite(marker_fd, saved_ready.data() + 88,
				    1, 88) == 1 && fsync(marker_fd) == 0 &&
				    close(marker_fd) == 0);
			}
			const std::string pending_name =
			    find_pending_delivery(outbound.dirfd);
			assert(!pending_name.empty());
			{
				std::vector<uint8_t> extra_record(185);
				int extra_fd = openat(outbound.dirfd,
				    pending_name.c_str(), O_RDONLY | O_NOFOLLOW |
				    O_CLOEXEC);
				assert(extra_fd >= 0 && pread(extra_fd,
				    extra_record.data(), extra_record.size(), 0) ==
				    (ssize_t)extra_record.size() && close(extra_fd) == 0);
				extra_record[20] = 78;
				extra_record[38] = 9;
				reseal(extra_record);
				std::string extra_name = pending_name;
				extra_name.replace(43, 16, "000000000000004e");
				extra_fd = openat(outbound.dirfd, extra_name.c_str(),
				    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
				    O_CLOEXEC, 0600);
				assert(extra_fd >= 0 && write(extra_fd,
				    extra_record.data(), extra_record.size()) ==
				    (ssize_t)extra_record.size() &&
				    fsync(extra_fd) == 0 && close(extra_fd) == 0 &&
				    fsync(outbound.dirfd) == 0);
				assert(outbound.source_journal_pending_status(reserved,
				    destination_session, 100, 200, mapped) == -1 &&
				    errno == EPROTO &&
				    !outbound.import_source_journal_pending(reserved,
				    destination_session, 100, 200) &&
				    errno == EPROTO);
				assert(unlinkat(outbound.dirfd, extra_name.c_str(), 0) == 0 &&
				    fsync(outbound.dirfd) == 0 &&
				    outbound.source_journal_pending_status(reserved,
				    destination_session, 100, 200, mapped) == 2);
			}
			assert(unlinkat(outbound.dirfd, ready_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 1 &&
			    outbound.populate_existing() &&
			    outbound.import_source_journal_pending(reserved,
			    destination_session, 100, 200) &&
			    find_ready(outbound.dirfd) == ready_name &&
			    outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 2);
			{
				int scanfd = openat(outbound.dirfd, ".",
				    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
				assert(scanfd >= 0);
				DIR *scan = fdopendir(scanfd);
				assert(scan != nullptr);
				for (dirent *entry; (entry = readdir(scan)) != nullptr;)
					assert(entry->d_name[0] == '.');
				assert(closedir(scan) == 0);
			}
			{
				dir reopened(outbound_path, nullptr);
				reopened.state = &control;
				control.outbounddir = &reopened;
				assert(reopened.populate_existing());
				pending_records.clear();
				assert(reopened.list_deliveries(pending_records) &&
				    pending_records.size() == 1 &&
				    pending_records[0].phase ==
				    delivery_phase::pending &&
				    reopened.import_source_journal_pending(reserved,
				    destination_session, 100, 200));
				assert(reopened.load_source_journal_destination_stage(
				    reserved, destination_journal,
				    destination_ingress) == 1 &&
				    destination_journal.kills.size() == 1);
				control.outbounddir = &outbound;
			}
			std::string advanced_name = pending_name;
			advanced_name.back() = 'a';
			assert(renameat(outbound.dirfd, pending_name.c_str(),
			    outbound.dirfd, advanced_name.c_str()) == 0);
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == -1 &&
			    errno == EBUSY);
			{
				dir audit(outbound_path, nullptr);
				audit.state = &control;
				control.outbounddir = &audit;
				assert(!audit.populate_existing() && errno == EPROTO);
				control.outbounddir = &outbound;
			}
			assert(renameat(outbound.dirfd, advanced_name.c_str(),
			    outbound.dirfd, pending_name.c_str()) == 0 &&
			    fsync(outbound.dirfd) == 0);
			durable_handoff wrong_destination = reserved;
			wrong_destination.destination_epoch++;
			assert(inbound.stage_host_ingress_destination_wire_reserved(
			    wrong_destination, transfer, destination_session, 100,
			    200, "guest-b", plan) == -1 && errno == EBUSY);
			int fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_RDWR | O_NOFOLLOW | O_CLOEXEC);
			assert(fd >= 0);
			uint8_t original;
			assert(pread(fd, &original, 1, 80) == 1);
			uint8_t changed = original ^ 1;
			assert(pwrite(fd, &changed, 1, 80) == 1 &&
			    fsync(fd) == 0);
			assert(outbound.load_source_journal_destination_stage(
			    reserved, destination_journal, destination_ingress) == -1 &&
			    errno == EPROTO && destination_journal.deliveries.empty());
			assert(!outbound.begin_handoff_mutation(reserved) &&
			    errno == EPROTO &&
			    outbound.handoff_status(reserved.token, observed) ==
			    (int)handoff_phase::reserved);
			{
				dir audit(outbound_path, nullptr);
				audit.state = &control;
				control.outbounddir = &audit;
				assert(!audit.populate_existing() && errno == EPROTO);
				control.outbounddir = &outbound;
			}
			assert(!outbound.cancel_handoff_reservation(reserved) &&
			    errno == EPROTO);
			assert(pwrite(fd, &original, 1, 80) == 1 &&
			    fsync(fd) == 0 && close(fd) == 0);
			assert(outbound.populate_existing());
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
			assert(fd >= 0);
			struct stat sb{};
			assert(fstat(fd, &sb) == 0 && sb.st_size > 0);
			std::vector<uint8_t> saved_stage((size_t)sb.st_size);
			assert(pread(fd, saved_stage.data(), saved_stage.size(), 0) ==
			    (ssize_t)saved_stage.size() && close(fd) == 0);
			assert(unlinkat(outbound.dirfd, stage_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    !outbound.begin_handoff_mutation(reserved) &&
			    errno == EPROTO);
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 && write(fd, saved_stage.data(),
			    saved_stage.size()) == (ssize_t)saved_stage.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    outbound.populate_existing());
			std::vector<uint8_t> legacy_stage = saved_stage;
			legacy_stage.erase(legacy_stage.begin() + 80,
			    legacy_stage.begin() + 104);
			dtraced_wire_put_u32(legacy_stage.data() + 4, 1);
			reseal(legacy_stage);
			assert(unlinkat(outbound.dirfd, ready_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0);
			assert(unlinkat(outbound.dirfd, stage_name.c_str(), 0) == 0);
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 &&
			    write(fd, legacy_stage.data(), legacy_stage.size()) ==
			    (ssize_t)legacy_stage.size() && fsync(fd) == 0 &&
			    close(fd) == 0 && fsync(outbound.dirfd) == 0);
			assert(!outbound.populate_existing() && errno == EPROTO);
			assert(unlinkat(outbound.dirfd, pending_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0);
			assert(outbound.populate_existing() &&
			    outbound.load_source_journal_destination_stage(reserved,
			    destination_journal, destination_ingress) == 1 &&
			    outbound.plan_source_journal_destination(reserved,
			    destination_session, 100, 200, mapped) == -1 &&
			    errno == EOPNOTSUPP);
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == -1 &&
			    errno == EOPNOTSUPP);
			assert(unlinkat(outbound.dirfd, stage_name.c_str(), 0) == 0);
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 &&
			    write(fd, saved_stage.data(), saved_stage.size()) ==
			    (ssize_t)saved_stage.size() && fsync(fd) == 0 &&
			    close(fd) == 0 && fsync(outbound.dirfd) == 0 &&
			    outbound.populate_existing());
			assert(outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 1);
			assert(outbound.import_source_journal_pending(reserved,
			    destination_session, 100, 200) &&
			    outbound.source_journal_pending_status(reserved,
			    destination_session, 100, 200, mapped) == 2);
			assert(renameat(outbound.dirfd, pending_name.c_str(),
			    outbound.dirfd, advanced_name.c_str()) == 0);
			assert(!outbound.cancel_handoff_reservation(reserved) &&
			    errno == EBUSY && !find_stage(outbound.dirfd).empty());
			assert(renameat(outbound.dirfd, advanced_name.c_str(),
			    outbound.dirfd, pending_name.c_str()) == 0 &&
			    fsync(outbound.dirfd) == 0);
			assert(outbound.cancel_handoff_reservation(reserved));
			assert(find_stage(outbound.dirfd).empty() &&
			    find_ready(outbound.dirfd).empty());
			pending_records.clear();
			assert(outbound.list_deliveries(pending_records) &&
			    pending_records.empty());
			fd = openat(outbound.dirfd, ready_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 && write(fd, saved_ready.data(),
			    saved_ready.size()) == (ssize_t)saved_ready.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(outbound.dirfd) == 0);
			assert(!outbound.populate_existing() && errno == EPROTO);
			assert(unlinkat(outbound.dirfd, ready_name.c_str(), 0) == 0);
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0);
			assert(write(fd, saved_stage.data(), saved_stage.size()) ==
			    (ssize_t)saved_stage.size() && fsync(fd) == 0 &&
			    close(fd) == 0);
			assert(!outbound.populate_existing() && errno == EPROTO);
			assert(unlinkat(outbound.dirfd, stage_name.c_str(), 0) == 0);
			/* A complete journal-only HJB1/HJR1 and exact pending HTD5
			 * survive both phase transitions and their retry paths. */
			assert(outbound.reserve_handoff(reserved) &&
			    outbound.stage_source_journal_destination_wire(reserved,
			    transfer, destination_session, 100, 200) &&
			    outbound.import_source_journal_pending(reserved,
			    destination_session, 100, 200));
			assert(renameat(outbound.dirfd, pending_name.c_str(),
			    outbound.dirfd, advanced_name.c_str()) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    !outbound.begin_handoff_mutation(reserved) &&
			    errno == EPROTO &&
			    renameat(outbound.dirfd, advanced_name.c_str(),
			    outbound.dirfd, pending_name.c_str()) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    outbound.begin_handoff_mutation(reserved) &&
			    outbound.begin_handoff_mutation(reserved) &&
			    outbound.claim_handoff(reserved) &&
			    outbound.claim_handoff(reserved) &&
			    outbound.populate_existing());
			assert(unlinkat(outbound.dirfd, stage_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    !outbound.bind_handoff_kills_all(reserved) &&
			    errno == EPROTO);
			bool missing_stage_revoked = false;
			assert(outbound.handoff_kill_status(reserved,
			    kill.record.pid, kill.record.source_id,
			    missing_stage_revoked) == -1 && errno == EPROTO);
			fd = openat(outbound.dirfd, stage_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 && write(fd, saved_stage.data(),
			    saved_stage.size()) == (ssize_t)saved_stage.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(outbound.dirfd) == 0);
			assert(unlinkat(outbound.dirfd, ready_name.c_str(), 0) == 0 &&
			    fsync(outbound.dirfd) == 0 &&
			    !outbound.bind_handoff_kills_all(reserved) &&
			    errno == EBUSY);
			durable_delivery_state incomplete_source{};
			bool incomplete_revoked = false, incomplete_payload = false;
			assert(outbound.handoff_delivery_status(reserved, 0,
			    record.delivery_id, record.program_id, record.source_id,
			    incomplete_source, incomplete_revoked,
			    incomplete_payload, nullptr) == -1 && errno == EBUSY);
			fd = openat(outbound.dirfd, ready_name.c_str(),
			    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
			assert(fd >= 0 && write(fd, saved_ready.data(),
			    saved_ready.size()) == (ssize_t)saved_ready.size() &&
			    fsync(fd) == 0 && close(fd) == 0 &&
			    fsync(outbound.dirfd) == 0);
			const char *hidden_receipt = ".hidden-receipt";
			assert(renameat(outbound.dirfd, pending_name.c_str(),
			    outbound.dirfd, hidden_receipt) == 0 &&
			    !outbound.bind_handoff_kills_all(reserved) &&
			    errno == EPROTO &&
			    renameat(outbound.dirfd, hidden_receipt,
			    outbound.dirfd, pending_name.c_str()) == 0 &&
			    fsync(outbound.dirfd) == 0);
			durable_delivery_state claimed_source{};
			bool claimed_delivery_revoked = false;
			bool claimed_payload = false;
			assert(outbound.handoff_delivery_status(reserved, 0,
			    record.delivery_id, record.program_id, record.source_id,
			    claimed_source, claimed_delivery_revoked,
			    claimed_payload, nullptr) == 1 &&
			    claimed_source.record.session_id == ticket.source_session &&
			    claimed_source.record.vmid == ticket.source_vmid &&
			    claimed_source.record.epoch == ticket.source_epoch &&
			    claimed_source.phase == delivery_phase::accepted &&
			    !claimed_delivery_revoked && claimed_payload);
			bool bound_revoked = false;
			assert(outbound.bound_handoff_status(mapped_delivery,
			    bound_revoked) == 0 && !bound_revoked);
			durable_delivery_state bound_foreign{};
			assert(!outbound.bind_handoff_delivery(reserved,
			    record.delivery_id, record.program_id, record.source_id,
			    record.payload_digest.data(),
			    destination_session, 101, 200, bound_foreign) &&
			    errno == EPERM);
			auto wrong_digest = record.payload_digest;
			wrong_digest[0] ^= 1;
			assert(!outbound.bind_handoff_delivery(reserved,
			    record.delivery_id, record.program_id, record.source_id,
			    wrong_digest.data(),
			    destination_session, 100, 200, bound_foreign) &&
			    errno == EPROTO &&
			    outbound.bound_handoff_status(mapped_delivery,
			    bound_revoked) == 0 && !bound_revoked);
			bool claimed_revoked = false;
			assert(outbound.handoff_kill_status(reserved, kill.record.pid,
			    kill.record.source_id, claimed_revoked) == 'a' &&
			    claimed_revoked);
			assert(outbound.handoff_cleanup_status(reserved,
			    cleanup.record.delivery_id) == 'a' &&
			    outbound.handoff_cleanup_status(reserved,
			    cleanup.record.delivery_id + 1) == 0);
			assert(outbound.bind_handoff_kill(reserved, kill.record.pid + 1,
			    kill.record.source_id) == -1 && errno == ENOENT);
			assert(outbound.bind_handoff_kill(reserved, kill.record.pid,
			    kill.record.source_id) == 'p' &&
			    outbound.bind_handoff_kill(reserved, kill.record.pid,
			    kill.record.source_id) == 'p' &&
			    outbound.bind_handoff_kills_all(reserved) &&
			    outbound.bind_handoff_kills_all(reserved));
			std::vector<durable_kill> rebound_kills;
			assert(outbound.list_kills(rebound_kills) &&
			    rebound_kills.size() == 1 &&
			    rebound_kills[0].source_id == kill.record.source_id &&
			    rebound_kills[0].vmid == reserved.destination_vmid &&
			    rebound_kills[0].epoch == reserved.destination_epoch);
			assert(outbound.bind_handoff_delivery(reserved,
			    record.delivery_id, record.program_id, record.source_id,
			    record.payload_digest.data(),
			    destination_session, 100, 200, bound_foreign) &&
			    bound_foreign.phase == delivery_phase::accepted &&
			    bound_foreign.record.session_id == destination_session &&
			    outbound.bind_handoff_delivery(reserved,
			    record.delivery_id, record.program_id, record.source_id,
			    record.payload_digest.data(),
			    destination_session, 100, 200, bound_foreign) &&
			    outbound.handoff_delivery_status(reserved, 0,
			    record.delivery_id, record.program_id, record.source_id,
			    claimed_source, claimed_delivery_revoked,
			    claimed_payload, nullptr) == 1 &&
			    !claimed_delivery_revoked && claimed_payload &&
			    outbound.bound_handoff_status(mapped_delivery,
			    bound_revoked) == 1 && !bound_revoked &&
			    outbound.handoff_kill_status(reserved, kill.record.pid,
			    kill.record.source_id, claimed_revoked) == 'a' &&
			    claimed_revoked &&
			    outbound.handoff_cleanup_status(reserved,
			    cleanup.record.delivery_id) == 'a' &&
			    outbound.bind_handoff_kill(reserved, kill.record.pid,
			    kill.record.source_id) == 'p' &&
			    outbound.bind_handoff_kills_all(reserved));
			/* Rebind a nonempty HJB1 claim after its old KILL and
			 * CLEANUP are durable, while the old guest has not started. */
			durable_cleanup old_cleanup = cleanup.record;
			old_cleanup.vmid = reserved.destination_vmid;
			old_cleanup.epoch = reserved.destination_epoch;
			assert(outbound.record_cleanup_pending(old_cleanup) &&
			    outbound.record_cleanup_queued(old_cleanup));
			std::array<uint8_t, 16> replacement_session{};
			replacement_session[0] = 0xf2;
			assert(outbound.begin_handoff_rebind(reserved, 9, 13,
			    replacement_session, 101, 201));
			assert(outbound.stage_handoff_rebind(reserved, 9, 13,
			    replacement_session, 101, 201));
			assert(outbound.publish_handoff_rebind_pending(reserved, 9, 13,
			    replacement_session, 101, 201));
			assert(outbound.begin_handoff_rebind(reserved, 9, 13,
			    replacement_session, 101, 201));
			assert(outbound.publish_handoff_rebind_pending(reserved, 9, 13,
			    replacement_session, 101, 201));
			std::vector<durable_delivery_state> rebound;
			assert(outbound.list_deliveries(rebound) &&
			    rebound.size() == 2);
			assert(std::any_of(rebound.begin(), rebound.end(),
			    [&](const auto &entry) {
				return (entry.record.vmid == 9 &&
				    entry.record.epoch == 13 &&
				    entry.phase == delivery_phase::pending);
			}));
			assert(outbound.handoff_rebind_nonempty_preflight(
			    reserved, 9, 13, replacement_session, 101, 201));
			std::array<uint8_t, handoff_rebind_size> intent{};
			std::vector<uint8_t> plan_wire;
			assert(handoff_rebind_read_at(outbound.dirfd, reserved,
			    &intent) == 1 &&
			    handoff_rebind_plan_read_at(outbound.dirfd, reserved,
			    intent, &plan_wire) == 1);
			source_journal_cut staged_cut;
			host_ingress_transfer_bundle staged_ingress;
			source_journal_stage_binding staged_binding;
			std::array<uint8_t, SHA256_DIGEST_LENGTH> stage_digest{};
			assert(source_journal_stage_load_locked(outbound.dirfd,
			    reserved, staged_cut, staged_ingress, &staged_binding,
			    &stage_digest) == 1);
			dtraced_rebind_decision_v2 decision{};
			decision.intent = intent;
			memcpy(decision.plan_digest.data(), plan_wire.data() +
			    plan_wire.size() - SHA256_DIGEST_LENGTH,
			    SHA256_DIGEST_LENGTH);
			decision.stage_digest = stage_digest;
			decision.foreign = true;
			std::array<uint8_t, DTRACED_REBIND_DECISION_V2_SIZE>
			    candidate{};
			assert(dtraced_rebind_decision_v2_encode(candidate.data(),
			    decision) == 0);
			durable_handoff rebind_original{}, rebind_proposed{};
			source_journal_destination_plan inventory;
			bool foreign = false;
			std::array<uint8_t, SHA256_DIGEST_LENGTH> observed_stage{};
			auto snapshot = [&]() {
				return (handoff_rebind_decision_v2_snapshot_locked(
				    outbound.dirfd, reserved.token, candidate.data(),
				    rebind_original, rebind_proposed, inventory, foreign,
				    observed_stage));
			};
			assert(snapshot() && foreign &&
			    observed_stage == stage_digest &&
			    handoff_same_destination(rebind_original, reserved) &&
			    rebind_proposed.destination_vmid == 9 &&
			    rebind_proposed.destination_epoch == 13 &&
			    inventory.deliveries.size() == 1);
			auto replacement_it = std::find_if(rebound.begin(),
			    rebound.end(), [&](const auto &entry) {
				return (entry.record.vmid == 9 &&
				    entry.record.epoch == 13);
			});
			assert(replacement_it != rebound.end());
			const durable_delivery replacement_record =
			    replacement_it->record;
			assert(delivery_transition_at(outbound.dirfd,
			    replacement_record, delivery_phase::accepted, false));
			assert(snapshot());
			durable_handoff precommit_old{}, precommit_new{};
			source_journal_destination_plan precommit_plan;
			assert(!handoff_rebind_decision_v2_recover_locked(
			    outbound.dirfd, &control, reserved.token,
			    candidate.data(), precommit_old, precommit_new,
			    precommit_plan));
			char claimed_name[44], capable_name[50];
			assert(handoff_name(reserved.token,
			    handoff_phase::claimed, claimed_name) &&
			    handoff_capable_name(reserved, capable_name));
			const auto proposed_bytes = handoff_bytes(rebind_proposed);
			const auto original_bytes = handoff_bytes(reserved);
			assert(handoff_replace_at(outbound.dirfd, capable_name,
			    proposed_bytes.data(), proposed_bytes.size()) &&
			    snapshot());
			assert(handoff_replace_at(outbound.dirfd, claimed_name,
			    proposed_bytes.data(), proposed_bytes.size()) &&
			    snapshot());
			durable_handoff third = rebind_proposed;
			third.destination_epoch++;
			const auto third_bytes = handoff_bytes(third);
			assert(handoff_replace_at(outbound.dirfd, claimed_name,
			    third_bytes.data(), third_bytes.size()));
			rebind_original.token[0] = 0x42;
			rebind_proposed.token[0] = 0x43;
			assert(!snapshot() && errno == EPROTO &&
			    rebind_original.token[0] == 0x42 &&
			    rebind_proposed.token[0] == 0x43);
			assert(handoff_replace_at(outbound.dirfd, claimed_name,
			    original_bytes.data(), original_bytes.size()) &&
			    handoff_replace_at(outbound.dirfd, capable_name,
			    original_bytes.data(), original_bytes.size()));
			char rebind_pending_name[80], accepted_name[80];
			delivery_record_name(replacement_record,
			    delivery_phase::pending, rebind_pending_name);
			delivery_record_name(replacement_record,
			    delivery_phase::accepted, accepted_name);
			assert(renameat(outbound.dirfd, accepted_name,
			    outbound.dirfd, rebind_pending_name) == 0 &&
			    fsync(outbound.dirfd) == 0);
			{
				dir recovered(outbound_path, nullptr);
				recovered.state = &control;
				control.outbounddir = &recovered;
				if (!recovered.populate_existing()) {
					perror("staged rebind startup audit");
					assert(false);
				}
				control.outbounddir = &outbound;
			}
			assert(outbound.cancel_handoff_rebind_pending(reserved));
			assert(outbound.cancel_handoff_rebind_pending(reserved));
			assert(outbound.list_deliveries(rebound) &&
			    rebound.size() == 1);
		}
		remove_directory(outbound_path);
		remove_directory(inbound_path);
	}
	reserved.transfer_digest[0] ^= 1;
	assert(!dir::decode_source_journal_transfer_wire(reserved, transfer,
	    destination_journal, destination_ingress) && errno == EPROTO &&
	    destination_journal.deliveries.empty());
	reserved.transfer_digest[0] ^= 1;
	reserved.source_session[0] ^= 1;
	assert(!dir::decode_source_journal_transfer_wire(reserved, transfer,
	    destination_journal, destination_ingress) && errno == EPROTO &&
	    destination_journal.deliveries.empty());
	reserved.source_session[0] ^= 1;
	assert(dtraced_transfer_wire_requires_import(transfer.data(),
	    transfer.size(), ticket.token.data(), &requires_import) &&
	    requires_import == 1);
	std::vector<uint8_t> empty_transfer;
	assert(dtraced_transfer_wire_build(ticket.token.data(), {}, {},
	    empty_transfer) &&
	    dtraced_transfer_wire_requires_import(empty_transfer.data(),
	    empty_transfer.size(), ticket.token.data(), &requires_import) &&
	    requires_import == 0);
	memcpy(reserved.transfer_digest.data(), empty_transfer.data() +
	    empty_transfer.size() - SHA256_DIGEST_LENGTH,
	    SHA256_DIGEST_LENGTH);
	assert(!dir::decode_source_journal_transfer_wire(reserved,
	    empty_transfer, destination_journal, destination_ingress) &&
	    errno == EPROTO);
	std::vector<uint8_t> unpacked_manifest, journal;
	std::vector<std::vector<uint8_t>> unpacked_frames,
	    ingress_frames;
	std::vector<uint8_t> ingress_manifest;
	assert(dtraced_transfer_wire_unpack(transfer.data(),
	    transfer.size(), ticket.token.data(), unpacked_manifest,
	    unpacked_frames) &&
	    dtraced_transfer_journal_split(ticket.token.data(),
	    unpacked_manifest, unpacked_frames, ingress_manifest,
	    ingress_frames, journal) && ingress_manifest.empty() &&
	    ingress_frames.empty() && journal == wire);
	std::vector<uint8_t> nested{'H', 'T', 'M', '1'};
	std::vector<std::vector<uint8_t>> nested_frames{{'H', 'T', 'P', '1'}};
	assert(dtraced_transfer_journal_wrap(ticket.token.data(), nested,
	    nested_frames, wire, manifest, frames) &&
	    dtraced_transfer_wire_build(ticket.token.data(), manifest,
	    frames, transfer) &&
	    dtraced_transfer_wire_inspect(transfer.data(),
	    transfer.size(), ticket.token.data(), &has_ingress,
	    &has_journal) && has_ingress == 1 && has_journal == 1 &&
	    dtraced_transfer_wire_requires_import(transfer.data(),
	    transfer.size(), ticket.token.data(), &requires_import) &&
	    requires_import == 1 &&
	    dtraced_transfer_journal_split(ticket.token.data(), manifest,
	    frames, ingress_manifest, ingress_frames, journal) &&
	    ingress_manifest == nested && ingress_frames == nested_frames &&
	    journal == wire);
	memcpy(reserved.transfer_digest.data(), transfer.data() +
	    transfer.size() - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
	assert(!dir::decode_source_journal_transfer_wire(reserved, transfer,
	    destination_journal, destination_ingress) && errno == EPROTO &&
	    destination_journal.deliveries.empty() &&
	    destination_ingress.entries.empty());
	auto wrong_manifest = manifest;
	wrong_manifest[32] ^= 1; /* the outer HTX1 may still checksum */
	assert(dtraced_transfer_wire_build(ticket.token.data(),
	    wrong_manifest, frames, transfer) &&
	    !dtraced_transfer_wire_inspect(transfer.data(),
	    transfer.size(), ticket.token.data(), &has_ingress,
	    &has_journal) && errno == EPROTO &&
	    !dtraced_transfer_journal_split(ticket.token.data(),
	    wrong_manifest, frames, ingress_manifest, ingress_frames,
	    journal) && errno == EPROTO && ingress_manifest.empty() &&
	    ingress_frames.empty() && journal.empty());
	for (size_t byte : {8U, 4U, 42U}) {
		auto wrong_archive = wire;
		wrong_archive[byte] ^= 1; /* ticket, version, or reserved */
		reseal(wrong_archive);
		assert(!dtraced_transfer_journal_wrap(ticket.token.data(),
		    nested, nested_frames, wrong_archive, wrong_manifest,
		    unpacked_frames) && errno == EPROTO);
		auto wrong_frames = frames;
		wrong_frames.back() = wrong_archive;
		wrong_manifest = manifest;
		memcpy(wrong_manifest.data() + 32,
		    wrong_archive.data() + wrong_archive.size() -
		    SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
		assert(dtraced_transfer_wire_build(ticket.token.data(),
		    wrong_manifest, wrong_frames, transfer) &&
		    !dtraced_transfer_wire_inspect(transfer.data(),
		    transfer.size(), ticket.token.data(), &has_ingress,
		    &has_journal) && errno == EPROTO &&
		    !dtraced_transfer_journal_split(ticket.token.data(),
		    wrong_manifest, wrong_frames, ingress_manifest,
		    ingress_frames, journal) && errno == EPROTO);
	}
	source_journal_cut decoded{};
	assert(dir::decode_source_journal_archive(ticket, wire.data(),
	    wire.size(), decoded));
	assert(decoded.deliveries.size() == 1 &&
	    decoded.deliveries[0].state.record.delivery_id == 77 &&
	    decoded.deliveries[0].state.phase == delivery_phase::accepted &&
	    decoded.deliveries[0].payload == delivery.payload &&
	    decoded.kills.size() == 1 && decoded.kills[0].applied &&
	    decoded.cleanups.size() == 1 &&
	    decoded.cleanups[0].phase == 'a');
	std::vector<uint8_t> repeated;
	assert(dir::encode_source_journal_archive(ticket, decoded,
	    repeated) && repeated == wire);
	auto changed = wire;
	changed[64 + 12 + 143 + 5] ^= 1;
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO &&
	    decoded.deliveries.empty());
	reseal(changed);
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO &&
	    decoded.deliveries.empty());
	changed = wire;
	changed[64 + 12] ^= 1; /* damaged HTD4 record */
	reseal(changed);
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO);
	changed = wire;
	changed[64 + 12 + 143 + sizeof(elf) - 1 + 2] = 1;
	reseal(changed); /* KILL reserved byte is not extensible */
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO);
	changed = wire;
	changed[42] = 1; /* header reserved byte */
	reseal(changed);
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO);
	changed = wire;
	memset(changed.data() + 64 + 8, 0xff, 4); /* oversized ELF */
	reseal(changed);
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO);
	changed = wire;
	changed[56] = changed[57] = 0xff; /* excessive entry count */
	reseal(changed);
	assert(!dir::decode_source_journal_archive(ticket, changed.data(),
	    changed.size(), decoded) && errno == EPROTO);
	durable_handoff wrong = ticket;
	wrong.token[0]++;
	assert(!dir::decode_source_journal_archive(wrong, wire.data(),
	    wire.size(), decoded) && errno == EPROTO);
	assert(!dir::decode_source_journal_archive(ticket, wire.data(),
	    wire.size() - 1, decoded) && errno == EPROTO);
	cut.deliveries.push_back(delivery);
	assert(!dir::encode_source_journal_archive(ticket, cut, repeated) &&
	    errno == EPROTO && repeated.empty());
	cut.deliveries.pop_back();
	cut.deliveries[0].revoked = true;
	cut.deliveries[0].payload.clear();
	assert(dir::encode_source_journal_archive(ticket, cut, repeated) &&
	    dir::decode_source_journal_archive(ticket, repeated.data(),
	    repeated.size(), decoded) &&
	    decoded.deliveries[0].revoked &&
	    decoded.deliveries[0].payload.empty());
	puts("PASS: canonical HJX1 source journal round trip and corruption fence");
}
