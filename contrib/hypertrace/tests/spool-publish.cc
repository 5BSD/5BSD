/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/stat.h>
#include <sys/hypertrace.h>
#include <openssl/sha.h>
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include "dtraced_clientrequest.h"
#include "dtraced_directory.h"
#include "dtraced_protocol.h"
#include "dtraced_state.h"
using namespace dtraced;
static int mode, calls, directory_syncs;
static std::mutex *published_ident_lock;
extern "C" ssize_t __real_write(int, const void *, size_t);
extern "C" ssize_t __real_read(int, void *, size_t);
extern "C" int __real_fsync(int);
extern "C" int __real_renameat(int, const char *, int, const char *);
extern "C" ssize_t __wrap_write(int fd, const void *p, size_t n) {
    if (mode == 1) {
        if (calls++ == 0) { errno = EINTR; return -1; }
        if (n > 3) n = 3;
    }
    if (mode == 2) return 0;
    if (mode == 3) { errno = ENOSPC; return -1; }
    return __real_write(fd, p, n);
}
extern "C" ssize_t __wrap_read(int fd, void *p, size_t n) {
    if (mode == 6) return 0;
    if (mode == 7) {
        if (calls++ == 0) { errno = EINTR; return -1; }
        if (n > 5) n = 5;
    }
    return __real_read(fd, p, n);
}
extern "C" int __wrap_fsync(int fd) {
    if (mode == 4) { errno = EIO; return -1; }
    struct stat sb; assert(fstat(fd, &sb) == 0);
    if (S_ISDIR(sb.st_mode)) {
        directory_syncs++;
        if (mode == 8) { errno = EIO; return -1; }
	if (mode == 9) {
	    assert(published_ident_lock);
	    bool acquired = false;
	    std::thread observer([&] {
	        acquired = published_ident_lock->try_lock();
	        if (acquired) published_ident_lock->unlock();
	    });
	    observer.join();
	    assert(!acquired); /* Watcher cannot launch before identifier commit. */
	}
    }
    return __real_fsync(fd);
}
extern "C" int __wrap_renameat(int from, const char *a, int to, const char *b) {
    if (mode == 5) { errno = EACCES; return -1; }
    return __real_renameat(from, a, to, b);
}
static std::vector<std::string> files(int fd) {
    int scan = openat(fd, ".", O_RDONLY | O_DIRECTORY); assert(scan >= 0);
    DIR *d = fdopendir(scan); assert(d);
    std::vector<std::string> result;
    while (dirent *e = readdir(d))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..") &&
            strcmp(e->d_name, ".handoff.lock")) result.emplace_back(e->d_name);
    closedir(d); return result;
}
int main() {
    alarm(15);
    {
	const char *vm_name = "guest-a";
	hypertrace_vm_envelope envelope{};
	envelope.magic = HYPERTRACE_ENVELOPE_MAGIC;
	envelope.version = HYPERTRACE_ENVELOPE_VERSION;
	envelope.vmid = 7;
	envelope.epoch = 42;
	envelope.name_length = strlen(vm_name);
	std::array<unsigned char, HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7 + 5> frame{};
    hypertrace_envelope_encode(frame.data(), &envelope);
	memcpy(frame.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE, vm_name, 7);
	memcpy(frame.data() + HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7,
	    "\177ELFx", 5);
	size_t elf_offset = 0;
	assert(parse_guest_elf_envelope(frame.data(), frame.size(), 7, 42,
	    vm_name, elf_offset) && elf_offset ==
	    HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7);
	assert(!parse_guest_elf_envelope(frame.data(), frame.size(), 8, 42,
	    vm_name, elf_offset) && errno == EPROTO);
	assert(!parse_guest_elf_envelope(frame.data(), frame.size(), 7, 43,
	    vm_name, elf_offset) && errno == EPROTO);
	assert(!parse_guest_elf_envelope(frame.data(), frame.size(), 7, 42,
	    "guest-b", elf_offset) && errno == EPROTO);
	frame[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7] ^= 1;
	assert(!parse_guest_elf_envelope(frame.data(), frame.size(), 7, 42,
	    vm_name, elf_offset) && errno == EPROTO);
	frame[HYPERTRACE_VM_ENVELOPE_WIRE_SIZE + 7] ^= 1;
	envelope.name_length = 1000;
	hypertrace_envelope_encode(frame.data(), &envelope);
	assert(!parse_guest_elf_envelope(frame.data(), frame.size(), 7, 42,
	    vm_name, elf_offset) && errno == EPROTO);
    }
    char root[] = "/tmp/hypertrace-publish.XXXXXX"; assert(mkdtemp(root));
    std::string srcpath = std::string(root) + "/src", dstpath = std::string(root) + "/dst";
    std::string moved = std::string(root) + "/moved";
    const char payload[] = "\177ELFabcdefghijklmnopqrstuvwxy";
    {
        dir src(srcpath.c_str(), nullptr), dst(dstpath.c_str(), nullptr);
        assert(fcntl(src.dirfd, F_GETFD) & FD_CLOEXEC);
        assert(dst.full_path().back() == '/');
        int fd = openat(src.dirfd, "program", O_CREAT | O_WRONLY, 0600); assert(fd >= 0);
        assert(write(fd, payload, sizeof(payload)) == sizeof(payload)); close(fd);
        assert(symlinkat("program", src.dirfd, "link") == 0);
        assert(mkfifoat(src.dirfd, "fifo", 0600) == 0);
        assert(!dst.copy_data(src.dirfd, "link") && !dst.copy_data(src.dirfd, "fifo"));
        assert(!dst.copy_data(src.dirfd, "../src/program"));
        assert(!dst.write_data(nullptr, 1));
        assert(!dst.write_data((unsigned char *)payload, SIZE_MAX));
        const char *stale = ".elf.0123456789abcdef0123456789abcdef";
        const char *complete = "elf.0123456789abcdef0123456789abcdef";
        int stale_fd = openat(dst.dirfd, stale, O_CREAT | O_WRONLY, 0600);
        assert(stale_fd >= 0); close(stale_fd);
        int complete_fd = openat(dst.dirfd, complete, O_CREAT | O_WRONLY, 0600);
        assert(complete_fd >= 0); close(complete_fd);
        assert(dst.populate_existing());
        assert(faccessat(dst.dirfd, stale, F_OK, 0) == -1 && errno == ENOENT);
        assert(faccessat(dst.dirfd, complete, F_OK, 0) == 0);
        assert(unlinkat(dst.dirfd, complete, 0) == 0);
        for (int failure : {2, 3, 4, 5, 6, 8}) {
            mode = failure; calls = 0;
            bool ok = failure == 6 ? dst.copy_data(src.dirfd, "program") :
                dst.write_data((unsigned char *)payload, sizeof(payload));
            mode = 0; assert(!ok); assert(files(dst.dirfd).empty());
        }
        /* Renaming the directory does not redirect its held descriptor. */
        assert(rename(dstpath.c_str(), moved.c_str()) == 0);
        for (int partial : {1, 7}) {
            mode = partial; calls = 0;
            int before_sync = directory_syncs;
            bool ok = partial == 7 ? dst.copy_data(src.dirfd, "program") :
                dst.write_data((unsigned char *)payload, sizeof(payload));
            mode = 0; assert(ok);
            assert(directory_syncs > before_sync);
            auto names = files(dst.dirfd); assert(names.size() == 1 && names[0][0] != '.');
            fd = openat(dst.dirfd, names[0].c_str(), O_RDONLY); assert(fd >= 0);
            char result[sizeof(payload) + 1];
            assert(read(fd, result, sizeof(result)) == sizeof(payload));
            assert(memcmp(result, payload, sizeof(payload)) == 0); close(fd);
            assert(unlinkat(dst.dirfd, names[0].c_str(), 0) == 0);
        }
	uint8_t identity[16] = { 0x42 };
	const char *stable = "elf.42000000000000000000000000000000";
	bool newly_created = false;
	{
	    /* Publication must not wait for a watcher holding dirmtx. */
	    std::lock_guard watcher(dst.dirmtx);
	    assert(dst.write_identified_data((const unsigned char *)payload,
	        sizeof(payload), identity, &newly_created) && newly_created);
	}
	assert(faccessat(dst.dirfd, stable, F_OK, 0) == 0);
	int before_retry_sync = directory_syncs;
	newly_created = true;
	assert(dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), identity, &newly_created) && !newly_created);
	assert(directory_syncs > before_retry_sync);
	assert(files(dst.dirfd).size() == 1);
	uint8_t competing_lineage[16] = { 0x55 };
	assert(!dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), identity, nullptr, competing_lineage) &&
	    errno == EEXIST);
	assert(files(dst.dirfd).size() == 1);
	char changed[sizeof(payload)]; memcpy(changed, payload, sizeof(changed));
	changed[4] ^= 1;
	assert(!dst.write_identified_data((const unsigned char *)changed,
	    sizeof(changed), identity) && errno == EEXIST);
	fd = openat(dst.dirfd, stable, O_RDONLY); assert(fd >= 0);
	char original[sizeof(payload)];
	assert(read(fd, original, sizeof(original)) == sizeof(original));
	assert(memcmp(original, payload, sizeof(payload)) == 0);
	close(fd); assert(unlinkat(dst.dirfd, stable, 0) == 0);
	mode = 8;
	assert(!dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), identity));
	mode = 0;
	assert(files(dst.dirfd).empty());
	uint8_t lineage[16] = { 0x55 };
	assert(dst.write_data_with_source((const unsigned char *)payload,
	    sizeof(payload), lineage));
	auto lineage_files = files(dst.dirfd);
	assert(lineage_files.size() == 1 && lineage_files[0].size() == 69 &&
	    lineage_files[0].substr(36) ==
	    ".55000000000000000000000000000000");
	assert(unlinkat(dst.dirfd, lineage_files[0].c_str(), 0) == 0);
	assert(dst.source_revoked(lineage) == 0);
	assert(dst.revoke_source(lineage));
	assert(dst.source_revoked(lineage) == 1);
	{
	    dir recovered(moved.c_str(), nullptr);
	    assert(recovered.source_revoked(lineage) == 1);
	}
	newly_created = true;
	assert(dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), identity, &newly_created, lineage) && !newly_created);
	assert(!dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), identity, &newly_created, lineage, true) &&
	    errno == ECANCELED);
	assert(files(dst.dirfd).size() == 1); /* Tombstone, no replayed ELF. */
	assert(unlinkat(dst.dirfd,
	    ".revoke.55000000000000000000000000000000", 0) == 0);
	durable_kill scoped_kill{};
	scoped_kill.pid = 123;
	scoped_kill.vmid = 7;
	scoped_kill.epoch = 9;
	memcpy(scoped_kill.source_id.data(), lineage, sizeof(lineage));
	assert(dst.record_kill(scoped_kill));
	assert(dst.source_revoked_for_vm(lineage, 7, 9) == 1);
	assert(dst.source_revoked_for_vm(lineage, 8, 9) == 0);
	assert(dst.source_revoked_for_vm(lineage, 7, 10) == 0);
	assert(dst.source_revoked_for_vm(lineage, 0, 9) == -1 && errno == EINVAL);
	assert(dst.source_revoked_for_vm(lineage, HYPERTRACE_MAX_VMS, 9) == -1 &&
	    errno == EINVAL);
	assert(unlinkat(dst.dirfd,
	    ".kill.0007.0000000000000009.0000007b.55000000000000000000000000000000",
	    0) == 0);
	int malformed = openat(dst.dirfd, ".kill.invalid",
	    O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(malformed >= 0); close(malformed);
	assert(dst.source_revoked(lineage) == -1 && errno == EPROTO);
	assert(unlinkat(dst.dirfd, ".kill.invalid", 0) == 0);
	durable_delivery delivery{};
	delivery.session_id[0] = 0xa5;
	delivery.delivery_id = 17;
	delivery.vmid = 7;
	delivery.epoch = 9;
	delivery.program_id[0] = 0x42;
	delivery.source_id[0] = 0x55;
	delivery.peer_uid = geteuid();
	delivery.peer_pid = getpid();
	mode = 4;
	assert(!dst.record_delivery(delivery, delivery_phase::pending));
	mode = 0;
	assert(files(dst.dirfd).empty());
	mode = 8;
	assert(!dst.record_delivery(delivery, delivery_phase::pending));
	mode = 0;
	assert(dst.record_delivery(delivery, delivery_phase::pending));
	assert(dst.delivery_status(delivery) == (int)delivery_phase::pending);
	mode = 5;
	assert(!dst.record_delivery(delivery, delivery_phase::accepted));
	mode = 0;
	assert(dst.delivery_status(delivery) == (int)delivery_phase::pending);
	assert(dst.record_delivery(delivery, delivery_phase::accepted));
	mode = 8;
	assert(!dst.record_delivery(delivery, delivery_phase::installed));
	mode = 0;
	assert(dst.record_delivery(delivery, delivery_phase::installed));
	assert(dst.record_delivery(delivery, delivery_phase::terminal));
	assert(dst.delivery_status(delivery) == (int)delivery_phase::terminal);
	auto delivery_files = files(dst.dirfd);
	assert(delivery_files.size() == 1);
	assert(unlinkat(dst.dirfd, delivery_files[0].c_str(), 0) == 0);
	durable_delivery guest_outbound = delivery;
	guest_outbound.scope = 2;
	guest_outbound.delivery_id = 18;
	guest_outbound.vmid = 0;
	guest_outbound.epoch = 0;
	guest_outbound.journal_version = 4;
	assert(SHA256((const unsigned char *)payload, sizeof(payload),
	    guest_outbound.payload_digest.data()) != NULL);
	assert(dst.record_delivery(guest_outbound, delivery_phase::pending, true));
	assert(dst.record_delivery(guest_outbound, delivery_phase::accepted));
	assert(!dst.record_delivery(guest_outbound, delivery_phase::installed) &&
	    errno == EINVAL);
	auto guest_files = files(dst.dirfd);
	assert(guest_files.size() == 1);
	int corrupt = openat(dst.dirfd, guest_files[0].c_str(), O_RDWR);
	assert(corrupt >= 0);
	uint8_t digest_byte;
	assert(pread(corrupt, &digest_byte, 1, 79) == 1);
	uint8_t changed_byte = digest_byte ^ 1;
	assert(pwrite(corrupt, &changed_byte, 1, 79) == 1 &&
	    fsync(corrupt) == 0);
	{
	    dir recovered(moved.c_str(), nullptr);
	    std::vector<durable_delivery_state> entries;
	    assert(!recovered.list_deliveries(entries) && errno == EPROTO);
	}
	assert(pwrite(corrupt, &digest_byte, 1, 79) == 1 &&
	    fsync(corrupt) == 0);
	std::array<uint8_t, 111> legacy_guest{};
	assert(pread(corrupt, legacy_guest.data(), 79, 0) == 79);
	memcpy(legacy_guest.data(), "HTD3", 4);
	assert(SHA256(legacy_guest.data(), 79,
	    legacy_guest.data() + 79) != NULL);
	assert(close(corrupt) == 0);
	{
	    dir recovered(moved.c_str(), nullptr);
	    std::vector<durable_delivery_state> entries;
	    assert(recovered.list_deliveries(entries) && entries.size() == 1);
	    assert(entries[0].record.scope == 2 &&
	        entries[0].record.vmid == 0 &&
	        entries[0].record.epoch == 0 &&
	        entries[0].record.journal_version == 4 &&
	        entries[0].record.payload_digest ==
	        guest_outbound.payload_digest &&
	        entries[0].phase == delivery_phase::accepted);
	}
	assert(dst.retire_accepted_outbound(guest_outbound));
	assert(dst.delivery_status(guest_outbound) == 0);
	delivery_files = files(dst.dirfd);
	assert(delivery_files.empty());
	int legacy_fd = openat(dst.dirfd, guest_files[0].c_str(),
	    O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(legacy_fd >= 0 && write(legacy_fd, legacy_guest.data(),
	    legacy_guest.size()) == (ssize_t)legacy_guest.size());
	assert(fsync(legacy_fd) == 0 && close(legacy_fd) == 0 &&
	    fsync(dst.dirfd) == 0);
	{
	    dir recovered(moved.c_str(), nullptr);
	    std::vector<durable_delivery_state> entries;
	    assert(recovered.list_deliveries(entries) && entries.size() == 1);
	    assert(entries[0].record.scope == 2 &&
	        entries[0].record.journal_version == 3 &&
	        entries[0].phase == delivery_phase::accepted);
	    assert(recovered.retire_accepted_outbound(entries[0].record));
	}
	assert(files(dst.dirfd).empty());
	assert(dst.verify_pending_outbound(guest_outbound) == 0 &&
	    errno == ENOENT);
	assert(dst.write_identified_data((const unsigned char *)payload,
	    sizeof(payload), guest_outbound.program_id.data(), nullptr,
	    guest_outbound.source_id.data()));
	assert(dst.verify_pending_outbound(guest_outbound) == 1);
	const char *pending_spool =
	    "elf.42000000000000000000000000000000.55000000000000000000000000000000";
	int pending_fd = openat(dst.dirfd, pending_spool, O_RDWR);
	assert(pending_fd >= 0);
	char changed_payload = 'Z';
	assert(pwrite(pending_fd, &changed_payload, 1, 4) == 1);
	assert(dst.verify_pending_outbound(guest_outbound) == -1 &&
	    errno == EPROTO);
	assert(pwrite(pending_fd, payload + 4, 1, 4) == 1);
	assert(close(pending_fd) == 0);
	assert(dst.verify_pending_outbound(guest_outbound) == 1);
	assert(unlinkat(dst.dirfd, pending_spool, 0) == 0);
	state receiver{};
	receiver.inbounddir = &dst;
	dtraced_hdr_t inbound{};
	inbound.msg_type = DTRACED_MSG_ELF;
	inbound.elf.len = sizeof(payload);
	inbound.elf.ident_present = 1;
	memset(inbound.elf.ident, 0x23, sizeof(inbound.elf.ident));
	memcpy(inbound.elf.program_id, identity, sizeof(identity));
	memcpy(inbound.elf.source_id, lineage, sizeof(lineage));
	const char *stable_lineage =
	    "elf.42000000000000000000000000000000.55000000000000000000000000000000";
	strlcpy(inbound.elf.location, "inbound", sizeof(inbound.elf.location));
	client_request first(receiver, inbound, (unsigned char *)payload,
	    sizeof(payload));
	mode = 8;
	assert(!first.handle() && receiver.identlist.empty());
	mode = 0;
	assert(files(dst.dirfd).empty());
	published_ident_lock = &receiver.identlistmtx;
	mode = 9;
	assert(first.handle());
	mode = 0;
	published_ident_lock = nullptr;
	assert(first.handle());
	assert(receiver.identlist.size() == 1);
	assert(files(dst.dirfd).size() == 1);
	{
	    dir recovered(moved.c_str(), nullptr);
	    assert(recovered.populate_existing());
	    assert(recovered.memorized(stable_lineage));
	}
	client_request conflict(receiver, inbound, (unsigned char *)changed,
	    sizeof(changed));
	assert(!conflict.handle());
	assert(receiver.identlist.size() == 1);
	assert(faccessat(dst.dirfd, stable_lineage, F_OK, 0) == 0);
	assert(dst.revoke_source(lineage));
	dst.state = &receiver;
	struct dirent pending{};
	strlcpy(pending.d_name, stable_lineage, sizeof(pending.d_name));
	assert(process_inbound(dst, &pending));
	assert(dst.memorized(stable_lineage) && receiver.pidlist.empty());
	assert(unlinkat(dst.dirfd,
	    ".revoke.55000000000000000000000000000000", 0) == 0);
	assert(unlinkat(dst.dirfd, stable_lineage, 0) == 0);
	assert(unlinkat(dst.dirfd, ".handoff.lock", 0) == 0);
        for (const char *name : {"program", "link", "fifo"}) assert(unlinkat(src.dirfd, name, 0) == 0);
    }
    assert(rmdir(srcpath.c_str()) == 0); assert(rmdir(moved.c_str()) == 0); assert(rmdir(root) == 0);
    puts("PASS: durable directory sync after atomic spool publication, short/EINTR I/O and failure cleanup");
}
