/* SPDX-License-Identifier: BSD-2-Clause */
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dtraced_directory.h"

using namespace dtraced;

static int status_dirfd = -1;
static bool fail_status_fsync;
static bool fail_phase_file_fsync;
static int fail_handoff_file_fsync_countdown;

static EVP_PKEY *
new_ed25519_key(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	EVP_PKEY *key = nullptr;
	assert(ctx != nullptr && EVP_PKEY_keygen_init(ctx) == 1);
	assert(EVP_PKEY_keygen(ctx, &key) == 1);
	EVP_PKEY_CTX_free(ctx);
	return (key);
}

extern "C" int __real_fsync(int);
extern "C" int
__wrap_fsync(int fd)
{
	struct stat sb;
	if (fail_handoff_file_fsync_countdown != 0 &&
	    fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode) &&
	    sb.st_size == 152 && --fail_handoff_file_fsync_countdown == 0) {
		errno = EIO;
		return (-1);
	}
	if (fail_phase_file_fsync && fstat(fd, &sb) == 0 &&
	    S_ISREG(sb.st_mode) && (sb.st_size == 120 || sb.st_size == 152)) {
		fail_phase_file_fsync = false;
		errno = EIO;
		return (-1);
	}
	if (fd == status_dirfd && fail_status_fsync) {
		fail_status_fsync = false;
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

int
main()
{
	char path[] = "/tmp/hypertrace-handoff-ledger.XXXXXX";
	char ingresspath[] = "/tmp/hypertrace-handoff-ingress.XXXXXX";
	assert(mkdtemp(path) != nullptr);
	assert(mkdtemp(ingresspath) != nullptr);
	durable_handoff ticket{};
	ticket.token[0] = 0xa1;
	ticket.source_session[0] = 0xb2;
	ticket.source_vmid = 42;
	ticket.source_epoch = 99;
	ticket.transfer_digest[0] = 0xd4;
	{
		dir journal(path, nullptr);
		const char *orphan =
		    ".handoff-tmp.00000000000000000000000000000001";
		int orphan_fd = openat(journal.dirfd, orphan,
		    O_WRONLY | O_CREAT | O_EXCL, 0600);
		assert(orphan_fd >= 0 && write(orphan_fd, "x", 1) == 1 &&
		    fsync(orphan_fd) == 0 && close(orphan_fd) == 0 &&
		    fsync(journal.dirfd) == 0);
		/* Startup must wait for a publishing daemon before deciding that
		 * a temporary handoff inode is abandoned. */
		int startup_lockfd = openat(journal.dirfd, ".handoff.lock",
		    O_RDWR | O_CREAT | O_CLOEXEC, 0600);
		assert(startup_lockfd >= 0 && flock(startup_lockfd, LOCK_EX) == 0);
		int startup_ready[2], finished[2];
		assert(pipe(startup_ready) == 0 && pipe(finished) == 0);
		pid_t cleaner = fork();
		assert(cleaner >= 0);
		if (cleaner == 0) {
			close(startup_lockfd);
			close(startup_ready[0]);
			close(finished[0]);
			char marker = 'r';
			if (write(startup_ready[1], &marker, 1) != 1)
				_exit(2);
			close(startup_ready[1]);
			int code = journal.populate_existing() ? 0 : 1;
			(void)write(finished[1], &marker, 1);
			_exit(code);
		}
		close(startup_ready[1]);
		close(finished[1]);
		char marker;
		assert(read(startup_ready[0], &marker, 1) == 1);
		close(startup_ready[0]);
		struct pollfd wait_cleaner = {finished[0], POLLIN, 0};
		assert(poll(&wait_cleaner, 1, 100) == 0);
		assert(faccessat(journal.dirfd, orphan, F_OK, 0) == 0);
		assert(close(startup_lockfd) == 0);
		int cleaner_status;
		assert(waitpid(cleaner, &cleaner_status, 0) == cleaner &&
		    WIFEXITED(cleaner_status) && WEXITSTATUS(cleaner_status) == 0);
		close(finished[0]);
		assert(journal.populate_existing());
		assert(faccessat(journal.dirfd, orphan, F_OK, 0) == -1 &&
		    errno == ENOENT);
		durable_handoff observed{};
		durable_delivery delivery{};
		delivery.session_id = ticket.source_session;
		delivery.delivery_id = 77;
		delivery.vmid = ticket.source_vmid;
		delivery.epoch = ticket.source_epoch;
		delivery.program_id[0] = 1;
		delivery.source_id[0] = 2;
		delivery.peer_uid = 0;
		delivery.peer_pid = 123;
		assert(journal.record_delivery(delivery,
		    delivery_phase::pending, true));
		assert(journal.record_delivery(delivery,
		    delivery_phase::accepted));
		assert(journal.handoff_status(ticket.token, observed) == 0);
		const char *prepared_name =
		    ".handoff.a1000000000000000000000000000000.p";
		assert(mkfifoat(journal.dirfd, prepared_name, 0600) == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		assert(unlinkat(journal.dirfd, prepared_name, 0) == 0);
		assert(unlinkat(journal.dirfd, ".handoff.lock", 0) == 0);
		assert(symlinkat("missing", journal.dirfd,
		    ".handoff.lock") == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    (errno == ELOOP || errno == EMLINK));
		assert(unlinkat(journal.dirfd, ".handoff.lock", 0) == 0);
		durable_handoff aborted = ticket;
		aborted.token[0] = 0xa2;
		fail_phase_file_fsync = true;
		assert(!journal.prepare_handoff(aborted, false) && errno == EIO);
		assert(!fail_phase_file_fsync &&
		    journal.handoff_status(aborted.token, observed) == 0);
		assert(journal.prepare_handoff(aborted, false));
		assert(journal.record_delivery(delivery,
		    delivery_phase::accepted));
		assert(!journal.record_delivery(delivery,
		    delivery_phase::installed) && errno == EBUSY);
		assert(!journal.record_delivery(delivery,
		    delivery_phase::terminal) && errno == EBUSY);
		assert(journal.abort_handoff(aborted));
		assert(journal.abort_handoff(aborted));
		assert(journal.handoff_status(aborted.token, observed) == 0);
		/* An existing HTH1 phase file has no transfer digest and must
		 * remain usable after the daemon learns HTH2. */
		durable_handoff legacy = ticket;
		legacy.token[0] = 0xa6;
		legacy.transfer_digest = {};
		assert(journal.prepare_handoff(legacy, false));
		const char *legacy_name =
		    ".handoff.a6000000000000000000000000000000.p";
		int legacy_fd = openat(journal.dirfd, legacy_name, O_RDWR);
		assert(legacy_fd >= 0);
		uint8_t legacy_bytes[120];
		assert(pread(legacy_fd, legacy_bytes, 88, 0) == 88);
		memcpy(legacy_bytes, "HTH1", 4);
		assert(SHA256(legacy_bytes, 88, legacy_bytes + 88) != nullptr);
		assert(pwrite(legacy_fd, legacy_bytes, sizeof(legacy_bytes), 0) ==
		    (ssize_t)sizeof(legacy_bytes));
		assert(ftruncate(legacy_fd, sizeof(legacy_bytes)) == 0);
		assert(fsync(legacy_fd) == 0 && close(legacy_fd) == 0);
		assert(fsync(journal.dirfd) == 0);
		assert(journal.handoff_status(legacy.token, observed) ==
		    (int)handoff_phase::prepared &&
		    observed.transfer_digest == legacy.transfer_digest);
		assert(journal.abort_handoff(legacy));
		/* Two daemon processes cannot prepare distinct tickets for the same
		 * VMM incarnation, even when their forwarding sessions differ. */
		durable_handoff race = ticket;
		race.source_vmid = 51;
		race.source_epoch = 61;
		int start[2];
		assert(pipe(start) == 0);
		pid_t contenders[2];
		for (unsigned i = 0; i < 2; i++) {
			contenders[i] = fork();
			assert(contenders[i] >= 0);
			if (contenders[i] == 0) {
				close(start[1]);
				char go;
				if (read(start[0], &go, 1) != 1)
					_exit(2);
				dir contender(path, nullptr);
				durable_handoff candidate = race;
				candidate.token[0] = (uint8_t)(0xb1 + i);
				candidate.source_session[0] = (uint8_t)(0xc1 + i);
				if (contender.prepare_handoff(candidate, false))
					_exit(0);
				_exit(errno == EBUSY ? 1 : 2);
			}
		}
		close(start[0]);
		assert(write(start[1], "GG", 2) == 2);
		close(start[1]);
		int results[2];
		for (unsigned i = 0; i < 2; i++) {
			assert(waitpid(contenders[i], &results[i], 0) ==
			    contenders[i]);
			assert(WIFEXITED(results[i]));
		}
		assert((WEXITSTATUS(results[0]) == 0 &&
		    WEXITSTATUS(results[1]) == 1) ||
		    (WEXITSTATUS(results[0]) == 1 &&
		    WEXITSTATUS(results[1]) == 0));
		assert(journal.source_handoff_for_vm(51, 61, observed) ==
		    (int)handoff_phase::prepared);
		assert(journal.abort_handoff(observed));
		assert(journal.source_handoff_for_vm(51, 61, observed) == 0);
		assert(journal.source_handoff_for_vm(ticket.source_vmid,
		    ticket.source_epoch, observed) == 0);
		assert(!journal.commit_handoff(ticket) && errno == EINVAL);
		assert(journal.prepare_handoff(ticket, false));
		assert(journal.prepare_handoff(ticket, false));
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::prepared);
		assert(observed.transfer_digest == ticket.transfer_digest);
		durable_handoff wrong_transfer = ticket;
		wrong_transfer.transfer_digest[0]++;
		assert(!journal.prepare_handoff(wrong_transfer, false) && errno == EPROTO);
		assert(fchmodat(journal.dirfd, prepared_name, 0644, 0) == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		assert(fchmodat(journal.dirfd, prepared_name, 0600, 0) == 0);
		assert(linkat(journal.dirfd, prepared_name, journal.dirfd,
		    ".phase-hardlink", 0) == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		assert(unlinkat(journal.dirfd, ".phase-hardlink", 0) == 0);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::prepared);
		const char *linked_orphan =
		    ".handoff-tmp.00000000000000000000000000000002";
		assert(linkat(journal.dirfd, prepared_name, journal.dirfd,
		    linked_orphan, 0) == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		assert(journal.populate_existing());
		assert(faccessat(journal.dirfd, linked_orphan, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::prepared);
		status_dirfd = journal.dirfd;
		fail_status_fsync = true;
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EIO);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::prepared);
		status_dirfd = -1;
		assert(journal.source_handoff_for_vm(ticket.source_vmid,
		    ticket.source_epoch, observed) ==
		    (int)handoff_phase::prepared && observed.token == ticket.token);
		durable_handoff duplicate = ticket;
		duplicate.token[0] = 0xa4;
		assert(!journal.prepare_handoff(duplicate, false) && errno == EBUSY);
		duplicate.source_session[0]++;
		assert(!journal.prepare_handoff(duplicate, false) && errno == EBUSY);
		assert(journal.handoff_status(duplicate.token, observed) == 0);
		int lockfd = openat(journal.dirfd, ".handoff.lock",
		    O_RDWR | O_NOFOLLOW);
		assert(lockfd >= 0 && flock(lockfd, LOCK_EX) == 0);
		int ready[2], done[2];
		assert(pipe(ready) == 0 && pipe(done) == 0);
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			close(lockfd);
			close(ready[0]);
			close(done[0]);
			dir other(path, nullptr);
			if (write(ready[1], "R", 1) != 1)
				_exit(2);
			durable_handoff child_record{};
			int phase = other.handoff_status(ticket.token,
			    child_record);
			if (phase != (int)handoff_phase::prepared ||
			    write(done[1], "D", 1) != 1)
				_exit(3);
			_exit(0);
		}
		close(ready[1]);
		close(done[1]);
		char signal;
		assert(read(ready[0], &signal, 1) == 1 && signal == 'R');
		pollfd event{done[0], POLLIN, 0};
		assert(poll(&event, 1, 100) == 0);
		assert(flock(lockfd, LOCK_UN) == 0 && close(lockfd) == 0);
		assert(poll(&event, 1, 2000) == 1);
		assert(read(done[0], &signal, 1) == 1 && signal == 'D');
		int child_status;
		assert(waitpid(child, &child_status, 0) == child &&
		    WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
		close(ready[0]);
		close(done[0]);
		assert(observed.source_session == ticket.source_session &&
		    observed.source_vmid == 42 && observed.source_epoch == 99 &&
		    observed.transfer_digest == ticket.transfer_digest);
		durable_handoff wrong = ticket;
		wrong.source_session[0]++;
		assert(!journal.prepare_handoff(wrong, false) && errno == EPROTO);
		assert(!journal.abort_handoff(wrong) && errno == EPROTO);
		ticket.checkpoint_digest[0] = 0xc3;
		assert(journal.commit_handoff(ticket));
		assert(journal.commit_handoff(ticket));
		assert(journal.source_release_status(ticket) == 0);
		EVP_PKEY *source_key = new_ed25519_key();
		EVP_PKEY *destination_key = new_ed25519_key();
		std::array<uint8_t, 32> source_public{}, destination_public{};
		size_t key_length = 32;
		assert(EVP_PKEY_get_raw_public_key(source_key,
		    source_public.data(), &key_length) == 1 && key_length == 32);
		key_length = 32;
		assert(EVP_PKEY_get_raw_public_key(destination_key,
		    destination_public.data(), &key_length) == 1 &&
		    key_length == 32);
		std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> attestation{};
		const std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE>
		    zero_attestation{};
		assert(!journal.attest_source_release(ticket, source_key,
		    destination_public.data(), attestation) && errno == EBUSY);
		assert(attestation == zero_attestation);
		wrong_transfer = ticket;
		wrong_transfer.transfer_digest[0]++;
		assert(!journal.record_source_release(wrong_transfer) &&
		    errno == EPROTO);
		assert(journal.record_source_release(ticket));
		assert(journal.record_source_release(ticket));
		assert(journal.source_release_status(ticket) == 1);
		assert(journal.attest_source_release(ticket, source_key,
		    destination_public.data(), attestation));
		assert(dir::verify_source_release_attestation(ticket,
		    source_public.data(), destination_public.data(),
		    attestation.data()));
		durable_handoff decoded_release{};
		assert(dir::decode_source_release_attestation(attestation.data(),
		    source_public.data(), destination_public.data(),
		    ticket.token.data(), ticket.checkpoint_digest.data(),
		    decoded_release));
		assert(decoded_release.token == ticket.token &&
		    decoded_release.source_session == ticket.source_session &&
		    decoded_release.source_vmid == ticket.source_vmid &&
		    decoded_release.source_epoch == ticket.source_epoch &&
		    decoded_release.transfer_digest == ticket.transfer_digest &&
		    decoded_release.checkpoint_digest == ticket.checkpoint_digest &&
		    decoded_release.destination_vmid == 0 &&
		    decoded_release.destination_epoch == 0);
		const durable_handoff accepted_release = decoded_release;
		auto wrong_token = ticket.token;
		wrong_token[0] ^= 1;
		assert(!dir::decode_source_release_attestation(attestation.data(),
		    source_public.data(), destination_public.data(),
		    wrong_token.data(), ticket.checkpoint_digest.data(),
		    decoded_release) && errno == EPROTO);
		auto wrong_digest = ticket.checkpoint_digest;
		wrong_digest[0] ^= 1;
		assert(!dir::decode_source_release_attestation(attestation.data(),
		    source_public.data(), destination_public.data(),
		    ticket.token.data(), wrong_digest.data(),
		    decoded_release) && errno == EPROTO);
		assert(!dir::decode_source_release_attestation(attestation.data(),
		    destination_public.data(), source_public.data(),
		    ticket.token.data(), ticket.checkpoint_digest.data(),
		    decoded_release) && errno == EPROTO);
		auto changed_release = attestation;
		changed_release.back() ^= 1;
		assert(!dir::decode_source_release_attestation(changed_release.data(),
		    source_public.data(), destination_public.data(),
		    ticket.token.data(), ticket.checkpoint_digest.data(),
		    decoded_release) && errno == EPROTO);
		assert(decoded_release.token == accepted_release.token &&
		    decoded_release.checkpoint_digest ==
		    accepted_release.checkpoint_digest);
		const auto signed_release = attestation;
		assert(!journal.stage_imported_source_release(
		    signed_release.data(), source_public.data(),
		    destination_public.data(), ticket.token.data(),
		    ticket.checkpoint_digest.data()) && errno == EBUSY);
		{
			char foreign_path[] =
			    "/tmp/hypertrace-imported-release.XXXXXX";
			assert(mkdtemp(foreign_path) != nullptr);
			{
				dir foreign(foreign_path, nullptr);
				durable_handoff imported{};
				assert(foreign.read_imported_source_release(
				    source_public.data(), destination_public.data(),
				    ticket.token.data(), ticket.checkpoint_digest.data(),
				    imported) == 0);
				assert(!foreign.stage_imported_source_release(
				    signed_release.data(), destination_public.data(),
				    source_public.data(), ticket.token.data(),
				    ticket.checkpoint_digest.data()) && errno == EPROTO);
				assert(foreign.stage_imported_source_release(
				    signed_release.data(), source_public.data(),
				    destination_public.data(), ticket.token.data(),
				    ticket.checkpoint_digest.data()));
				assert(foreign.stage_imported_source_release(
				    signed_release.data(), source_public.data(),
				    destination_public.data(), ticket.token.data(),
				    ticket.checkpoint_digest.data()));
				assert(foreign.read_imported_source_release(
				    source_public.data(), destination_public.data(),
				    ticket.token.data(), ticket.checkpoint_digest.data(),
				    imported) == 1 &&
				    imported.source_session == ticket.source_session);
				assert(foreign.handoff_status(ticket.token, imported) == 0);
			}
			{
				dir reopened(foreign_path, nullptr);
				durable_handoff imported{};
				assert(reopened.read_imported_source_release(
				    source_public.data(), destination_public.data(),
				    ticket.token.data(), ticket.checkpoint_digest.data(),
				    imported) == 1);
				char imported_name[43];
				memcpy(imported_name, ".imported.", 10);
				static const char hex[] = "0123456789abcdef";
				for (size_t i = 0; i < ticket.token.size(); i++) {
					imported_name[10 + i * 2] =
					    hex[ticket.token[i] >> 4];
					imported_name[11 + i * 2] =
					    hex[ticket.token[i] & 15];
				}
				imported_name[42] = '\0';
				int fd = openat(reopened.dirfd, imported_name,
				    O_RDWR | O_NOFOLLOW | O_CLOEXEC);
				assert(fd >= 0);
				uint8_t damaged = signed_release.back() ^ 1;
				assert(pwrite(fd, &damaged, 1,
				    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
				    fsync(fd) == 0);
				assert(reopened.read_imported_source_release(
				    source_public.data(), destination_public.data(),
				    ticket.token.data(), ticket.checkpoint_digest.data(),
				    imported) == -1 && errno == EPROTO);
				assert(!reopened.stage_imported_source_release(
				    signed_release.data(), source_public.data(),
				    destination_public.data(), ticket.token.data(),
				    ticket.checkpoint_digest.data()) && errno == EPROTO);
				assert(pwrite(fd, &signed_release.back(), 1,
				    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1 &&
				    fsync(fd) == 0 && close(fd) == 0);
				assert(unlinkat(reopened.dirfd, imported_name, 0) == 0);
				assert(unlinkat(reopened.dirfd, ".handoff.lock", 0) == 0);
			}
			assert(rmdir(foreign_path) == 0);
		}
		assert(journal.attest_source_release(ticket, source_key,
		    destination_public.data(), attestation));
		assert(attestation == signed_release);
		std::array<uint8_t, DTRACED_RELEASE_ATTESTED_SIZE> recovered_release{};
		assert(journal.read_source_release_attestation(ticket,
		    source_public.data(), destination_public.data(),
		    recovered_release));
		assert(recovered_release == signed_release);
		auto wrong_destination = destination_public;
		wrong_destination[0] ^= 1;
		assert(!journal.read_source_release_attestation(ticket,
		    source_public.data(), wrong_destination.data(),
		    recovered_release) && errno == EPROTO);
		assert(recovered_release == zero_attestation);
		assert(!dir::verify_source_release_attestation(wrong_transfer,
		    source_public.data(), destination_public.data(),
		    attestation.data()) && errno == EPROTO);
		assert(!journal.attest_source_release(wrong_transfer, source_key,
		    destination_public.data(), attestation) && errno == EPROTO);
		assert(attestation == zero_attestation);
		char attested_name[43];
		static const char hex[] = "0123456789abcdef";
		memcpy(attested_name, ".attested.", 10);
		for (size_t i = 0; i < ticket.token.size(); i++) {
			attested_name[10 + i * 2] = hex[ticket.token[i] >> 4];
			attested_name[11 + i * 2] = hex[ticket.token[i] & 15];
		}
		attested_name[42] = '\0';
		int attested_fd = openat(journal.dirfd, attested_name,
		    O_RDWR | O_NOFOLLOW | O_CLOEXEC);
		assert(attested_fd >= 0);
		uint8_t damaged = signed_release.back() ^ 1;
		assert(pwrite(attested_fd, &damaged, 1,
		    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1);
		assert(fsync(attested_fd) == 0);
		assert(!journal.read_source_release_attestation(ticket,
		    source_public.data(), destination_public.data(),
		    recovered_release) && errno == EPROTO);
		assert(recovered_release == zero_attestation);
		assert(!journal.attest_source_release(ticket, source_key,
		    destination_public.data(), attestation) && errno == EPROTO);
		assert(attestation == zero_attestation);
		assert(pwrite(attested_fd, &signed_release.back(), 1,
		    DTRACED_RELEASE_ATTESTED_SIZE - 1) == 1);
		assert(fsync(attested_fd) == 0);
		assert(close(attested_fd) == 0);
		EVP_PKEY_free(destination_key);
		EVP_PKEY_free(source_key);
		{
			dir reopened(path, nullptr);
			assert(reopened.source_release_status(ticket) == 1);
			assert(reopened.read_source_release_attestation(ticket,
			    source_public.data(), destination_public.data(),
			    recovered_release));
			assert(recovered_release == signed_release);
		}
		wrong_transfer = ticket;
		wrong_transfer.transfer_digest[0]++;
		assert(!journal.commit_handoff(wrong_transfer) && errno == EPROTO);
		durable_handoff prepared = ticket;
		prepared.checkpoint_digest = {};
		assert(!journal.abort_handoff(prepared) && errno == EBUSY);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::committed);
		assert(journal.source_handoff_for_vm(ticket.source_vmid,
		    ticket.source_epoch, observed) ==
		    (int)handoff_phase::committed &&
		    observed.token == ticket.token);
		durable_handoff second = prepared;
		second.token[0] = 0xa5;
		assert(!journal.prepare_handoff(second, false) && errno == EBUSY);
		assert(observed.checkpoint_digest == ticket.checkpoint_digest);
		wrong = ticket;
		wrong.checkpoint_digest[0]++;
		assert(!journal.commit_handoff(wrong) && errno == EPROTO);
		assert(!journal.prepare_handoff(ticket, false) && errno == EINVAL);
		ticket.destination_vmid = 43;
		ticket.destination_epoch = 100;
		assert(!journal.claim_handoff(ticket) && errno == EBUSY);
		assert(journal.reserve_handoff(ticket));
		assert(journal.reserve_handoff(ticket));
		{
			durable_handoff committed = ticket;
			committed.destination_vmid = 0;
			committed.destination_epoch = 0;
			assert(journal.source_release_status(committed) == 1);
		}
		{
			static const char hex[] = "0123456789abcdef";
			char release_name[43];
			memcpy(release_name, ".released.", 10);
			for (size_t i = 0; i < ticket.token.size(); i++) {
				release_name[10 + i * 2] = hex[ticket.token[i] >> 4];
				release_name[11 + i * 2] = hex[ticket.token[i] & 15];
			}
			release_name[42] = '\0';
			assert(renameat(journal.dirfd, release_name,
			    journal.dirfd, ".released.saved") == 0);
			assert(journal.handoff_status(ticket.token, observed) == -1 &&
			    errno == EPROTO);
			assert(renameat(journal.dirfd, ".released.saved",
			    journal.dirfd, release_name) == 0);
			int fd = openat(journal.dirfd, release_name,
			    O_RDWR | O_NOFOLLOW | O_CLOEXEC);
			assert(fd >= 0);
			char original, changed = 'X';
			assert(pread(fd, &original, 1, 0) == 1 &&
			    pwrite(fd, &changed, 1, 0) == 1 && fsync(fd) == 0);
			assert(journal.handoff_status(ticket.token, observed) == -1 &&
			    errno == EPROTO);
			assert(pwrite(fd, &original, 1, 0) == 1 && fsync(fd) == 0 &&
			    close(fd) == 0);
			assert(journal.handoff_status(ticket.token, observed) ==
			    (int)handoff_phase::reserved);
		}
		assert(journal.cancel_handoff_reservation(ticket));
		assert(journal.cancel_handoff_reservation(ticket));
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::committed);
		assert(journal.reserve_handoff(ticket));
		wrong = ticket;
		wrong.destination_epoch++;
		assert(!journal.reserve_handoff(wrong) && errno == EBUSY);
		wrong = ticket;
		wrong.checkpoint_digest[0]++;
		assert(!journal.reserve_handoff(wrong) && errno == EBUSY);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::reserved);
		assert(observed.destination_vmid == 43 &&
		    observed.destination_epoch == 100);
		durable_delivery_state found{};
		bool revoked = false, payload = false;
		status_dirfd = journal.dirfd;
		fail_status_fsync = true;
		assert(journal.handoff_delivery_status(ticket, 0,
		    delivery.delivery_id, delivery.program_id,
		    delivery.source_id, found, revoked, payload) == -1 &&
		    errno == EIO);
		assert(journal.handoff_delivery_status(ticket, 0,
		    delivery.delivery_id, delivery.program_id,
		    delivery.source_id, found, revoked, payload) == 1 &&
		    found.phase == delivery_phase::accepted && !payload);
		fail_status_fsync = true;
		assert(journal.handoff_delivery_status(ticket, 0,
		    delivery.delivery_id + 1, delivery.program_id,
		    delivery.source_id, found, revoked, payload) == -1 &&
		    errno == EIO);
		assert(journal.handoff_delivery_status(ticket, 0,
		    delivery.delivery_id + 1, delivery.program_id,
		    delivery.source_id, found, revoked, payload) == 0);
		/* A queued HOST_ELF acknowledges the separate host ingress
		 * journal. A reconnect may have used an older session. */
		{
			dir incoming(ingresspath, nullptr);
			durable_delivery ingress = delivery;
			ingress.scope = 3;
			ingress.journal_version = 4;
			ingress.session_id[0]++;
			ingress.delivery_id++;
			ingress.payload_digest[0] = 0x5a;
			assert(incoming.record_delivery(ingress,
			    delivery_phase::pending, true));
			assert(journal.handoff_delivery_status(ticket, 3,
			    ingress.delivery_id, ingress.program_id,
			    ingress.source_id, found, revoked, payload,
			    &incoming) == 1 &&
			    found.phase == delivery_phase::pending && !payload);
			assert(incoming.record_delivery(ingress,
			    delivery_phase::accepted));
			assert(journal.handoff_delivery_status(ticket, 3,
			    ingress.delivery_id, ingress.program_id,
			    ingress.source_id, found, revoked, payload,
			    &incoming) == 1 &&
			    found.phase == delivery_phase::accepted && payload &&
			    found.record.payload_digest == ingress.payload_digest);
			assert(journal.handoff_delivery_status(ticket, 0,
			    ingress.delivery_id, ingress.program_id,
			    ingress.source_id, found, revoked, payload) == 0);
			assert(journal.handoff_delivery_status(ticket, 3,
			    ingress.delivery_id + 1, ingress.program_id,
			    ingress.source_id, found, revoked, payload,
			    &incoming) == 0);
			int scanfd = openat(incoming.dirfd, ".",
			    O_RDONLY | O_DIRECTORY);
			assert(scanfd >= 0);
			DIR *scan = fdopendir(scanfd);
			assert(scan != nullptr);
			for (dirent *entry; (entry = readdir(scan)) != nullptr; )
				if (strcmp(entry->d_name, ".") != 0 &&
				    strcmp(entry->d_name, "..") != 0)
					assert(unlinkat(incoming.dirfd,
					    entry->d_name, 0) == 0);
			assert(closedir(scan) == 0);
		}
		durable_kill kill{};
		kill.pid = 124;
		kill.vmid = ticket.source_vmid;
		kill.epoch = ticket.source_epoch;
		kill.source_id[0] = 3;
		assert(journal.record_kill(kill));
		fail_status_fsync = true;
		assert(journal.handoff_kill_status(ticket, kill.pid,
		    kill.source_id, revoked) == -1 && errno == EIO);
		assert(journal.handoff_kill_status(ticket, kill.pid,
		    kill.source_id, revoked) == 'p' && revoked);
		fail_status_fsync = true;
		assert(journal.handoff_kill_status(ticket, kill.pid + 1,
		    kill.source_id, revoked) == -1 && errno == EIO);
		assert(journal.handoff_kill_status(ticket, kill.pid + 1,
		    kill.source_id, revoked) == 0 && revoked);
		status_dirfd = -1;
		{
			dir recovered(path, nullptr);
			assert(recovered.handoff_status(ticket.token, observed) ==
			    (int)handoff_phase::reserved);
			assert(recovered.reserve_handoff(ticket));
		}
		assert(!journal.claim_handoff(ticket) && errno == EBUSY);
		wrong = ticket;
		wrong.destination_vmid++;
		assert(!journal.begin_handoff_mutation(wrong) &&
		    errno == EBUSY);
		durable_handoff rival = ticket;
		rival.token[0] = 0xa3;
		rival.source_session[0] = 0xb4;
		rival.source_vmid = 44;
		rival.source_epoch = 101;
		durable_handoff rival_prepared = rival;
		rival_prepared.checkpoint_digest = {};
		rival_prepared.destination_vmid = 0;
		rival_prepared.destination_epoch = 0;
		assert(journal.prepare_handoff(rival_prepared, false));
		durable_handoff rival_committed = rival;
		rival_committed.destination_vmid = 0;
		rival_committed.destination_epoch = 0;
		assert(journal.commit_handoff(rival_committed));
		assert(journal.record_source_release(rival_committed));
		assert(!journal.reserve_handoff(rival) && errno == EBUSY);
		assert(journal.begin_handoff_mutation(ticket));
		assert(journal.begin_handoff_mutation(ticket));
		/* A revocation after the source image cut is not in its saved
		 * control queue. CLAIM must still copy it before guest startup. */
		durable_kill preclaim{};
		preclaim.pid = 126;
		preclaim.vmid = ticket.source_vmid;
		preclaim.epoch = ticket.source_epoch;
		preclaim.source_id[0] = 0x55;
		assert(journal.record_kill(preclaim));
		assert(!journal.cancel_handoff_reservation(ticket) && errno == EBUSY);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::mutating);
		{
			dir recovered(path, nullptr);
			assert(recovered.handoff_status(ticket.token, observed) ==
			    (int)handoff_phase::mutating);
			assert(!recovered.cancel_handoff_reservation(ticket) &&
			    errno == EBUSY);
			assert(recovered.begin_handoff_mutation(ticket));
		}
		fail_handoff_file_fsync_countdown = 2;
		assert(!journal.claim_handoff(ticket) && errno == EIO &&
		    fail_handoff_file_fsync_countdown == 0);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::mutating);
		{
			dir recovered(path, nullptr);
			assert(recovered.populate_existing());
		}
		assert(journal.claim_handoff(ticket));
		assert(journal.claim_handoff(ticket));
		const char *capable_name =
		    ".handoff-capable.a1000000000000000000000000000000";
		const char *held_capable = ".capable-held";
		assert(renameat(journal.dirfd, capable_name, journal.dirfd,
		    held_capable) == 0);
		assert(!journal.claim_handoff(ticket) && errno == EOPNOTSUPP);
		assert(!journal.mark_handoff_execution_start(ticket) &&
		    errno == EOPNOTSUPP);
		assert(journal.handoff_execution_start_status(ticket) == -1 &&
		    errno == EOPNOTSUPP);
		assert(renameat(journal.dirfd, held_capable, journal.dirfd,
		    capable_name) == 0 && fsync(journal.dirfd) == 0);
		int capable_fd = openat(journal.dirfd, capable_name, O_RDWR);
		assert(capable_fd >= 0);
		uint8_t capable_byte;
		assert(pread(capable_fd, &capable_byte, 1, 46) == 1);
		uint8_t corrupt_capable = capable_byte ^ 1;
		assert(pwrite(capable_fd, &corrupt_capable, 1, 46) == 1 &&
		    fsync(capable_fd) == 0);
		assert(!journal.mark_handoff_execution_start(ticket) &&
		    errno == EPROTO);
		{
			dir recovered(path, nullptr);
			assert(!recovered.populate_existing() && errno == EPROTO);
		}
		assert(pwrite(capable_fd, &capable_byte, 1, 46) == 1 &&
		    fsync(capable_fd) == 0 && close(capable_fd) == 0);
		assert(journal.handoff_execution_start_status(ticket) == 0);
		assert(journal.mark_handoff_execution_start(ticket));
		assert(journal.mark_handoff_execution_start(ticket));
		assert(journal.handoff_execution_start_status(ticket) == 1);
		char start_name[48];
		assert(snprintf(start_name, sizeof(start_name),
		    ".handoff-start.a1000000000000000000000000000000") == 47);
		int start_fd = openat(journal.dirfd, start_name, O_RDWR);
		assert(start_fd >= 0);
		uint8_t start_byte;
		assert(pread(start_fd, &start_byte, 1, 46) == 1);
		uint8_t corrupt_byte = start_byte ^ 1;
		assert(pwrite(start_fd, &corrupt_byte, 1, 46) == 1);
		assert(fsync(start_fd) == 0);
		assert(journal.handoff_execution_start_status(ticket) == -1 &&
		    errno == EPROTO);
		{
			dir recovered(path, nullptr);
			assert(!recovered.populate_existing() && errno == EPROTO);
		}
		assert(pwrite(start_fd, &start_byte, 1, 46) == 1);
		assert(fsync(start_fd) == 0);
		assert(close(start_fd) == 0);
		assert(journal.handoff_execution_start_status(ticket) == 1);
		{
			dir recovered(path, nullptr);
			assert(recovered.populate_existing());
		}
		const char *orphan_start =
		    ".handoff-start.00000000000000000000000000000000";
		int orphan_start_fd = openat(journal.dirfd, orphan_start,
		    O_WRONLY | O_CREAT | O_EXCL, 0600);
		assert(orphan_start_fd >= 0 &&
		    write(orphan_start_fd, "x", 1) == 1 &&
		    fsync(orphan_start_fd) == 0 && close(orphan_start_fd) == 0 &&
		    fsync(journal.dirfd) == 0);
		{
			dir recovered(path, nullptr);
			assert(!recovered.populate_existing() && errno == EPROTO);
		}
		assert(unlinkat(journal.dirfd, orphan_start, 0) == 0 &&
		    fsync(journal.dirfd) == 0);
		wrong = ticket;
		wrong.destination_epoch++;
		assert(!journal.mark_handoff_execution_start(wrong) &&
		    errno == EBUSY);
		assert(journal.handoff_execution_start_status(wrong) == -1 &&
		    errno == EBUSY);
		assert(journal.mark_handoff_rekey_applied(ticket));
		assert(journal.mark_handoff_rekey_applied(ticket));
		wrong = ticket;
		wrong.destination_epoch++;
		assert(!journal.mark_handoff_rekey_applied(wrong) &&
		    errno == EBUSY);
		char claimed_name[44];
		assert(snprintf(claimed_name, sizeof(claimed_name),
		    ".handoff.a1000000000000000000000000000000.r") == 43);
		char applied_name[50];
		assert(snprintf(applied_name, sizeof(applied_name),
		    ".handoff-applied.%.*s", 32, claimed_name + 9) == 49);
		int applied_fd = openat(journal.dirfd, applied_name, O_RDWR);
		assert(applied_fd >= 0);
		uint8_t altered;
		assert(pread(applied_fd, &altered, 1, 46) == 1);
		altered ^= 1;
		assert(pwrite(applied_fd, &altered, 1, 46) == 1);
		assert(fsync(applied_fd) == 0);
		assert(!journal.mark_handoff_rekey_applied(ticket) &&
		    errno == EPROTO);
		altered ^= 1;
		assert(pwrite(applied_fd, &altered, 1, 46) == 1);
		assert(fsync(applied_fd) == 0);
		assert(close(applied_fd) == 0);
		assert(journal.mark_handoff_rekey_applied(ticket));
		assert(unlinkat(journal.dirfd, applied_name, 0) == 0);
		fail_phase_file_fsync = true;
		assert(!journal.mark_handoff_rekey_applied(ticket) &&
		    errno == EIO && !fail_phase_file_fsync);
		assert(faccessat(journal.dirfd, applied_name, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(journal.mark_handoff_rekey_applied(ticket));
		const char *applied_orphan =
		    ".handoff-tmp.00000000000000000000000000000003";
		assert(linkat(journal.dirfd, applied_name, journal.dirfd,
		    applied_orphan, 0) == 0);
		assert(!journal.mark_handoff_rekey_applied(ticket) &&
		    errno == EPROTO);
		assert(journal.populate_existing());
		assert(faccessat(journal.dirfd, applied_orphan, F_OK, 0) == -1 &&
		    errno == ENOENT);
		assert(journal.mark_handoff_rekey_applied(ticket));
		assert(unlinkat(journal.dirfd, applied_name, 0) == 0);
		assert(mkfifoat(journal.dirfd, applied_name, 0600) == 0);
		assert(!journal.mark_handoff_rekey_applied(ticket) &&
		    errno == EPROTO);
		assert(unlinkat(journal.dirfd, applied_name, 0) == 0);
		assert(journal.mark_handoff_rekey_applied(ticket));
		char skipped_name[44];
		memcpy(skipped_name, claimed_name, sizeof(skipped_name));
		skipped_name[42] = 'v';
		assert(linkat(journal.dirfd, claimed_name, journal.dirfd,
		    skipped_name, 0) == 0);
		assert(journal.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		assert(unlinkat(journal.dirfd, skipped_name, 0) == 0);
		assert(!journal.reserve_handoff(rival) && errno == EBUSY);
		rival.destination_vmid = 45;
		assert(journal.reserve_handoff(rival));
		assert(journal.cancel_handoff_reservation(rival));
		wrong = ticket;
		wrong.destination_epoch++;
		assert(!journal.claim_handoff(wrong) && errno == EBUSY);
		assert(journal.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::claimed);
		assert(observed.destination_vmid == 43 &&
		    observed.destination_epoch == 100);
	}
	{
		dir recovered(path, nullptr);
		durable_handoff observed{};
		assert(recovered.handoff_status(ticket.token, observed) ==
		    (int)handoff_phase::claimed);
		assert(observed.checkpoint_digest == ticket.checkpoint_digest);
		assert(recovered.claim_handoff(ticket));
		assert(recovered.handoff_execution_start_status(ticket) == 1);
		assert(recovered.mark_handoff_rekey_applied(ticket));
		/* A KILL arriving after CLAIM must reach the claimed incarnation;
		 * a later migration must extend that same revocation lineage. */
		assert(recovered.bind_handoff_kills_all(ticket));
		durable_kill copied{};
		copied.pid = 126;
		copied.vmid = ticket.destination_vmid;
		copied.epoch = ticket.destination_epoch;
		copied.source_id[0] = 0x55;
		assert(recovered.kill_applied(copied) == 0);
		durable_kill earlier{};
		earlier.pid = 124;
		earlier.vmid = ticket.destination_vmid;
		earlier.epoch = ticket.destination_epoch;
		earlier.source_id[0] = 3;
		assert(recovered.record_kill_applied(earlier));
		durable_kill late = earlier;
		late.pid = 125;
		late.vmid = ticket.source_vmid;
		late.epoch = ticket.source_epoch;
		late.source_id[0] = 4;
		std::vector<durable_kill> selected;
		assert(recovered.record_kill(late,
		    [&](const std::vector<durable_kill> &records) {
			selected = records;
			return (true);
		    }));
		assert(selected.size() == 2 &&
		    selected[0].vmid == ticket.source_vmid &&
		    selected[1].vmid == ticket.destination_vmid &&
		    selected[1].epoch == ticket.destination_epoch);
		late.vmid = ticket.destination_vmid;
		late.epoch = ticket.destination_epoch;
		assert(recovered.record_kill_applied(late));
		durable_handoff next{};
		next.token[0] = 0xa6;
		next.source_session[0] = 0xb6;
		next.source_vmid = ticket.destination_vmid;
		next.source_epoch = ticket.destination_epoch;
		next.checkpoint_digest[0] = 0xd6;
		next.destination_vmid = 46;
		next.destination_epoch = 102;
		durable_handoff next_prepared = next;
		next_prepared.checkpoint_digest = {};
		next_prepared.destination_vmid = 0;
		next_prepared.destination_epoch = 0;
		/* A second cut cannot omit this copied, unapplied revocation. */
		assert(!recovered.prepare_handoff(next_prepared, false) &&
		    errno == EBUSY);
		assert(recovered.record_kill_applied(copied));
		assert(recovered.prepare_handoff(next_prepared, false));
		durable_handoff next_committed = next;
		next_committed.destination_vmid = 0;
		next_committed.destination_epoch = 0;
		assert(recovered.commit_handoff(next_committed));
		assert(recovered.record_source_release(next_committed));
		assert(recovered.reserve_handoff(next));
		assert(recovered.begin_handoff_mutation(next));
		assert(recovered.claim_handoff(next));
		durable_kill newest = late;
		newest.pid = 126;
		newest.vmid = ticket.source_vmid;
		newest.epoch = ticket.source_epoch;
		newest.source_id[0] = 5;
		assert(recovered.record_kill(newest,
		    [&](const std::vector<durable_kill> &records) {
			selected = records;
			return (true);
		    }));
		assert(selected.size() == 3 &&
		    selected[0].vmid == ticket.source_vmid &&
		    selected[1].vmid == ticket.destination_vmid &&
		    selected[2].vmid == next.destination_vmid &&
		    selected[2].epoch == next.destination_epoch);
		std::vector<durable_kill> recorded;
		assert(recovered.list_kills(recorded));
		for (const durable_kill &member : selected)
			assert(std::any_of(recorded.begin(), recorded.end(),
			    [&](const durable_kill &entry) {
				return (entry.pid == member.pid &&
				    entry.vmid == member.vmid &&
				    entry.epoch == member.epoch &&
				    entry.source_id == member.source_id);
			    }));
		size_t before_retry = recorded.size();
		assert(recovered.record_kill(newest));
		assert(recovered.list_kills(recorded) &&
		    recorded.size() == before_retry);
		durable_kill interrupted = newest;
		interrupted.pid++;
		interrupted.source_id[0]++;
		status_dirfd = recovered.dirfd;
		fail_status_fsync = true;
		assert(!recovered.record_kill(interrupted) && errno == EIO);
		status_dirfd = -1;
		assert(recovered.list_kills(recorded));
		assert(std::none_of(recorded.begin(), recorded.end(),
		    [&](const durable_kill &entry) {
			return (entry.pid == interrupted.pid &&
			    entry.vmid == interrupted.vmid &&
			    entry.epoch == interrupted.epoch &&
			    entry.source_id == interrupted.source_id);
		    }));
		assert(recovered.record_kill(interrupted));
		assert(recovered.list_kills(recorded));
		for (uint16_t vmid : {ticket.source_vmid,
		    ticket.destination_vmid, next.destination_vmid})
			assert(std::any_of(recorded.begin(), recorded.end(),
			    [&](const durable_kill &entry) {
				return (entry.pid == interrupted.pid &&
				    entry.vmid == vmid &&
				    entry.source_id == interrupted.source_id);
			    }));
		before_retry = recorded.size();
		durable_kill refused = newest;
		refused.pid++;
		assert(!recovered.record_kill(refused,
		    [](const std::vector<durable_kill> &) {
			errno = ENOMEM;
			return (false);
		    }) && errno == ENOMEM);
		assert(recovered.list_kills(recorded) &&
		    recorded.size() == before_retry);
		char name[44];
		assert(snprintf(name, sizeof(name),
		    ".handoff.a1000000000000000000000000000000.r") == 43);
		int fd = openat(recovered.dirfd, name, O_WRONLY | O_NOFOLLOW);
		assert(fd >= 0);
		assert(pwrite(fd, "X", 1, 20) == 1);
		assert(close(fd) == 0);
		assert(recovered.handoff_status(ticket.token, observed) == -1 &&
		    errno == EPROTO);
		int scanfd = openat(recovered.dirfd, ".", O_RDONLY | O_DIRECTORY);
		assert(scanfd >= 0);
		DIR *scan = fdopendir(scanfd);
		assert(scan != nullptr);
		for (dirent *entry; (entry = readdir(scan)) != nullptr; ) {
			if (strcmp(entry->d_name, ".") != 0 &&
			    strcmp(entry->d_name, "..") != 0)
				assert(unlinkat(recovered.dirfd, entry->d_name, 0) == 0);
		}
		assert(closedir(scan) == 0);
	}
	assert(rmdir(path) == 0);
	assert(rmdir(ingresspath) == 0);
	puts("PASS: durable handoff reserve, cancel, mutation, claim and corruption fence");
}
