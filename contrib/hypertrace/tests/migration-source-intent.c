/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <sys/wait.h>
#include "migration_source_owner.h"

struct vmctx { uint16_t vmid; uint64_t epoch; };
static int mode, queries, stops, destroys, identities;
static bool retired, fail_sync;
static unsigned fail_sync_after;
int __real_fsync(int);
int __wrap_fsync(int fd) {
	if (fail_sync || (fail_sync_after != 0 && --fail_sync_after == 0)) {
		fail_sync = false; errno = EIO; return (-1);
	}
	return (__real_fsync(fd));
}
static int hypertrace_session_retired(uint16_t vmid, uint64_t epoch) {
	assert(vmid == 7 && epoch == 9); queries++;
	if (mode == 5) { errno = ENXIO; return (-1); }
	if (retired) return (0);
	errno = EBUSY; return (-1);
}
static int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch) {
	identities++;
	if (mode == 14) { errno = EIO; return (-1); }
	*vmid = ctx->vmid; *epoch = ctx->epoch; return (0);
}
static void fbsdrun_retire_cpus_begin(void) {}
static int join_error, context_closes;
static int fbsdrun_retire_cpus_wait(void) { return (join_error); }
static void vm_close(struct vmctx *ctx) { assert(ctx != NULL); context_closes++; }
static int vm_destroy_request_checked(struct vmctx *ctx) { (void)ctx; abort(); }
static int hypertrace_retire_transport(void) { return (0); }
static int pci_vtdtr_checkpoint_stop(void) { stops++; return mode == 3 ? EIO : 0; }
static int vm_destroy_identity_request_checked(struct vmctx *ctx, uint16_t vmid, uint64_t epoch) {
	assert(ctx && vmid == 7 && epoch == 9 && stops == 1); destroys++;
	if (mode == 4 || mode == 13 || mode == 15) {
		errno = mode == 4 ? EBUSY : mode == 13 ? ENOTTY : ESTALE; return (-1);
	}
	retired = mode != 7;
	if (mode == 8) fail_sync = true;
	return (0);
}
static int named_destroys;
static int vm_destroy_name_identity_checked(const char *name, uint16_t vmid, uint64_t epoch) {
	assert(strcmp(name, "orphan") == 0 && vmid == 7 && epoch == 9);
	named_destroys++;
	if (mode == 13 || mode == 15) { errno = mode == 13 ? ENOTTY : ESTALE; return (-1); }
	retired = mode != 7;
	return (0);
}
/* Exercise the actual restart adapter with controlled TLS/kernel boundaries. */
struct migration_tls_credentials { int unused; };
struct migration_channel { int unused; };
struct migration_transport { int unused; };
static int restart_mode, restart_cleanups, restart_runs, restart_connections;
static int migration_channel_init(struct migration_channel *c,
    struct migration_transport *xp, int fd, bool server,
    const struct migration_tls_credentials *credentials, int timeout) {
	(void)c; (void)xp; (void)fd; (void)credentials;
	assert(!server && timeout == 30000); restart_connections++;
	return (restart_mode == 1 ? EACCES : 0);
}
static int migration_channel_binding(struct migration_channel *c, bool source,
    uint8_t source_pin[32], uint8_t destination_pin[32]) {
	(void)c; assert(source);
	memset(source_pin, restart_mode == 3 ? 9 : 3, 32);
	memset(destination_pin, restart_mode == 4 ? 9 : 4, 32);
	return (restart_mode == 2 ? EIO : restart_mode == 8 ? EBUSY : 0);
}
static void migration_channel_cleanup(struct migration_channel *c) {
	(void)c; restart_cleanups++;
}
static int migration_recovery_source_run(struct migration_channel *c,
    struct migration_transport *xp, int fd,
    const struct migration_recovery_record *expected) {
	uint16_t phase;
	(void)c; (void)xp;
	assert(migration_recovery_load_at(fd, expected, &phase) == 0);
	assert(phase == MIGRATION_REC_SOURCE_RETIRED);
	restart_runs++; return (restart_mode == 7 ? ECONNRESET : 0);
}
#include "intent.inc"

int main(void) {
	struct migration_recovery_record binding = { .phase = MIGRATION_REC_SOURCE_INTENT,
	    .destination_vmid = 8, .destination_epoch = 10 };
	struct hypertrace_session_record session = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	assert(hypertrace_session_record_encode(binding.session, 40, &session) == 0);
	memset(binding.challenge, 1, 32); memset(binding.state_digest, 2, 32);
	memset(binding.source_certificate_sha256, 3, 32);
	memset(binding.destination_certificate_sha256, 4, 32);
	/* Model the fixed absolute path below an isolated administrator-owned root. */
	char hostroot[] = "hostroot.XXXXXX"; assert(mkdtemp(hostroot));
	int hostfd = open(hostroot, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(hostfd >= 0);
	int canonical = -99;
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) == ENOENT);
	assert(canonical == -99);
	assert(mkdirat(hostfd, "var", 0755) == 0);
	assert(mkdirat(hostfd, "var/db", 0755) == 0);
	assert(mkdirat(hostfd, "var/db/bhyve", 0755) == 0);
	assert(mkdirat(hostfd, "var/db/bhyve/migration", 0700) == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) == 0);
	assert(fcntl(canonical, F_GETFD) & FD_CLOEXEC);
	int selected = -1;
	assert(migration_source_root_pin(&selected, canonical) == 0);
	close(canonical); canonical = -99;
	assert(migration_source_root_open_at(hostfd, (uid_t)(geteuid() + 1), &canonical) == EPERM);
	assert(canonical == -99);
	int parent = openat(hostfd, "var/db/bhyve", O_RDONLY | O_DIRECTORY);
	assert(parent >= 0 && fchmod(parent, 0777) == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) == EPERM);
	assert(fchmod(parent, 0755) == 0);
	assert(fchmod(selected, 0755) == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) == EPERM);
	assert(fchmod(selected, 0700) == 0);
	assert(renameat(parent, "migration", parent, "original") == 0);
	assert(symlinkat("original", parent, "migration") == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) != 0);
	assert(canonical == -99);
	assert(unlinkat(parent, "migration", 0) == 0);
	assert(mkdirat(parent, "migration", 0700) == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) == 0);
	assert(migration_source_root_pin(&selected, canonical) == EXDEV);
	close(canonical); canonical = -99;
	assert(renameat(hostfd, "var/db/bhyve", hostfd, "var/db/original-bhyve") == 0);
	assert(symlinkat("original-bhyve", hostfd, "var/db/bhyve") == 0);
	assert(migration_source_root_open_at(hostfd, geteuid(), &canonical) != 0);
	assert(canonical == -99);
	close(selected); close(parent); close(hostfd);
	/* A retired lifetime can authorize only its original destination attempt. */
	char ownerdir[] = "owner.XXXXXX"; assert(mkdtemp(ownerdir));
	int ownerfd = open(ownerdir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(ownerfd >= 0);
	int pinned = -1;
	assert(migration_source_root_pin(&pinned, ownerfd) == 0);
	assert(pinned != ownerfd && (fcntl(pinned, F_GETFD) & FD_CLOEXEC));
	assert(migration_source_root_pin(&pinned, ownerfd) == 0);
	int alias = openat(ownerfd, ".", O_RDONLY | O_DIRECTORY);
	assert(alias >= 0 && migration_source_root_pin(&pinned, alias) == 0);
	close(alias);
	char otherdir[] = "other.XXXXXX"; assert(mkdtemp(otherdir));
	int otherfd = open(otherdir, O_RDONLY | O_DIRECTORY);
	assert(otherfd >= 0 && migration_source_root_pin(&pinned, otherfd) == EXDEV);
	assert(fchmod(otherfd, 0755) == 0);
	assert(migration_source_root_pin(&pinned, otherfd) == EPERM);
	close(otherfd);

	assert(migration_source_owner_at(ownerfd, &binding, false) == ENOENT);
	fail_sync = true;
	assert(migration_source_owner_at(ownerfd, &binding, true) == EIO);
	assert(migration_source_owner_at(ownerfd, &binding, false) == ENOENT);
	assert(migration_source_owner_at(ownerfd, &binding, true) == 0);
	assert(migration_source_owner_at(ownerfd, &binding, true) == 0);
	for (unsigned field = 0; field < 7; field++) {
		struct migration_recovery_record rival = binding;
		switch (field) {
		case 0: rival.challenge[0] ^= 1; break;
		case 1: rival.destination_vmid++; break;
		case 2: rival.destination_epoch++; break;
		case 3: rival.state_digest[0] ^= 1; break;
		case 4: rival.source_certificate_sha256[0] ^= 1; break;
		case 5: rival.destination_certificate_sha256[0] ^= 1; break;
		case 6:
			session.stop_token++;
			assert(hypertrace_session_record_encode(rival.session, 40, &session) == 0);
			session.stop_token--; break;
		}
		assert(migration_source_owner_at(ownerfd, &rival, true) == EPROTO);
		assert(migration_source_owner_at(ownerfd, &rival, false) == EPROTO);
		assert(migration_recovery_store_at(ownerfd, &rival) == 0 || field != 0);
		/* Even a competing journal plus kernel absence cannot retire it. */
		retired = true; queries = 0;
		assert(migration_prod_source_finish_intent(NULL, ownerfd, &rival) == EPROTO);
		assert(queries == 0);
	}
	/* A lost parent-directory sync response must not permit another owner.
	 * The renamed original record is visible, but publication reports EIO.
	 * Reopen the directory as a restarted controller would, then reject a
	 * different destination before consulting kernel retirement evidence. */
	char uncertain_dir[] = "owner-sync.XXXXXX";
	assert(mkdtemp(uncertain_dir));
	int uncertain_fd = open(uncertain_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(uncertain_fd >= 0);
	fail_sync_after = 2; /* temporary file succeeds; directory fails */
	assert(migration_source_owner_at(uncertain_fd, &binding, true) == EIO);
	assert(fail_sync_after == 0);
	close(uncertain_fd);
	uncertain_fd = open(uncertain_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(uncertain_fd >= 0);
	struct migration_recovery_record competing = binding;
	competing.destination_epoch++;
	assert(migration_source_owner_at(uncertain_fd, &competing, true) == EPROTO);
	retired = true; queries = 0;
	assert(migration_prod_source_finish_intent(NULL, uncertain_fd, &competing) == EPROTO);
	assert(queries == 0);
	/* Exact recovery still propagates a second failed directory sync, then
	 * finishes durability on retry without changing the original binding. */
	fail_sync_after = 2;
	assert(migration_source_owner_at(uncertain_fd, &binding, false) == EIO);
	assert(fail_sync_after == 0);
	assert(migration_source_owner_at(uncertain_fd, &binding, false) == 0);
	assert(migration_source_owner_at(uncertain_fd, &binding, true) == 0);
	assert(migration_source_owner_at(uncertain_fd, &competing, false) == EPROTO);
	struct migration_recovery_record loaded, sentinel;
	memset(&sentinel, 0xa5, sizeof(sentinel));
	loaded = sentinel;
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == 0);
	uint8_t original_wire[MIGRATION_RECOVERY_SIZE], loaded_wire[MIGRATION_RECOVERY_SIZE];
	assert(migration_recovery_encode(&binding, original_wire) == 0);
	assert(migration_recovery_encode(&loaded, loaded_wire) == 0);
	assert(memcmp(original_wire, loaded_wire, sizeof(original_wire)) == 0);
	/* Every byte, including reserved fields and checksum, is canonical. */
	for (size_t i = 0; i < sizeof(original_wire); i++) {
		memcpy(loaded_wire, original_wire, sizeof(loaded_wire));
		loaded_wire[i] ^= 1; loaded = sentinel;
		assert(migration_recovery_decode(loaded_wire, sizeof(loaded_wire), &loaded) == EPROTO);
		assert(memcmp(&loaded, &sentinel, sizeof(loaded)) == 0);
	}
	loaded = sentinel;
	assert(migration_source_owner_load_at(uncertain_fd, 7, 10, &loaded) == ENOENT);
	assert(memcmp(&loaded, &sentinel, sizeof(loaded)) == 0);
	for (unsigned sync = 1; sync <= 2; sync++) {
		fail_sync_after = sync;
		assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == EIO);
		assert(memcmp(&loaded, &sentinel, sizeof(loaded)) == 0);
	}
	int recordfd = openat(uncertain_fd,
	    "source-owner-0007-0000000000000009.state", O_RDWR | O_NOFOLLOW);
	assert(recordfd >= 0);
	assert(fchmod(recordfd, 0644) == 0);
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == EPERM);
	assert(fchmod(recordfd, 0600) == 0);
	assert(pwrite(recordfd, "x", 1, sizeof(original_wire)) == 1);
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == EPROTO);
	assert(ftruncate(recordfd, sizeof(original_wire) - 1) == 0);
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == EPROTO);
	assert(pwrite(recordfd, original_wire, sizeof(original_wire), 0) == sizeof(original_wire));
	struct migration_recovery_record wrong_lifetime = binding;
	struct hypertrace_session_record wrong_session = session;
	wrong_session.epoch += 2;
	assert(hypertrace_session_record_encode(wrong_lifetime.session, 40, &wrong_session) == 0);
	assert(migration_recovery_encode(&wrong_lifetime, loaded_wire) == 0);
	assert(pwrite(recordfd, loaded_wire, sizeof(loaded_wire), 0) == sizeof(loaded_wire));
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == ESTALE);
	wrong_lifetime = binding; wrong_lifetime.phase = MIGRATION_REC_SOURCE_RETIRED;
	assert(migration_recovery_encode(&wrong_lifetime, loaded_wire) == 0);
	assert(pwrite(recordfd, loaded_wire, sizeof(loaded_wire), 0) == sizeof(loaded_wire));
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == EPROTO);
	assert(memcmp(&loaded, &sentinel, sizeof(loaded)) == 0);
	assert(pwrite(recordfd, original_wire, sizeof(original_wire), 0) == sizeof(original_wire));
	close(recordfd);
	assert(migration_source_owner_load_at(uncertain_fd, 7, 9, &loaded) == 0);
	close(uncertain_fd);
	struct migration_recovery_record later = binding;
	later.phase = MIGRATION_REC_SOURCE_CONFIRMED;
	assert(migration_source_owner_at(ownerfd, &later, false) == 0);
	fail_sync = true;
	assert(migration_source_owner_at(ownerfd, &later, false) == EIO);
	assert(migration_source_owner_at(ownerfd, &later, false) == 0);
	close(ownerfd);
	assert(migration_source_owner_at(pinned, &binding, false) == 0);
	close(pinned);
	char racedir[] = "race.XXXXXX"; assert(mkdtemp(racedir));
	int racefd = open(racedir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(racefd >= 0);
	int gate[2]; assert(pipe(gate) == 0);
	pid_t children[2];
	for (unsigned i = 0; i < 2; i++) {
		children[i] = fork(); assert(children[i] >= 0);
		if (children[i] == 0) {
			char ready;
			close(gate[1]); assert(read(gate[0], &ready, 1) == 1);
			struct migration_recovery_record attempt = binding;
			attempt.challenge[0] += i;
			int error = migration_source_owner_at(racefd, &attempt, true);
			_exit(error == 0 ? 0 : error == EPROTO ? 1 : 2);
		}
	}
	close(gate[0]); assert(write(gate[1], "xx", 2) == 2); close(gate[1]);
	unsigned winners = 0;
	for (unsigned i = 0; i < 2; i++) {
		int status; assert(waitpid(children[i], &status, 0) == children[i]);
		assert(WIFEXITED(status) && WEXITSTATUS(status) <= 1);
		winners += WEXITSTATUS(status) == 0;
	}
	assert(winners == 1); close(racefd);
	const int restart_errors[] = {0, EACCES, EIO, EACCES, EACCES, EBUSY, ENXIO, ECONNRESET};
	for (restart_mode = 0; restart_mode < 8; restart_mode++) {
		char restart_dir[] = "restart.XXXXXX"; assert(mkdtemp(restart_dir));
		int fd = open(restart_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		assert(fd >= 0);
		struct migration_tls_credentials credentials = {0};
		restart_connections = restart_runs = restart_cleanups = 0;
		queries = stops = destroys = 0;
		mode = restart_mode == 6 ? 5 : 0;
		retired = restart_mode != 5;
		assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9, NULL, NULL) == EINVAL);
		assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9, &credentials, NULL) == ENOENT);
		assert(restart_connections == 0 && queries == 0);
		assert(migration_source_owner_at(fd, &binding, true) == 0);
		assert(migration_recovery_store_at(fd, &binding) == 0);
		int controller = -1, untouched = -99;
		assert(migration_source_controller_lock_at(fd, 7, 9, &controller) == 0);
		assert(fcntl(controller, F_GETFD) & FD_CLOEXEC);
		assert(migration_source_controller_lock_at(fd, 7, 9, &untouched) == EBUSY);
		assert(untouched == -99);
		assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9, &credentials, NULL) == EBUSY);
		assert(restart_connections == 0 && queries == 0);
		pid_t contender = fork(); assert(contender >= 0);
		if (contender == 0) {
			close(controller);
			int child_lock = -1;
			_exit(migration_source_controller_lock_at(fd, 7, 9, &child_lock) == EBUSY ? 0 : 1);
		}
		int contention_status;
		assert(waitpid(contender, &contention_status, 0) == contender);
		assert(WIFEXITED(contention_status) && WEXITSTATUS(contention_status) == 0);
		close(controller);
		assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9, &credentials, NULL) == restart_errors[restart_mode]);
		assert(restart_connections == 1);
		assert(restart_cleanups == (restart_mode == 1 ? 0 : 1));
		assert(restart_runs == (restart_mode == 0 || restart_mode == 7 ? 1 : 0));
		assert(stops == 0 && destroys == 0);
		assert(queries == (restart_mode == 0 || restart_mode >= 5 ? 1 : 0));
		uint16_t phase;
		assert(migration_recovery_load_at(fd, &binding, &phase) == 0);
		assert(phase == (restart_runs ? MIGRATION_REC_SOURCE_RETIRED : MIGRATION_REC_SOURCE_INTENT));
		if (restart_mode == 7) {
			/* A failed exchange retains retirement; retry never touches a VM. */
			restart_mode = 0;
			assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9, &credentials, NULL) == 0);
			assert(restart_runs == 2 && restart_cleanups == 2 && queries == 1);
			assert(stops == 0 && destroys == 0);
			restart_mode = 7;
		}
		close(fd);
	}
	for (int scenario = 0; scenario < 9; scenario++) {
		char directory[] = "orphan.XXXXXX"; assert(mkdtemp(directory));
		int fd = open(directory, O_RDONLY | O_DIRECTORY); assert(fd >= 0);
		assert(migration_source_owner_at(fd, &binding, true) == 0);
		assert(migration_recovery_store_at(fd, &binding) == 0);
		struct migration_tls_credentials credentials = {0};
		retired = false; named_destroys = restart_runs = 0;
		restart_mode = scenario < 4 || scenario == 8 ? scenario : 0;
		mode = scenario == 4 ? 15 : scenario == 5 ? 13 : scenario == 6 ? 7 : 0;
		const int expected_errors[] = {0, EACCES, EIO, EACCES, ESTALE, ENOTTY, EBUSY, 0, EBUSY};
		assert(migration_prod_source_recover_restart_named(-1, fd, 7, 9,
		    &credentials, "orphan") == expected_errors[scenario]);
		assert(named_destroys == ((scenario >= 1 && scenario <= 3) || scenario == 8 ? 0 : 1));
		assert(restart_runs == (expected_errors[scenario] == 0 ? 1 : 0));
		close(fd);
	}
	const int errors[] = {0, EBUSY, ESTALE, EIO, EBUSY, ENXIO, 0, EBUSY,
	    EIO, ENOENT, EINVAL, EPROTO, 0, ENOTTY, EIO, ESTALE};
	for (mode = 0; mode < 16; mode++) {
		char directory[] = "intent.XXXXXX"; assert(mkdtemp(directory));
		int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
		struct migration_recovery_record expected = binding, record = binding;
		struct vmctx original = { .vmid = 7, .epoch = mode == 2 || mode == 6 ? 100 : 9 };
		struct vmctx *ctx = mode == 1 ? NULL : &original;
		queries = stops = destroys = identities = 0; fail_sync = false;
		retired = mode == 6;
		assert(migration_source_owner_at(fd, &record, true) == 0);
		if (mode != 9) assert(migration_recovery_store_at(fd, &record) == 0);
		if (mode == 10) expected.phase = MIGRATION_REC_DEST_STAGED;
		if (mode == 11) expected.source_certificate_sha256[0] ^= 1;
		if (mode == 12) {
			record.phase = MIGRATION_REC_SOURCE_RETIRED;
			assert(migration_recovery_store_at(fd, &record) == 0);
		}
		int error = migration_prod_source_finish_intent(&ctx, fd, &expected);
		assert(error == errors[mode]);
		uint16_t phase = 0;
		if (mode != 9) {
			assert(migration_recovery_load_at(fd, &binding, &phase) == 0);
			assert(phase == (error == 0 ? MIGRATION_REC_SOURCE_RETIRED : MIGRATION_REC_SOURCE_INTENT));
		}
		if (mode == 0 || mode == 7 || mode == 8) {
			assert(ctx == NULL && destroys == 1 && queries == 2);
		} else {
			assert(ctx == (mode == 1 ? NULL : &original));
		}
		if (mode == 6) assert(queries == 1 && identities == 0 && stops == 0 && destroys == 0);
		if (mode >= 9 && mode <= 12) assert(queries == 0 && destroys == 0);
		if (mode == 7 || mode == 8) {
			/* Crash/failed-publication retry: no context and no second destroy. */
			retired = true;
			assert(migration_prod_source_finish_intent(NULL, fd, &binding) == 0);
			assert(destroys == 1);
			assert(migration_recovery_load_at(fd, &binding, &phase) == 0 && phase == MIGRATION_REC_SOURCE_RETIRED);
		}
		close(fd);
	}
	/* Successful destruction plus failed join retains the context and INTENT.
	 * A retry must drain it without repeating destruction, before RETIRED. */
	{
		char directory[] = "join-intent.XXXXXX"; assert(mkdtemp(directory));
		int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
		struct vmctx original = { .vmid = 7, .epoch = 9 }, *ctx = &original;
		uint16_t phase;
		mode=0; retired=false; destroys=stops=0; join_error=EBUSY;
		int before=context_closes;
		assert(migration_source_owner_at(fd, &binding, true)==0);
		assert(migration_recovery_store_at(fd, &binding)==0);
		assert(migration_prod_source_finish_intent(&ctx, fd, &binding)==EBUSY);
		assert(ctx==NULL && destroys==1 && context_closes==before);
		assert(migration_recovery_load_at(fd, &binding, &phase)==0 && phase==MIGRATION_REC_SOURCE_INTENT);
		assert(migration_prod_source_finish_intent(NULL, fd, &binding)==EBUSY);
		join_error=0;
		assert(migration_prod_source_finish_intent(NULL, fd, &binding)==0);
		assert(destroys==1 && context_closes==before+1);
		assert(migration_recovery_load_at(fd, &binding, &phase)==0 && phase==MIGRATION_REC_SOURCE_RETIRED);
		close(fd);
	}
	assert(migration_prod_source_finish_intent(NULL, -1, NULL) == EINVAL);
	puts("PASS: durable INTENT binding, checked identity destruction, exact retirement witness, failed proof/publication retry and no disappearance inference");
}
