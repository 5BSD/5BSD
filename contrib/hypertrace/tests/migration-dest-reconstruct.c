/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Actual production destination adapter slices (migration_session.c) for
 * image preservation and controller-loss reconstruction, driven through
 * real private journals and real mutual-TLS HMX1/HXR1 recovery against the
 * real source executor. Only VM/kernel primitives are substituted: guest
 * RAM is process memory, identities and the kernel retirement witness are a
 * table, and resume/commit record their calls. No VM, device, module or
 * daemon is used.
 */
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <pthread.h>
#include "migration_session.h"
#include "migration_recovery_execute.h"
#include "migration_source_owner.h"
#include "migration_dest_image.h"
#include "migration_snapshot.h"
#include "test-coverage.h"

#define LOWMEM (2U * MIGRATION_DEST_IMAGE_CHUNK)
#define HIGHMEM (16U * 4096U)
#define HIGHBASE (1ULL << 32)

struct vmctx {
	uint16_t vmid;
	uint64_t epoch;
	uint64_t highmem;
	uint8_t *low, *high;
};
struct pci_devinst { int unused; };
static struct pci_devinst device;

static bool tracing = true, startup_held = true, fail_commit;
static int resume_calls, commit_calls, destroy_calls, witness_calls;
static const uint8_t *committed_blob;
static size_t committed_length;
#define MAXLIVE 8
static uint16_t live_vmid[MAXLIVE];
static uint64_t live_epoch[MAXLIVE];

static bool hypertrace_initialized(void) { return (tracing); }
static bool checkpoint_restore_startup_held(void) { return (startup_held); }
static int vm_migrate_fresh_resume(struct vmctx *ctx, struct pci_devinst *d,
    const uint8_t record[40]) {
	(void)ctx; assert(d == &device && record != NULL && startup_held);
	resume_calls++; startup_held = false; return (0);
}
static int vm_migrate_resume(struct vmctx *ctx) { (void)ctx; abort(); }
static int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch) {
	*vmid = ctx->vmid; *epoch = ctx->epoch; return (0);
}
static void *vm_map_gpa(struct vmctx *ctx, uint64_t gpa, size_t length) {
	if (gpa + length <= LOWMEM) return (ctx->low + gpa);
	if (gpa >= HIGHBASE && gpa + length <= HIGHBASE + ctx->highmem)
		return (ctx->high + (gpa - HIGHBASE));
	return (NULL);
}
static uint64_t vm_get_lowmem_size(struct vmctx *ctx) { (void)ctx; return (LOWMEM); }
static uint64_t vm_get_highmem_size(struct vmctx *ctx) { return (ctx->highmem); }
static uint64_t vm_get_highmem_base(struct vmctx *ctx) { (void)ctx; return (HIGHBASE); }
static int hypertrace_session_retired(uint16_t vmid, uint64_t epoch) {
	witness_calls++;
	for (int i = 0; i < MAXLIVE; i++)
		if (live_vmid[i] == vmid && live_epoch[i] == epoch) {
			errno = EBUSY; return (-1);
		}
	return (0);
}
static int vm_destroy_name_identity_checked(const char *name, uint16_t vmid,
    uint64_t epoch) {
	destroy_calls++;
	assert(strcmp(name, "orphan") == 0);
	for (int i = 0; i < MAXLIVE; i++)
		if (live_vmid[i] == vmid && live_epoch[i] == epoch) {
			live_vmid[i] = 0; live_epoch[i] = 0; return (0);
		}
	errno = ESTALE; return (-1);
}
static int vm_migrate_fresh_commit_state(struct vmctx *ctx, const uint8_t *blob,
    size_t length, struct pci_devinst **d) {
	(void)ctx; commit_calls++;
	if (fail_commit) return (EIO);
	committed_blob = blob; committed_length = length; *d = &device; return (0);
}
static const struct migration_dest_ops migration_prod_dest_ops = {0};
#include "dest-reconstruct.inc"

static void set_live(int slot, uint16_t vmid, uint64_t epoch) {
	live_vmid[slot] = vmid; live_epoch[slot] = epoch;
}

static struct migration_tls_credentials credentials(const char *name, const char *peer) {
	struct migration_tls_credentials c; char path[64];
	snprintf(path, sizeof(path), "%s.pem", name); c.certificate_fd = open(path, O_RDONLY);
	snprintf(path, sizeof(path), "%s.key", name); c.private_key_fd = open(path, O_RDONLY);
	snprintf(path, sizeof(path), "%s.pem", peer); c.trust_fd = open(path, O_RDONLY);
	snprintf(path, sizeof(path), "%s.pin", peer); int fd = open(path, O_RDONLY);
	assert(c.certificate_fd >= 0 && c.private_key_fd >= 0 && c.trust_fd >= 0 && fd >= 0);
	assert(read(fd, c.peer_certificate_sha256, 32) == 32); close(fd); return (c);
}

struct source_run {
	int fd, dirfd, error;
	struct migration_tls_credentials credentials;
	struct migration_recovery_record record;
};
static void *source_thread(void *arg) {
	struct source_run *run = arg;
	struct migration_channel channel; struct migration_transport xp;
	run->error = migration_channel_init(&channel, &xp, run->fd, false,
	    &run->credentials, 2000);
	if (run->error == 0) {
		run->error = migration_recovery_source_run(&channel, &xp, run->dirfd,
		    &run->record);
		migration_channel_cleanup(&channel);
	}
	close(run->fd);
	return (NULL);
}
/* One real TLS recovery connection: source executor versus the actual
 * production destination recovery adapter of the reconstructed owner. */
static int recover(struct migration_prod_dest *owner, int dirfd,
    const struct migration_tls_credentials *src, const struct migration_tls_credentials *dst,
    const struct migration_recovery_record *source_record, int *source_error) {
	int sockets[2]; pthread_t thread;
	struct source_run run = { .dirfd = dirfd, .credentials = *src, .record = *source_record };
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	run.fd = sockets[0];
	assert(pthread_create(&thread, NULL, source_thread, &run) == 0);
	int error = migration_prod_dest_recover_release(owner, sockets[1], dst);
	close(sockets[1]);
	assert(pthread_join(thread, NULL) == 0);
	*source_error = run.error;
	return (error);
}

static uint8_t *blob;
static size_t blob_length;
static int other_dirfd = -1;	/* a different private directory (EXDEV) */
static struct migration_recovery_record source_record, dest_record;

static void make_blob(void) {
	struct hypertrace_session_record stopped = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	blob_length = MIGRATE_BLOB_HDR + 300 + 200 + HYPERTRACE_SESSION_RECORD_SIZE;
	blob = malloc(blob_length); assert(blob);
	memset(blob, 0, blob_length);
	le64enc(blob, 300); le64enc(blob + 8, 200);
	for (size_t i = MIGRATE_BLOB_HDR; i < MIGRATE_BLOB_HDR + 500; i++)
		blob[i] = (uint8_t)(i * 31 + 7);
	assert(hypertrace_session_record_encode(blob + MIGRATE_BLOB_HDR + 500,
	    HYPERTRACE_SESSION_RECORD_SIZE, &stopped) == 0);
}

static void make_vm(struct vmctx *vm, uint16_t vmid, uint64_t epoch, uint8_t seed) {
	vm->vmid = vmid; vm->epoch = epoch; vm->highmem = HIGHMEM;
	vm->low = malloc(LOWMEM); vm->high = malloc(HIGHMEM);
	assert(vm->low && vm->high);
	for (size_t i = 0; i < LOWMEM; i++) vm->low[i] = (uint8_t)(i * 3 + seed);
	for (size_t i = 0; i < HIGHMEM; i++) vm->high[i] = (uint8_t)(i * 11 + seed);
}
static void free_vm(struct vmctx *vm) { free(vm->low); free(vm->high); }

static bool image_present(int dirfd) {
	struct migration_recovery_record r; struct migration_dest_geometry g; uint64_t d;
	return (migration_dest_image_header_at(dirfd, dest_record.challenge, &r, &g, &d) == 0);
}

static int scenario(const struct migration_tls_credentials *src,
    const struct migration_tls_credentials *dst, int dirfd) {
	struct vmctx original, successor[8], refused[8];
	struct migration_session_config config = { .recovery_enabled = true,
	    .recovery_dirfd = dirfd, .tls_credentials = dst };
	struct migration_dest_result result;
	struct migration_prod_reconstruct *state = NULL;
	struct migration_prod_dest *owner = NULL;
	struct migration_commit_binding binding;
	int source_error, checks = 0;

	memset(live_vmid, 0, sizeof(live_vmid)); memset(live_epoch, 0, sizeof(live_epoch));
	resume_calls = commit_calls = destroy_calls = witness_calls = 0;
	startup_held = true; tracing = true; fail_commit = false;
	make_vm(&original, 8, 10, 1);
	set_live(0, 8, 10);

	/* ---- Original destination: preserve before STAGED. ---- */
	struct migration_prod_dest *dst_owner = calloc(1, sizeof(*dst_owner));
	assert(dst_owner);
	dst_owner->ctx = &original; dst_owner->controller_fd = -1;
	dst_owner->recovery_dirfd = fcntl(dirfd, F_DUPFD_CLOEXEC, 0);
	dst_owner->dev_blob = malloc(blob_length); memcpy(dst_owner->dev_blob, blob, blob_length);
	dst_owner->dev_len = blob_length;
	dst_owner->fresh_device = &device;
	dst_owner->recovery = dest_record;
	memcpy(dst_owner->fresh_record, dest_record.session, 40);
	memset(&binding, 0, sizeof(binding));
	binding.destination_vmid = 8; binding.destination_epoch = 10;
	memcpy(binding.challenge, dest_record.challenge, 32);
	memcpy(binding.state_digest, dest_record.state_digest, 32);
	/* Uncommitted state, changed challenge or digest cannot be preserved. */
	assert(prod_dest_preserve(dst_owner, &binding) == EPROTO);
	dst_owner->committed = true;
	binding.challenge[3] ^= 1;
	assert(prod_dest_preserve(dst_owner, &binding) == EPROTO);
	binding.challenge[3] ^= 1; binding.state_digest[0] ^= 1;
	assert(prod_dest_preserve(dst_owner, &binding) == EPROTO);
	binding.state_digest[0] ^= 1;
	assert(!image_present(dirfd) && dst_owner->controller_fd < 0);
	assert(prod_dest_preserve(dst_owner, &binding) == 0);
	assert(dst_owner->controller_fd >= 0 && image_present(dirfd));
	assert(prod_dest_preserve(dst_owner, &binding) == EPROTO);
	checks += 5;
	/* The core publishes STAGED only after the image; the source then
	 * records INTENT (retirement started) for the accepted COMMIT. */
	struct migration_recovery_record staged = dest_record;
	assert(migration_recovery_store_at(dirfd, &staged) == 0);
	struct migration_recovery_record intent = source_record;
	assert(migration_recovery_store_at(dirfd, &intent) == 0);

	/* While the original controller lives, reconstruction is refused. */
	make_vm(&successor[0], 8, 11, 0x40);
	assert(migration_prod_dest_reconstruct_begin(&successor[0], dirfd,
	    dest_record.challenge, "orphan", &state) == EBUSY && state == NULL);
	assert(witness_calls == 0 && destroy_calls == 0);
	checks++;

	/* ---- Controller loss: the process dies; its VM object persists. ---- */
	close(dst_owner->recovery_dirfd);
	prod_dest_free(dst_owner, -1);

	tracing = false;
	assert(migration_prod_dest_reconstruct_begin(&successor[0], dirfd,
	    dest_record.challenge, NULL, &state) == EOPNOTSUPP);
	tracing = true; startup_held = false;
	assert(migration_prod_dest_reconstruct_begin(&successor[0], dirfd,
	    dest_record.challenge, NULL, &state) == EBUSY);
	startup_held = true;
	/* Previous incarnation still live and no name: refuse. */
	assert(migration_prod_dest_reconstruct_begin(&successor[0], dirfd,
	    dest_record.challenge, NULL, &state) == EBUSY && state == NULL);
	assert(witness_calls == 1 && destroy_calls == 0);
	checks += 3;

	/* Each refused prepared() consumes its admission; every new admission
	 * must first retire the previously published incarnation. */
	uint64_t epoch = 11;
	struct { int error; int kind; } refusals[] = {
		{ EXDEV, 0 }, { EACCES, 1 }, { ESTALE, 2 }, { ESTALE, 3 },
		{ EPROTO, 4 }, { EIO, 5 }, { EBUSY, 6 }, { EOPNOTSUPP, 7 },
	};
	char stem[67], path[128];
	migration_dest_stem(dest_record.challenge, stem);
	snprintf(path, sizeof(path), "%s.image", stem);
	free_vm(&successor[0]);
	for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
		struct vmctx *vm = &refused[i];
		make_vm(vm, 8, epoch, (uint8_t)(0x40 + i));
		/* First admission destroys the original orphan by exact identity. */
		assert(migration_prod_dest_reconstruct_begin(vm, dirfd,
		    dest_record.challenge, i == 0 ? "orphan" : NULL, &state) == 0);
		assert(state != NULL);
		if (i == 0) assert(destroy_calls == 1 && live_vmid[0] == 0);
		struct migration_session_config c = config;
		int corrupted = -1;
		uint8_t byte = 0;
		switch (refusals[i].kind) {
		case 0: c.recovery_dirfd = other_dirfd; break;
		case 1: c.tls_credentials = NULL; break;
		case 2: vm->highmem -= 4096; break;
		case 3: vm->epoch++; break;
		case 4:
			corrupted = openat(dirfd, path, O_RDWR);
			assert(corrupted >= 0 && pread(corrupted, &byte, 1, 256 + 4096) == 1);
			byte ^= 0x80; assert(pwrite(corrupted, &byte, 1, 256 + 4096) == 1);
			break;
		case 5: fail_commit = true; break;
		case 6: startup_held = false; break;
		default: tracing = false; break;
		}
		owner = NULL;
		assert(migration_prod_dest_reconstruct_prepared(vm, state, &c, &result,
		    &owner) == refusals[i].error);
		assert(owner == NULL && !result.retained && result.phase == MIGRATION_PHASE_FAILED);
		state = NULL;
		if (corrupted >= 0) {
			byte ^= 0x80; assert(pwrite(corrupted, &byte, 1, 256 + 4096) == 1);
			close(corrupted);
		}
		if (refusals[i].kind == 2) vm->highmem += 4096;
		fail_commit = false; startup_held = true; tracing = true;
		/* The failed successor exits; its VM object was reinitialized or
		 * destroyed, so its exact lifetime is no longer live. */
		epoch++;
		checks++;
	}
	/* An abandoned admission releases its controller for the next one. */
	make_vm(&successor[4], 8, epoch, 0x50);
	assert(migration_prod_dest_reconstruct_begin(&successor[4], dirfd,
	    dest_record.challenge, NULL, &state) == 0);
	migration_prod_dest_reconstruct_abandon(state); state = NULL;
	epoch++;
	free_vm(&successor[4]);
	/* A still-live failed successor blocks the next admission. */
	make_vm(&successor[5], 8, epoch, 0x60);
	set_live(1, 8, epoch - 1);
	assert(migration_prod_dest_reconstruct_begin(&successor[5], dirfd,
	    dest_record.challenge, NULL, &state) == EBUSY);
	set_live(1, 0, 0);
	checks += 2;

	/* ---- Successful reconstruction. ---- */
	assert(migration_prod_dest_reconstruct_begin(&successor[5], dirfd,
	    dest_record.challenge, NULL, &state) == 0);
	struct migration_dest_successor published;
	uint8_t digest[32];
	assert(migration_dest_binding_digest(&dest_record, digest) == 0);
	assert(migration_dest_successor_load_at(dirfd, dest_record.challenge,
	    digest, &published) == 0);
	assert(published.current_epoch == epoch && published.generation >= 10);
	int commits_before = commit_calls;
	assert(migration_prod_dest_reconstruct_prepared(&successor[5], state,
	    &config, &result, &owner) == 0);
	state = NULL;
	assert(owner && result.retained && result.phase == MIGRATION_PHASE_RECOVERY);
	assert(commit_calls == commits_before + 1 && committed_length == blob_length);
	assert(memcmp(committed_blob, blob, blob_length) == 0);
	assert(memcmp(successor[5].low, original.low, LOWMEM) == 0);
	assert(memcmp(successor[5].high, original.high, HIGHMEM) == 0);
	assert(owner->reconstructed && owner->incarnation_epoch == epoch && !owner->running);
	/* The owner keeps the original attempt binding for HMX1. */
	assert(owner->recovery.destination_vmid == 8 && owner->recovery.destination_epoch == 10);
	bool running, uncertain, acknowledged;
	migration_prod_dest_recovery_status(owner, &running, &uncertain, &acknowledged);
	assert(!running && !uncertain && !acknowledged);
	checks++;

	/* Source still at INTENT: release cannot be authorized; no resume. */
	int error = recover(owner, dirfd, src, dst, &source_record, &source_error);
	assert(error != 0 && source_error == EBUSY && resume_calls == 0 && startup_held);
	checks++;
	/* The reconstructed owner validates its successor lifetime, not the
	 * original destination lifetime. */
	successor[5].epoch = 10; successor[5].vmid = 8;
	error = recover(owner, dirfd, src, dst, &source_record, &source_error);
	assert(error == ESTALE && resume_calls == 0);
	successor[5].epoch = epoch;
	checks++;

	/* Source finishes retirement durably (RETIRED); real TLS recovery then
	 * persists RELEASED/RUNNING and resumes exactly once. */
	struct migration_recovery_record retired = source_record;
	retired.phase = MIGRATION_REC_SOURCE_RETIRED;
	assert(migration_recovery_store_at(dirfd, &retired) == 0);
	error = recover(owner, dirfd, src, dst, &source_record, &source_error);
	assert(error == 0 && source_error == 0 && resume_calls == 1 && !startup_held);
	uint16_t phase;
	assert(migration_recovery_load_at(dirfd, &source_record, &phase) == 0 &&
	    phase == MIGRATION_REC_SOURCE_CONFIRMED);
	assert(migration_recovery_load_at(dirfd, &dest_record, &phase) == 0 &&
	    phase == MIGRATION_REC_DEST_RUNNING);
	migration_prod_dest_recovery_status(owner, &running, &uncertain, &acknowledged);
	assert(running && !uncertain && acknowledged);
	/* The image is obsolete after RELEASED plus resume. */
	assert(!image_present(dirfd));
	checks++;
	/* A lost ACK is recovered by reconnecting; never a second resume. */
	error = recover(owner, dirfd, src, dst, &source_record, &source_error);
	assert(error == 0 && source_error == 0 && resume_calls == 1);
	checks++;
	/* After RUNNING no further successor may be admitted. */
	struct vmctx late;
	make_vm(&late, 9, 99, 0x70);
	close(owner->controller_fd); owner->controller_fd = -1;
	startup_held = true;	/* a new, still-fenced successor process */
	assert(migration_prod_dest_reconstruct_begin(&late, dirfd,
	    dest_record.challenge, NULL, &state) == ENOENT && state == NULL);
	checks++;
	free_vm(&late);

	close(owner->recovery_dirfd); free(owner->dev_blob); free(owner);
	free_vm(&original);
	for (size_t i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++)
		free_vm(&refused[i]);
	free_vm(&successor[5]);
	return (checks);
}

/* RELEASED is persisted before any resume: such an attempt is quarantined. */
static void released_quarantine(int dirfd) {
	struct vmctx original, next;
	struct migration_prod_reconstruct *state = NULL;
	struct migration_commit_binding binding = { .destination_vmid = 8,
	    .destination_epoch = 10 };
	make_vm(&original, 8, 10, 1);
	make_vm(&next, 8, 11, 2);
	memset(live_vmid, 0, sizeof(live_vmid));
	struct migration_prod_dest *d = calloc(1, sizeof(*d));
	d->ctx = &original; d->controller_fd = -1; d->recovery_dirfd = dirfd;
	d->dev_blob = malloc(blob_length); memcpy(d->dev_blob, blob, blob_length);
	d->dev_len = blob_length; d->fresh_device = &device; d->committed = true;
	d->recovery = dest_record;
	memcpy(binding.challenge, dest_record.challenge, 32);
	memcpy(binding.state_digest, dest_record.state_digest, 32);
	assert(prod_dest_preserve(d, &binding) == 0);
	struct migration_recovery_record r = dest_record;
	assert(migration_recovery_store_at(dirfd, &r) == 0);
	r.phase = MIGRATION_REC_DEST_RELEASED;
	assert(migration_recovery_store_at(dirfd, &r) == 0);
	prod_dest_free(d, -1);
	witness_calls = 0;
	assert(migration_prod_dest_reconstruct_begin(&next, dirfd,
	    dest_record.challenge, NULL, &state) == ENOTRECOVERABLE && state == NULL);
	assert(witness_calls == 0);
	free_vm(&original); free_vm(&next);
}

int main(int argc, char **argv) {
	bool sandbox = argc == 2 && strcmp(argv[1], "--capsicum") == 0;
	struct migration_tls_credentials src = credentials("source", "destination");
	struct migration_tls_credentials dst = credentials("destination", "source");
	struct hypertrace_session_record stopped = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	SHA256_CTX hash;
	make_blob();
	memset(&dest_record, 0, sizeof(dest_record));
	dest_record.phase = MIGRATION_REC_DEST_STAGED;
	dest_record.destination_vmid = 8; dest_record.destination_epoch = 10;
	assert(hypertrace_session_record_encode(dest_record.session, 40, &stopped) == 0);
	for (int i = 0; i < 32; i++) dest_record.challenge[i] = (uint8_t)(i + 1);
	SHA256_Init(&hash); SHA256_Update(&hash, blob, blob_length);
	SHA256_Final(dest_record.state_digest, &hash);
	memcpy(dest_record.source_certificate_sha256, dst.peer_certificate_sha256, 32);
	memcpy(dest_record.destination_certificate_sha256, src.peer_certificate_sha256, 32);
	source_record = dest_record;
	source_record.phase = MIGRATION_REC_SOURCE_INTENT;

	char directory[] = "reconstruct.XXXXXX"; assert(mkdtemp(directory));
	int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(dirfd >= 0);
	char quarantine[] = "released.XXXXXX"; assert(mkdtemp(quarantine));
	char other[] = "other.XXXXXX"; assert(mkdtemp(other));
	other_dirfd = open(other, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	assert(other_dirfd >= 0);
	int qfd = open(quarantine, O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(qfd >= 0);
	if (sandbox) {
		fflush(stdout);
		pid_t child = fork(); assert(child >= 0);
		if (child != 0) {
			int status;
			assert(waitpid(child, &status, 0) == child);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			puts("PASS: reconstruction and TLS recovery ran after Capsicum entry");
			return (0);
		}
		ht_test_coverage_start("dest-reconstruct-capsicum", true);
		assert(cap_enter() == 0);
		assert(open("/", O_RDONLY | O_DIRECTORY) == -1 && errno == ECAPMODE);
	}
	int checks = scenario(&src, &dst, dirfd);
	released_quarantine(qfd);
	printf("PASS: %d production reconstruction checks; RELEASED quarantine\n", checks + 1);
	if (sandbox) { fflush(stdout); ht_test_coverage_finish(); _exit(0); }
	return (0);
}
