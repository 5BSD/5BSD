/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/capsicum.h>
#include <sys/wait.h>
#include "migration_recovery_execute.h"
#include "test-coverage.h"

#ifdef TEST_SOURCE_RESTART
#include "migration_source_owner.h"
struct vmctx { int unused; };
static bool exact_retirement;
static unsigned retirement_queries, named_destroys;
static int hypertrace_session_retired(uint16_t vmid, uint64_t epoch) {
	assert(vmid == 7 && epoch == 9); retirement_queries++;
	if (exact_retirement) return (0);
	errno = EBUSY; return (-1);
}
static int vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch) {
	(void)ctx; (void)vmid; (void)epoch; abort();
}
static void fbsdrun_retire_cpus_begin(void) {}
static int fbsdrun_retire_cpus_wait(void) { return (0); }
static void vm_close(struct vmctx *ctx) { assert(ctx != NULL); }
static int vm_destroy_request_checked(struct vmctx *ctx) { (void)ctx; abort(); }
static int hypertrace_retire_transport(void) { return (0); }
static int pci_vtdtr_checkpoint_stop(void) { abort(); }
static int vm_destroy_identity_request_checked(struct vmctx *ctx, uint16_t vmid, uint64_t epoch) {
	(void)ctx; (void)vmid; (void)epoch; abort();
}
static int vm_destroy_name_identity_checked(const char *name, uint16_t vmid, uint64_t epoch) {
	assert(strcmp(name, "orphan") == 0 && vmid == 7 && epoch == 9);
	named_destroys++; exact_retirement = true; return (0);
}
#include "source-restart.inc"
#endif

static atomic_bool fail_sync;
int __real_fsync(int);
int __wrap_fsync(int fd) {
	if (atomic_exchange(&fail_sync, false)) { errno = EIO; return (-1); }
	return (__real_fsync(fd));
}
struct executor {
	int fd, dirfd, mode, error, resumes;
	enum migration_recovery_destination observed;
	struct migration_recovery_run_state state;
	struct migration_tls_credentials credentials;
	struct migration_recovery_record expected;
};
static _Thread_local struct executor *current;
static _Thread_local int (*real_send)(void *, const void *, size_t);
static _Thread_local int (*real_recv)(void *, void *, size_t);
static int observe(void *arg, enum migration_recovery_destination *observed) {
	*observed = ((struct executor *)arg)->observed; return (0);
}
static int resume(void *arg) {
	struct executor *ep = arg;
	assert(ep->observed == MIGRATION_REC_VM_PAUSED); ep->resumes++;
	uint16_t phase;
	assert(migration_recovery_load_at(ep->dirfd, &ep->expected, &phase) == 0);
	assert(phase == MIGRATION_REC_DEST_RELEASED);
	if (ep->mode == 2) return (EIO);
	ep->observed = MIGRATION_REC_VM_RUNNING;
	if (ep->mode == 6) atomic_store(&fail_sync, true);
	return (0);
}
static const struct migration_recovery_run_ops ops = { observe, resume };
static int send_fault(void *arg, const void *buf, size_t len) {
	if (len == 40 && memcmp(buf, "HXR1", 4) == 0) {
		uint16_t phase;
		assert(migration_recovery_load_at(current->dirfd, &current->expected, &phase) == 0);
		assert(phase == MIGRATION_REC_DEST_RUNNING);
		if (current->mode == 4) return (EPIPE);
		if (current->mode == 5) { int e = real_send(arg, buf, len); return e ? e : EPIPE; }
		if (current->mode == 9) {
			uint8_t altered[40]; memcpy(altered, buf, 40); altered[8] ^= 1;
			return (real_send(arg, altered, 40));
		}
	}
	return (real_send(arg, buf, len));
}
static int recv_fault(void *arg, void *buf, size_t len) {
	int error = real_recv(arg, buf, len);
	if (error == 0 && len == 40 && current->mode == 8) ((uint8_t *)buf)[8] ^= 1;
	return (error);
}
static void *serve(void *arg) {
	struct executor *ep = arg; current = ep;
	struct migration_channel channel; struct migration_transport xp;
	assert(migration_channel_init(&channel, &xp, ep->fd, true, &ep->credentials, 1000) == 0);
	real_send = xp.xp_send; real_recv = xp.xp_recv;
	xp.xp_send = send_fault; xp.xp_recv = recv_fault;
	ep->error = migration_recovery_destination_run(&channel, &xp, ep->dirfd,
	    &ep->expected, &ops, ep, &ep->state);
	migration_channel_cleanup(&channel); close(ep->fd); return (NULL);
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
int main(int argc, char **argv) {
	bool sandbox = argc == 2 && strcmp(argv[1], "--capsicum") == 0;
	/* Invalid attempts must not retain the ACK status of a prior attempt. */
	struct migration_recovery_run_state invalid = { .ack_sent = true };
	assert(migration_recovery_destination_run(NULL, NULL, -1, NULL,
	    NULL, NULL, &invalid) == EINVAL && !invalid.ack_sent);
	struct migration_recovery_run_ops missing = { NULL, resume };
	invalid.ack_sent = true;
	assert(migration_recovery_destination_run(NULL, NULL, -1, NULL,
	    &missing, NULL, &invalid) == EINVAL && !invalid.ack_sent);
	missing.observe = observe; missing.resume = NULL; invalid.ack_sent = true;
	assert(migration_recovery_destination_run(NULL, NULL, -1, NULL,
	    &missing, NULL, &invalid) == EINVAL && !invalid.ack_sent);
	struct migration_tls_credentials src = credentials("source", "destination");
	struct migration_tls_credentials dst = credentials("destination", "source");
	struct migration_recovery_record binding = { .phase = MIGRATION_REC_SOURCE_INTENT,
	    .destination_vmid = 8, .destination_epoch = 10 };
	struct hypertrace_session_record stopped = { .vmid = 7, .epoch = 9,
	    .stop_token = 11, .features = HYPERTRACE_SESSION_FEATURES };
	assert(hypertrace_session_record_encode(binding.session, 40, &stopped) == 0);
	memset(binding.challenge, 1, 32); memset(binding.state_digest, 2, 32);
	memcpy(binding.source_certificate_sha256, dst.peer_certificate_sha256, 32);
	memcpy(binding.destination_certificate_sha256, src.peer_certificate_sha256, 32);
	for (int mode = 0; mode < 11; mode++) {
		char directory[] = "execute.XXXXXX"; assert(mkdtemp(directory));
		int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC); assert(fd >= 0);
		if (sandbox) {
			/* Each case starts without TLS initialization in the parent.
			 * Only the selected directory and credential fds cross the fence. */
			pid_t child = fork(); assert(child >= 0);
			if (child != 0) {
				int status;
				assert(waitpid(child, &status, 0) == child);
				assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
				close(fd);
				continue;
			}
			ht_test_coverage_start("recovery-capsicum", true);
			assert(cap_enter() == 0);
			assert(open("/", O_RDONLY | O_DIRECTORY) == -1 && errno == ECAPMODE);
		}

		struct migration_recovery_record record = binding;
		assert(migration_recovery_store_at(fd, &record) == 0);
		if (mode != 7
#ifdef TEST_SOURCE_RESTART
		    && mode != 10
#endif
		    ) {
			record.phase = MIGRATION_REC_SOURCE_RETIRED;
			assert(migration_recovery_store_at(fd, &record) == 0);
		}
		struct executor server = { .dirfd = fd, .mode = mode, .credentials = dst,
		    .expected = binding, .observed = mode == 3 ? MIGRATION_REC_VM_UNAVAILABLE :
		    mode == 1 ? MIGRATION_REC_VM_RUNNING : MIGRATION_REC_VM_PAUSED };
		server.expected.phase = MIGRATION_REC_DEST_STAGED;
		record = server.expected;
		assert(migration_recovery_store_at(fd, &record) == 0);
		if (mode == 1) {
			record.phase = MIGRATION_REC_DEST_RELEASED; assert(migration_recovery_store_at(fd, &record) == 0);
			record.phase = MIGRATION_REC_DEST_RUNNING; assert(migration_recovery_store_at(fd, &record) == 0);
			/* RUNNING cannot precede source release authorization. */
			record = binding; record.phase = MIGRATION_REC_SOURCE_RELEASED;
			assert(migration_recovery_store_at(fd, &record) == 0);
		}
#ifdef TEST_SOURCE_RESTART
		assert(migration_source_owner_at(fd, &binding, true) == 0);
		exact_retirement = mode != 7 && mode != 10;
		named_destroys = 0;
		retirement_queries = 0;
#endif
		bool retry = mode == 4 || mode == 5 || mode == 6 || mode == 9;
		for (int attempt = 0; attempt < (retry ? 2 : 1); attempt++) {
			int sockets[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
			server.fd = sockets[1]; pthread_t thread;
			assert(pthread_create(&thread, NULL, serve, &server) == 0);
#ifdef TEST_SOURCE_RESTART
			int error = mode == 10 ?
			    migration_prod_source_recover_restart_named(sockets[0], fd, 7, 9, &src, "orphan") :
			    migration_prod_source_recover_restart_named(sockets[0], fd, 7, 9, &src, NULL);
#else
			struct migration_channel channel; struct migration_transport xp;
			assert(migration_channel_init(&channel, &xp, sockets[0], false, &src, 1000) == 0);
			int error = migration_recovery_source_run(&channel, &xp, fd, &binding);
			migration_channel_cleanup(&channel);
#endif
			close(sockets[0]);
			assert(pthread_join(thread, NULL) == 0);
			uint16_t source_phase, dest_phase;
			assert(migration_recovery_load_at(fd, &binding, &source_phase) == 0);
			assert(migration_recovery_load_at(fd, &server.expected, &dest_phase) == 0);
			if (mode < 2 || mode == 10 || attempt == 1) {
				assert(error == 0 && server.error == 0 && server.state.ack_sent);
				assert(source_phase == MIGRATION_REC_SOURCE_CONFIRMED && dest_phase == MIGRATION_REC_DEST_RUNNING);
			} else {
				assert(mode == 5 ? error == 0 : error != 0);
				assert(mode == 9 ? server.error == 0 : server.error != 0);
				assert(source_phase == (mode == 5 ? MIGRATION_REC_SOURCE_CONFIRMED :
				    mode == 7 ? MIGRATION_REC_SOURCE_INTENT : MIGRATION_REC_SOURCE_RELEASED));
				if (mode == 2 || mode == 6) assert(dest_phase == MIGRATION_REC_DEST_RELEASED);
				if (mode == 3 || mode == 7 || mode == 8) assert(dest_phase == MIGRATION_REC_DEST_STAGED);
			}
			if (retry) server.mode = 0;
		}
		assert(server.resumes == (mode == 1 || mode == 3 || mode == 7 || mode == 8 ? 0 : 1));
		if (mode == 2) {
			assert(server.state.resume_uncertain);
			assert(migration_recovery_destination_run(NULL, NULL, fd, &server.expected,
			    &ops, &server, &server.state) == EBUSY);
		}
#ifdef TEST_SOURCE_RESTART
		assert(retirement_queries == (mode == 7 ? 1U : mode == 10 ? 3U : 0U));
		assert(named_destroys == (mode == 10 ? 1U : 0U));
#endif
		close(fd);
		if (sandbox) { ht_test_coverage_finish(); _exit(0); }
	}
	close(src.certificate_fd); close(src.private_key_fd); close(src.trust_fd);
	close(dst.certificate_fd); close(dst.private_key_fd); close(dst.trust_fd);
	if (sandbox) puts("PASS: all recovery cases ran after Capsicum entry with absolute opens denied");
	puts("PASS: TLS recovery execution, durable ordering, lost ACK retries, one resume, uncertain-resume quarantine and no INTENT inference");
}
