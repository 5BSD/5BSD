/* SPDX-License-Identifier: BSD-2-Clause */
#include "test-coverage.h"
#include <sys/socket.h>
#include <sys/capsicum.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "migration_session.h"
#include "migration_credentials.h"

struct vmctx { int unused; };
struct migration_prod_dest { bool running, uncertain, ack; };
static struct migration_prod_dest owner;
static int scenario, initial_fd, listen_fd;
static atomic_int resumes, calls;
static atomic_bool returned;
static bool fail_thread, sandbox;
static int clients[4], client_count, client_next;
static char socket_path[104];
static struct migration_tls_credentials credentials;
static struct migration_session_config config;
static struct vmctx ctx;
static int owned_credentials[3];
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *p) {
	return (fail_thread ? EAGAIN : __real_pthread_create(t, a, f, p));
}
int migration_prod_dest_serve_prepared(struct vmctx *v, int fd,
    const struct migration_session_config *c, struct migration_dest_result *r,
    struct migration_prod_dest **out) {
	(void)v; assert(fd == initial_fd); atomic_fetch_add(&calls, 1);
	assert(c->tls_credentials != &credentials);
	assert(c->tls_credentials->peer_certificate_sha256[0] == 9);
	owned_credentials[0] = c->tls_credentials->certificate_fd;
	owned_credentials[1] = c->tls_credentials->private_key_fd;
	owned_credentials[2] = c->tls_credentials->trust_fd;
	assert(owned_credentials[0] != credentials.certificate_fd);
	assert(owned_credentials[1] != credentials.private_key_fd);
	assert(owned_credentials[2] != credentials.trust_fd);
	memset(r, 0, sizeof(*r));
	if (scenario == 0) { *out = NULL; return EIO; }
	*out = &owner; owner.running = scenario == 2;
	r->resumed = owner.running; r->retained = !owner.running;
	return owner.running ? 0 : ETIMEDOUT;
}
/* Reconstruction source: consumes its state exactly once, or is abandoned
 * when receiver setup fails before the source runs. */
struct migration_prod_reconstruct { int id; int consumed, abandoned; };
static atomic_int reconstruct_calls;
int migration_prod_dest_reconstruct_prepared(struct vmctx *v,
    struct migration_prod_reconstruct *state, const struct migration_session_config *c,
    struct migration_dest_result *r, struct migration_prod_dest **out) {
	(void)v; atomic_fetch_add(&reconstruct_calls, 1);
	assert(state->consumed == 0 && state->abandoned == 0); state->consumed++;
	assert(c->tls_credentials != &credentials && c->recovery_enabled);
	owned_credentials[0] = c->tls_credentials->certificate_fd;
	owned_credentials[1] = c->tls_credentials->private_key_fd;
	owned_credentials[2] = c->tls_credentials->trust_fd;
	memset(r, 0, sizeof(*r));
	if (state->id == 0) { *out = NULL; return (EIO); }
	*out = &owner; owner.running = false; r->retained = true;
	r->phase = MIGRATION_PHASE_RECOVERY; return (0);
}
void migration_prod_dest_reconstruct_abandon(struct migration_prod_reconstruct *state) {
	assert(state->consumed == 0 && state->abandoned == 0); state->abandoned++;
}
int migration_prod_dest_recover_release(struct migration_prod_dest *o, int fd,
    const struct migration_tls_credentials *c) {
	assert(o == &owner && c->certificate_fd == owned_credentials[0]);
	for (unsigned i = 0; i < 3; i++) {
		int flags = fcntl(owned_credentials[i], F_GETFD);
		assert(flags >= 0 && (flags & FD_CLOEXEC) != 0);
	}
	char op; assert(read(fd, &op, 1) == 1);
	int error = 0;
	if (op == 'F') error = EACCES;
	else if (op == 'Q') { o->uncertain = true; error = EIO; }
	else if (o->uncertain) { op = 'B'; error = EBUSY; }
	else if (op == 'R') {
		assert(!o->running); o->running = true; atomic_fetch_add(&resumes, 1);
		error = EPIPE; /* Running despite lost ACK. */
	} else { assert(op == 'A' && o->running); o->ack = true; }
	assert(write(fd, &op, 1) == 1); return error;
}
void migration_prod_dest_recovery_status(const struct migration_prod_dest *o,
    bool *running, bool *uncertain, bool *ack) {
	*running = o->running; *uncertain = o->uncertain; *ack = o->ack;
}
static int connect_client(void) {
	int fd = socket(AF_UNIX, SOCK_STREAM, 0); assert(fd >= 0);
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	strlcpy(address.sun_path, socket_path, sizeof(address.sun_path));
	assert(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	return fd;
}
static void request(char op, char expected) {
	int fd;
	if (sandbox) {
		assert(client_next < client_count);
		fd = clients[client_next++];
	} else
		fd = connect_client();
	assert(write(fd, &op, 1) == 1);
	char reply; assert(read(fd, &reply, 1) == 1 && reply == expected); close(fd);
}
static void *recover_paused(void *unused) {
	(void)unused; request('F', 'F'); request('R', 'R'); return NULL;
}
static void *managed(void *unused) {
	(void)unused; struct migration_dest_result result;
	int error = migration_prod_dest_serve_managed(&ctx, initial_fd, listen_fd, &config, &result);
	assert(error == 0 && result.resumed); atomic_store(&returned, true); return NULL;
}
int main(int argc, char **argv) {
	sandbox = argc == 2 && strcmp(argv[1], "--capsicum") == 0;
	char directory[] = "receiver.XXXXXX"; assert(mkdtemp(directory));
	snprintf(socket_path, sizeof(socket_path), "%s/socket", directory);
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0); assert(listen_fd >= 0);
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	strlcpy(address.sun_path, socket_path, sizeof(address.sun_path));
	assert(bind(listen_fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	assert(migration_recovery_listener_check(listen_fd) == EINVAL);
	assert(listen(listen_fd, 8) == 0 && migration_recovery_listener_check(listen_fd) == 0);
	credentials.certificate_fd = open("/dev/null", O_RDONLY);
	credentials.private_key_fd = open("/dev/null", O_RDONLY);
	credentials.trust_fd = open("/dev/null", O_RDONLY);
	credentials.peer_certificate_sha256[0] = 9;
	config.recovery_enabled = true; config.tls_credentials = &credentials;
	int old_flags = fcntl(listen_fd, F_GETFL);
	struct migration_dest_result result;
	fail_thread = true;
	assert(migration_prod_dest_serve_managed(&ctx, initial_fd, listen_fd, &config, &result) == EAGAIN);
	assert(atomic_load(&calls) == 0 && fcntl(listen_fd, F_GETFL) == old_flags);
	/* Reconstruction: setup failures abandon (never consume) the admitted
	 * state; a source failure consumes it and leaves no owner or worker. */
	struct migration_prod_reconstruct failed = { .id = 1 };
	assert(migration_prod_dest_reconstruct_managed(&ctx, &failed, listen_fd, &config, &result) == EAGAIN);
	assert(failed.abandoned == 1 && failed.consumed == 0 && atomic_load(&reconstruct_calls) == 0);
	assert(fcntl(listen_fd, F_GETFL) == old_flags);
	fail_thread = false;
	struct migration_prod_reconstruct invalid = { .id = 1 };
	assert(migration_prod_dest_reconstruct_managed(&ctx, &invalid, listen_fd, NULL, &result) == EINVAL);
	assert(invalid.abandoned == 1);
	struct migration_prod_reconstruct unlistened = { .id = 1 };
	int plain = socket(AF_UNIX, SOCK_STREAM, 0); assert(plain >= 0);
	assert(migration_prod_dest_reconstruct_managed(&ctx, &unlistened, plain, &config, &result) == EINVAL);
	assert(unlistened.abandoned == 1 && atomic_load(&reconstruct_calls) == 0); close(plain);
	struct migration_prod_reconstruct corrupt = { .id = 0 };
	assert(migration_prod_dest_reconstruct_managed(&ctx, &corrupt, listen_fd, &config, &result) == EIO);
	assert(corrupt.consumed == 1 && corrupt.abandoned == 0 && atomic_load(&reconstruct_calls) == 1);
	assert(fcntl(listen_fd, F_GETFL) == old_flags && !result.resumed);
	for (unsigned i = 0; i < 3; i++) assert(fcntl(owned_credentials[i], F_GETFD) == -1 && errno == EBADF);
	for (scenario = 0; scenario < 5; scenario++) {
		client_next = 0;
		client_count = scenario == 0 ? 0 : scenario == 1 || scenario == 4 ? 4 : 2;
		if (sandbox)
			for (int i = 0; i < client_count; i++) clients[i] = connect_client();
		pid_t child = fork(); assert(child >= 0);
		if (child == 0) {
			ht_test_coverage_start(sandbox ? "receiver-capsicum" : "receiver", true);
			pthread_t thread;
			if (sandbox) {
				assert(cap_enter() == 0);
				assert(open("/", O_RDONLY | O_DIRECTORY) == -1 && errno == ECAPMODE);
				fail_thread = true;
				assert(migration_prod_dest_serve_managed(&ctx, initial_fd, listen_fd,
				    &config, &result) == EAGAIN);
				assert(atomic_load(&calls) == 0 && fcntl(listen_fd, F_GETFL) == old_flags);
				fail_thread = false;
			}
			if (scenario == 0) {
				assert(migration_prod_dest_serve_managed(&ctx, initial_fd, listen_fd, &config, &result) == EIO);
				assert(fcntl(listen_fd, F_GETFL) == old_flags);
				for (unsigned i = 0; i < 3; i++) assert(fcntl(owned_credentials[i], F_GETFD) == -1 && errno == EBADF);
				ht_test_coverage_finish();
				_exit(0);
			}
			if (scenario == 3) {
				assert(pthread_create(&thread, NULL, managed, NULL) == 0);
				request('Q', 'Q'); request('A', 'B');
				assert(!atomic_load(&returned) && atomic_load(&resumes) == 0);
				ht_test_coverage_finish();
				_exit(0); /* The deliberately quarantined process stays blocked. */
			}
			if (scenario == 1 || scenario == 4)
				assert(pthread_create(&thread, NULL, recover_paused, NULL) == 0);
			if (scenario == 4) {
				/* A reconstructed owner waits fenced until recovery resumes it. */
				struct migration_prod_reconstruct image = { .id = 7 };
				assert(migration_prod_dest_reconstruct_managed(&ctx, &image,
				    listen_fd, &config, &result) == 0);
				assert(image.consumed == 1 && image.abandoned == 0);
			} else
				assert(migration_prod_dest_serve_managed(&ctx, initial_fd, listen_fd, &config, &result) == 0);
			assert(result.resumed && !result.retained && !result.release_ack_sent);
			if (scenario == 1 || scenario == 4) assert(pthread_join(thread, NULL) == 0);
			close(listen_fd); close(credentials.certificate_fd);
			close(credentials.private_key_fd); close(credentials.trust_fd);
			request('A', 'A'); request('A', 'A');
			assert(atomic_load(&resumes) == (scenario == 1 || scenario == 4 ? 1 : 0));
			ht_test_coverage_finish();
			_exit(0);
		}
		if (sandbox)
			for (int i = 0; i < client_count; i++) close(clients[i]);
		int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
		assert(fcntl(listen_fd, F_SETFL, old_flags) == 0);
	}
	close(listen_fd); close(credentials.certificate_fd);
	close(credentials.private_key_fd); close(credentials.trust_fd);
	assert(unlink(socket_path) == 0 && rmdir(directory) == 0);
	if (sandbox) puts("PASS: actual listener acceptance and retained worker setup after Capsicum entry");
	puts("PASS: receiver worker setup failure, paused recovery, running reconnect, independent descriptors, quarantine and reconstructed-owner service");
}
