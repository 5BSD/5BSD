/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of usr.sbin/bhyve/migration_receiver.c.
 *
 * The original source is compiled with the maintained bhyve compile command
 * (BHYVE_SNAPSHOT, BHYVE_GDB, WITH_DTRACE, ...) by coverage-bhyve.py.  This
 * harness supplies the retained destination owner (implemented and tested in
 * migration_session.c) and injects libc/pthread faults with --wrap.  Every
 * injected fault is counted and the tests assert that it fired.  Oracles are
 * independent of the implementation: returned errno values, descriptor
 * tables, listener flags, warning text, worker sleep counts and the owner's
 * recovery history.  No VM, device, daemon or network peer is used.
 */
#include "test-coverage.h"
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "migration_session.h"
#include "migration_credentials.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed\n", \
	__FILE__, __LINE__, #x); abort(); } } while (0)

struct vmctx { int id; };
struct migration_prod_dest {
	bool running, uncertain, ack;
	int recoveries, resumes;
	char script[16];	/* per-client release outcome */
	int next;
};
struct migration_prod_reconstruct { int id, consumed, abandoned; };

/* ------------------------------------------------------------ fault plan */
static atomic_int fail_calloc, fail_mutex_init, fail_cond_init, fail_create;
static atomic_int fcntl_fail_cmd = -1, fcntl_fail_skip, fcntl_fail_errno;
static atomic_int fcntl_failed;
static atomic_int sockopt_mode, sockopt_calls;
static atomic_int sleeps, cond_waits;
/* Scripted poll/accept results consumed by the worker before real I/O. */
#define SCRIPT_MAX 16
static struct { int ret, err, revents; } poll_script[SCRIPT_MAX];
static atomic_int poll_len, poll_pos;
static struct { int err; } accept_script[SCRIPT_MAX];
static atomic_int accept_len, accept_pos;
static pthread_mutex_t warn_lock = PTHREAD_MUTEX_INITIALIZER;
static char warnings[32][160];
static int nwarnings;

void *__real_calloc(size_t, size_t);
int __real_fcntl(int, int, ...);
int __real_getsockopt(int, int, int, void *, socklen_t *);
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __real_pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *);
int __real_poll(struct pollfd *, nfds_t, int);
int __real_accept4(int, struct sockaddr *, socklen_t *, int);

void *
__wrap_calloc(size_t n, size_t size)
{
	if (atomic_exchange(&fail_calloc, 0)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(n, size));
}

int
__wrap_fcntl(int fd, int cmd, ...)
{
	va_list ap;
	long arg;

	va_start(ap, cmd);
	arg = va_arg(ap, long);
	va_end(ap);
	if (cmd == atomic_load(&fcntl_fail_cmd)) {
		if (atomic_load(&fcntl_fail_skip) == 0) {
			atomic_store(&fcntl_fail_cmd, -1);
			atomic_fetch_add(&fcntl_failed, 1);
			errno = atomic_load(&fcntl_fail_errno);
			return (-1);
		}
		atomic_fetch_sub(&fcntl_fail_skip, 1);
	}
	return (__real_fcntl(fd, cmd, arg));
}

/* 1: fail SO_TYPE, 2: short SO_TYPE, 3: fail SO_ACCEPTCONN, 4: short
 * SO_ACCEPTCONN.  Mode resets after it fires. */
int
__wrap_getsockopt(int fd, int level, int name, void *value, socklen_t *length)
{
	int mode = atomic_load(&sockopt_mode);

	atomic_fetch_add(&sockopt_calls, 1);
	if ((mode == 1 && name == SO_TYPE) || (mode == 3 && name == SO_ACCEPTCONN)) {
		atomic_store(&sockopt_mode, 0);
		errno = ENOTSOCK;
		return (-1);
	}
	int error = __real_getsockopt(fd, level, name, value, length);
	if (error == 0 && ((mode == 2 && name == SO_TYPE) ||
	    (mode == 4 && name == SO_ACCEPTCONN))) {
		atomic_store(&sockopt_mode, 0);
		*length = 2;
	}
	return (error);
}

int
__wrap_pthread_mutex_init(pthread_mutex_t *m, const pthread_mutexattr_t *a)
{
	if (atomic_exchange(&fail_mutex_init, 0))
		return (ENOMEM);
	return (__real_pthread_mutex_init(m, a));
}

int
__wrap_pthread_cond_init(pthread_cond_t *c, const pthread_condattr_t *a)
{
	if (atomic_exchange(&fail_cond_init, 0))
		return (EAGAIN);
	return (__real_pthread_cond_init(c, a));
}

int
__wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *p)
{
	if (atomic_exchange(&fail_create, 0))
		return (EAGAIN);
	return (__real_pthread_create(t, a, f, p));
}

int
__wrap_pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m)
{
	atomic_fetch_add(&cond_waits, 1);
	return (__real_pthread_cond_wait(c, m));
}

int
__wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	int pos = atomic_load(&poll_pos);

	if (pos < atomic_load(&poll_len)) {
		atomic_store(&poll_pos, pos + 1);
		fds[0].revents = (short)poll_script[pos].revents;
		if (poll_script[pos].ret < 0)
			errno = poll_script[pos].err;
		return (poll_script[pos].ret);
	}
	return (__real_poll(fds, n, timeout));
}

int
__wrap_accept4(int s, struct sockaddr *a, socklen_t *l, int flags)
{
	int pos = atomic_load(&accept_pos);

	CHECK((flags & SOCK_CLOEXEC) != 0);
	if (pos < atomic_load(&accept_len)) {
		atomic_store(&accept_pos, pos + 1);
		errno = accept_script[pos].err;
		return (-1);
	}
	return (__real_accept4(s, a, l, flags));
}

int
__wrap_nanosleep(const struct timespec *t, struct timespec *r)
{
	(void)r;
	CHECK(t->tv_sec == 1 && t->tv_nsec == 0);
	atomic_fetch_add(&sleeps, 1);
	return (0);
}

void
__wrap_warnx(const char *fmt, ...)
{
	va_list ap;

	pthread_mutex_lock(&warn_lock);
	CHECK(nwarnings < 32);
	va_start(ap, fmt);
	vsnprintf(warnings[nwarnings++], sizeof(warnings[0]), fmt, ap);
	va_end(ap);
	pthread_mutex_unlock(&warn_lock);
}

static int
warning_count(void)
{
	int n;

	pthread_mutex_lock(&warn_lock);
	n = nwarnings;
	pthread_mutex_unlock(&warn_lock);
	return (n);
}

static bool
warning_is(int i, const char *text)
{
	bool same;

	pthread_mutex_lock(&warn_lock);
	same = i < nwarnings && strcmp(warnings[i], text) == 0;
	pthread_mutex_unlock(&warn_lock);
	return (same);
}

/* ----------------------------------------------------- owner boundaries */
static struct migration_prod_dest owner;
static struct vmctx vm = { 1 };
static atomic_int source_calls, reconstruct_calls;
static int source_mode;	/* see serve_prepared */
static int expected_fd;
static atomic_bool wait_for_worker;

/* The receiver passes private, close-on-exec duplicates of every credential;
 * the caller's descriptors must never reach the owner. */
static struct migration_tls_credentials caller_credentials;
static int owned[3];

static void
check_private_credentials(const struct migration_session_config *c)
{
	CHECK(c->tls_credentials != &caller_credentials);
	CHECK(memcmp(c->tls_credentials->peer_certificate_sha256,
	    caller_credentials.peer_certificate_sha256, 32) == 0);
	owned[0] = c->tls_credentials->certificate_fd;
	owned[1] = c->tls_credentials->private_key_fd;
	owned[2] = c->tls_credentials->trust_fd;
	for (int i = 0; i < 3; i++) {
		int flags = fcntl(owned[i], F_GETFD);
		CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
	}
	CHECK(owned[0] != caller_credentials.certificate_fd);
	CHECK(owned[1] != caller_credentials.private_key_fd);
	CHECK(owned[2] != caller_credentials.trust_fd);
}

static void
await_worker_wait(void)
{
	/* The worker blocks on the receiver condition until the source returns.
	 * Observe that wait before returning so its loop is exercised. */
	for (int i = 0; i < 2000 && atomic_load(&cond_waits) == 0; i++)
		usleep(1000);
	CHECK(atomic_load(&cond_waits) > 0);
}

/* source_mode: 0 failure without owner, 1 completed without owner (success),
 * 2 retained paused owner, 3 retained owner that is already running. */
int
migration_prod_dest_serve_prepared(struct vmctx *v, int fd,
    const struct migration_session_config *c, struct migration_dest_result *r,
    struct migration_prod_dest **out)
{
	CHECK(v == &vm && fd == expected_fd);
	atomic_fetch_add(&source_calls, 1);
	check_private_credentials(c);
	if (atomic_exchange(&wait_for_worker, false))
		await_worker_wait();
	memset(r, 0, sizeof(*r));
	switch (source_mode) {
	case 0:
		*out = NULL;
		r->phase = MIGRATION_PHASE_FAILED;
		return (EIO);
	case 1:
		*out = NULL;
		r->phase = MIGRATION_PHASE_COMPLETED;
		r->resumed = true;
		r->release_ack_sent = true;
		return (0);
	default:
		*out = &owner;
		owner.running = source_mode == 3;
		owner.ack = source_mode == 3;
		r->resumed = owner.running;
		r->release_ack_sent = owner.ack;
		r->retained = !owner.running;
		r->phase = owner.running ? MIGRATION_PHASE_COMPLETED : MIGRATION_PHASE_RECOVERY;
		return (owner.running ? 0 : ETIMEDOUT);
	}
}

int
migration_prod_dest_reconstruct_prepared(struct vmctx *v,
    struct migration_prod_reconstruct *state, const struct migration_session_config *c,
    struct migration_dest_result *r, struct migration_prod_dest **out)
{
	CHECK(v == &vm && state->consumed == 0 && state->abandoned == 0);
	CHECK(c->recovery_enabled);
	atomic_fetch_add(&reconstruct_calls, 1);
	state->consumed++;
	check_private_credentials(c);
	memset(r, 0, sizeof(*r));
	if (state->id == 0) {
		*out = NULL;
		return (EIO);
	}
	*out = &owner;
	owner.running = false;
	r->retained = true;
	r->phase = MIGRATION_PHASE_RECOVERY;
	return (0);
}

void
migration_prod_dest_reconstruct_abandon(struct migration_prod_reconstruct *state)
{
	CHECK(state->consumed == 0 && state->abandoned == 0);
	state->abandoned++;
}

/* Each accepted client consumes one script character:
 *   R resume (EPIPE: running although the ACK was lost)
 *   A resume and acknowledge (0)
 *   F authentication failure (EACCES), Q uncertain quarantine (EIO). */
int
migration_prod_dest_recover_release(struct migration_prod_dest *o, int fd,
    const struct migration_tls_credentials *c)
{
	char op = o->script[o->next++];
	int error = 0;

	CHECK(o == &owner && fd >= 0 && c->certificate_fd == owned[0]);
	CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
	o->recoveries++;
	switch (op) {
	case 'F':
		error = EACCES;
		break;
	case 'Q':
		o->uncertain = true;
		error = EIO;
		break;
	case 'R':
		CHECK(!o->running);
		o->running = true;
		o->resumes++;
		error = EPIPE;
		break;
	case 'A':
		if (!o->running)
			o->resumes++;
		o->running = o->ack = true;
		break;
	default:
		abort();
	}
	return (error);
}

void
migration_prod_dest_recovery_status(const struct migration_prod_dest *o,
    bool *running, bool *uncertain, bool *ack)
{
	*running = o->running;
	*uncertain = o->uncertain;
	*ack = o->ack;
}

/* ----------------------------------------------------------- utilities */
static int
open_descriptors(void)
{
	int n = 0;

	for (int fd = 0; fd < 512; fd++)
		if (fcntl(fd, F_GETFD) >= 0)
			n++;
	return (n);
}

static char directory[64];
static int sockets;

static int
make_listener(char *path, size_t size)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	CHECK(fd >= 0);
	snprintf(path, size, "%s/l%d", directory, sockets++);
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	CHECK(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	CHECK(listen(fd, 8) == 0);
	return (fd);
}

static int
connect_to(const char *path)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	CHECK(fd >= 0);
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
	return (fd);
}

static struct migration_session_config config;

static void
reset_owner(const char *script)
{
	memset(&owner, 0, sizeof(owner));
	strlcpy(owner.script, script, sizeof(owner.script));
}

static void
check_failed_result(const struct migration_dest_result *r)
{
	CHECK(r->phase == MIGRATION_PHASE_FAILED && r->reason == MIGRATION_REASON_STATE);
	CHECK(!r->resumed && !r->retained && !r->release_ack_sent);
	CHECK(r->rounds == 0 && r->bytes_received == 0);
}

/* ------------------------------------------------------------- tests */
static void
test_listener_check(void)
{
	char path[104];
	int listener = make_listener(path, sizeof(path));
	int dgram = socket(AF_UNIX, SOCK_DGRAM, 0);
	int stream = socket(AF_UNIX, SOCK_STREAM, 0);

	CHECK(dgram >= 0 && stream >= 0);
	CHECK(migration_recovery_listener_check(listener) == 0);
	CHECK(migration_recovery_listener_check(stream) == EINVAL);
	CHECK(migration_recovery_listener_check(dgram) == EINVAL);
	CHECK(migration_recovery_listener_check(-1) == EBADF);
	int calls = atomic_load(&sockopt_calls);
	atomic_store(&sockopt_mode, 1);
	CHECK(migration_recovery_listener_check(listener) == ENOTSOCK);
	atomic_store(&sockopt_mode, 2);
	CHECK(migration_recovery_listener_check(listener) == EINVAL);
	atomic_store(&sockopt_mode, 3);
	CHECK(migration_recovery_listener_check(listener) == ENOTSOCK);
	atomic_store(&sockopt_mode, 4);
	CHECK(migration_recovery_listener_check(listener) == EINVAL);
	/* Each mode fired once: 1 + 1 + 2 + 2 calls. */
	CHECK(atomic_load(&sockopt_calls) == calls + 6 && atomic_load(&sockopt_mode) == 0);
	close(dgram);
	close(stream);
	close(listener);
	printf("listener-check: 8 cases\n");
}

static void
test_argument_validation(void)
{
	struct migration_dest_result result;
	struct migration_session_config disabled = config, missing = config;
	char path[104];
	int listener = make_listener(path, sizeof(path));
	int before = open_descriptors();

	disabled.recovery_enabled = false;
	missing.tls_credentials = NULL;
	memset(&result, 0x5a, sizeof(result));
	CHECK(migration_prod_dest_serve_managed(NULL, 3, listener, &config, &result) == EINVAL);
	check_failed_result(&result);
	CHECK(migration_prod_dest_serve_managed(&vm, 3, listener, NULL, &result) == EINVAL);
	CHECK(migration_prod_dest_serve_managed(&vm, 3, listener, &config, NULL) == EINVAL);
	CHECK(migration_prod_dest_serve_managed(&vm, 3, listener, &disabled, &result) == EINVAL);
	check_failed_result(&result);
	CHECK(migration_prod_dest_serve_managed(&vm, 3, listener, &missing, &result) == EINVAL);
	/* A descriptor that is not a listening stream socket is refused before
	 * any resource is duplicated. */
	int plain = socket(AF_UNIX, SOCK_STREAM, 0);
	CHECK(plain >= 0);
	CHECK(migration_prod_dest_serve_managed(&vm, 3, plain, &config, &result) == EINVAL);
	check_failed_result(&result);
	close(plain);

	struct migration_prod_reconstruct s[6] = {{1, 0, 0}, {1, 0, 0}, {1, 0, 0},
	    {1, 0, 0}, {1, 0, 0}, {1, 0, 0}};
	memset(&result, 0x5a, sizeof(result));
	CHECK(migration_prod_dest_reconstruct_managed(&vm, NULL, listener, &config, &result) == EINVAL);
	check_failed_result(&result);
	CHECK(migration_prod_dest_reconstruct_managed(NULL, &s[0], listener, &config, &result) == EINVAL);
	CHECK(migration_prod_dest_reconstruct_managed(&vm, &s[1], listener, NULL, &result) == EINVAL);
	CHECK(migration_prod_dest_reconstruct_managed(&vm, &s[2], listener, &config, NULL) == EINVAL);
	CHECK(migration_prod_dest_reconstruct_managed(&vm, &s[3], listener, &disabled, &result) == EINVAL);
	CHECK(migration_prod_dest_reconstruct_managed(&vm, &s[4], listener, &missing, &result) == EINVAL);
	for (int i = 0; i < 5; i++)
		CHECK(s[i].abandoned == 1 && s[i].consumed == 0);
	CHECK(atomic_load(&source_calls) == 0 && atomic_load(&reconstruct_calls) == 0);
	CHECK(open_descriptors() == before);
	close(listener);
	printf("argument-validation: 12 cases\n");
}

/* Every setup failure before the source runs returns the injected error,
 * leaves the caller's listener flags and descriptor table unchanged, never
 * invokes the source and abandons (never consumes) a reconstruction. */
static void
test_setup_failures(void)
{
	struct { const char *name; int cmd, skip, err; atomic_int *flag; int expect; } cases[] = {
		{ "calloc", -1, 0, 0, &fail_calloc, ENOMEM },
		{ "dup-listener", F_DUPFD_CLOEXEC, 0, EMFILE, NULL, EMFILE },
		{ "getfl", F_GETFL, 0, EBADF, NULL, EBADF },
		{ "setfl", F_SETFL, 0, EINVAL, NULL, EINVAL },
		{ "dup-certificate", F_DUPFD_CLOEXEC, 1, ENFILE, NULL, ENFILE },
		{ "dup-key", F_DUPFD_CLOEXEC, 2, EMFILE, NULL, EMFILE },
		{ "dup-trust", F_DUPFD_CLOEXEC, 3, EMFILE, NULL, EMFILE },
		{ "mutex", -1, 0, 0, &fail_mutex_init, ENOMEM },
		{ "cond", -1, 0, 0, &fail_cond_init, EAGAIN },
		{ "thread", -1, 0, 0, &fail_create, EAGAIN },
	};
	char path[104];
	int listener = make_listener(path, sizeof(path));
	int flags = fcntl(listener, F_GETFL);
	struct migration_dest_result result;

	for (unsigned reconstruct = 0; reconstruct < 2; reconstruct++)
	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int before = open_descriptors(), fired = atomic_load(&fcntl_failed);
		struct migration_prod_reconstruct state = { 7, 0, 0 };

		if (cases[i].flag != NULL)
			atomic_store(cases[i].flag, 1);
		else {
			atomic_store(&fcntl_fail_skip, cases[i].skip);
			atomic_store(&fcntl_fail_errno, cases[i].err);
			atomic_store(&fcntl_fail_cmd, cases[i].cmd);
		}
		int error = reconstruct ?
		    migration_prod_dest_reconstruct_managed(&vm, &state, listener, &config, &result) :
		    migration_prod_dest_serve_managed(&vm, expected_fd, listener, &config, &result);
		if (error != cases[i].expect) {
			fprintf(stderr, "%s: %d\n", cases[i].name, error);
			abort();
		}
		if (cases[i].flag != NULL)
			CHECK(atomic_load(cases[i].flag) == 0);	/* fired */
		else
			CHECK(atomic_load(&fcntl_failed) == fired + 1);
		CHECK(fcntl(listener, F_GETFL) == flags);
		CHECK(open_descriptors() == before);
		CHECK(atomic_load(&source_calls) == 0 && atomic_load(&reconstruct_calls) == 0);
		if (reconstruct)
			CHECK(state.abandoned == 1 && state.consumed == 0);
		check_failed_result(&result);
	}
	close(listener);
	printf("setup-failures: 20 cases\n");
}

/* A source that fails or completes without retaining an owner releases the
 * worker and every private resource; its result is returned unchanged. */
static void
test_unretained_sources(void)
{
	char path[104];
	int listener = make_listener(path, sizeof(path));
	int flags = fcntl(listener, F_GETFL);
	struct migration_dest_result result;
	int before = open_descriptors();

	source_mode = 0;
	atomic_store(&wait_for_worker, true);
	int waits = atomic_load(&cond_waits);
	CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener, &config, &result) == EIO);
	CHECK(atomic_load(&cond_waits) > waits);	/* worker waited for readiness */
	CHECK(result.phase == MIGRATION_PHASE_FAILED && !result.resumed);
	CHECK(open_descriptors() == before && fcntl(listener, F_GETFL) == flags);
	for (int i = 0; i < 3; i++)
		CHECK(fcntl(owned[i], F_GETFD) == -1 && errno == EBADF);
	source_mode = 1;
	CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener, &config, &result) == 0);
	CHECK(result.phase == MIGRATION_PHASE_COMPLETED && result.resumed &&
	    result.release_ack_sent && !result.retained);
	CHECK(open_descriptors() == before && fcntl(listener, F_GETFL) == flags);
	struct migration_prod_reconstruct corrupt = { 0, 0, 0 };
	CHECK(migration_prod_dest_reconstruct_managed(&vm, &corrupt, listener, &config, &result) == EIO);
	CHECK(corrupt.consumed == 1 && corrupt.abandoned == 0);
	CHECK(open_descriptors() == before && fcntl(listener, F_GETFL) == flags);
	CHECK(atomic_load(&source_calls) == 2 && atomic_load(&reconstruct_calls) == 1);
	close(listener);
	atomic_store(&source_calls, 0);
	atomic_store(&reconstruct_calls, 0);
	printf("unretained-sources: 3 cases\n");
}

/* An owner that is already running when the source returns needs no
 * recovery: the call returns at once and the worker stays retained. */
static void
test_retained_running(void)
{
	char path[104];
	int listener = make_listener(path, sizeof(path));
	struct migration_dest_result result;

	reset_owner("");
	source_mode = 3;
	int warned = warning_count();
	CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener, &config, &result) == 0);
	CHECK(result.resumed && !result.retained && result.release_ack_sent);
	CHECK(result.phase == MIGRATION_PHASE_COMPLETED && result.reason == MIGRATION_REASON_NONE);
	CHECK(warning_count() == warned && owner.recoveries == 0);
	/* The listener is kept for the process lifetime (worker retained). */
	printf("retained-running: 1 case\n");
	(void)listener;
}

struct client_job { const char *path; const char *ops; };

static void *
clients(void *arg)
{
	struct client_job *job = arg;

	for (const char *op = job->ops; *op != '\0'; op++) {
		int fd = connect_to(job->path);
		char byte;
		/* The receiver closes the client after one recovery attempt. */
		CHECK(read(fd, &byte, 1) == 0);
		close(fd);
	}
	return (NULL);
}

/* Paused owner: the worker survives every listener and client failure,
 * reports each distinct error once, sleeps only after failures without a
 * client, never resumes twice, and the caller returns only once running. */
static void
test_worker_failures(bool sandbox)
{
	char path[104];
	int listener = make_listener(path, sizeof(path));
	struct migration_dest_result result;
	pthread_t thread;
	struct client_job job = { path, "FRA" };

	reset_owner("FRA");
	source_mode = 2;
	int script[][3] = {
		{ -1, EINTR, 0 },	/* retried silently */
		{ -1, ENOMEM, 0 },	/* warned, slept */
		{ -1, ENOMEM, 0 },	/* same error: slept, not warned again */
		{ 1, 0, POLLHUP },	/* EIO: warned, slept */
		{ 1, 0, POLLIN },	/* accept EINTR: retried */
		{ 1, 0, POLLIN },	/* accept EAGAIN: retried */
		{ 1, 0, POLLIN },	/* accept ECONNABORTED: warned, slept */
	};
	for (int i = 0; i < 7; i++) {
		poll_script[i].ret = script[i][0];
		poll_script[i].err = script[i][1];
		poll_script[i].revents = script[i][2];
	}
	accept_script[0].err = EINTR;
	accept_script[1].err = EAGAIN;
	accept_script[2].err = ECONNABORTED;
	atomic_store(&accept_pos, 0);
	atomic_store(&accept_len, 3);
	atomic_store(&poll_pos, 0);
	atomic_store(&poll_len, 7);
	int warned = warning_count(), slept = atomic_load(&sleeps);
	CHECK(pthread_create(&thread, NULL, clients, &job) == 0);
	CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener, &config, &result) == 0);
	CHECK(pthread_join(thread, NULL) == 0);
	CHECK(result.resumed && !result.retained && result.phase == MIGRATION_PHASE_COMPLETED);
	/* Resumed by the 'R' client: its acknowledgment was lost. */
	CHECK(owner.resumes == 1);
	CHECK(atomic_load(&poll_pos) == 7 && atomic_load(&accept_pos) == 3);
	CHECK(atomic_load(&sleeps) == slept + 4);
	/* The third client acknowledges after the caller already returned. */
	for (int i = 0; i < 2000 && owner.recoveries < 3; i++)
		usleep(1000);
	CHECK(owner.recoveries == 3 && owner.ack && owner.resumes == 1);
	const char *expect[] = {
		"migration destination retained; awaiting authenticated recovery",
		"migration recovery attempt failed: 12; retaining destination",
		"migration recovery attempt failed: 5; retaining destination",
		"migration recovery attempt failed: 53; retaining destination",
		"migration recovery attempt failed: 13; retaining destination",
		"migration recovery attempt failed: 32; retaining destination",
	};
	for (int i = 0; i < 2000 && warning_count() < warned + 6; i++)
		usleep(1000);
	CHECK(warning_count() == warned + 6);
	/* The retained notice and worker warnings race; check membership and the
	 * worker's own order. */
	int seen = 0, last = -1;
	for (int w = warned; w < warned + 6; w++)
		for (int e = 0; e < 6; e++)
			if (warning_is(w, expect[e])) {
				seen |= 1 << e;
				if (e > 0) {
					CHECK(e > last);
					last = e;
				}
			}
	CHECK(seen == 0x3f);
	(void)sandbox;
	printf("worker-failures%s: 7 scripted listener results, 3 clients\n",
	    sandbox ? " (capability mode)" : "");
}

/* An uncertain resume quarantines the owner: the caller keeps waiting and
 * later clients cannot resume it. */
static void *
quarantined_caller(void *arg)
{
	struct migration_dest_result result;

	(void)arg;
	(void)migration_prod_dest_serve_managed(&vm, expected_fd, *(int *)arg, &config, &result);
	abort();	/* never returns while quarantined */
}

static void
test_quarantine(void)
{
	char path[104];
	static int listener;
	pthread_t thread;
	struct client_job job = { path, "QA" };

	listener = make_listener(path, sizeof(path));
	reset_owner("QA");
	source_mode = 2;
	CHECK(pthread_create(&thread, NULL, quarantined_caller, &listener) == 0);
	CHECK(pthread_detach(thread) == 0);
	for (int i = 0; i < 2000 && atomic_load(&source_calls) == 0; i++)
		usleep(1000);
	clients(&job);
	for (int i = 0; i < 2000 && owner.recoveries < 2; i++)
		usleep(1000);
	CHECK(owner.recoveries == 2 && owner.uncertain);
	/* 'A' after quarantine still marks running in this owner model, but the
	 * receiver requires running && !uncertain before releasing the caller. */
	usleep(50000);
	CHECK(owner.running && owner.resumes == 1);
	printf("quarantine: caller stays blocked after uncertain resume\n");
}

int
main(int argc, char **argv)
{
	bool sandbox = argc == 2 && strcmp(argv[1], "--capsicum") == 0;

	ht_test_coverage_start(sandbox ? "receiver-cov-capsicum" : "receiver-cov", false);
	strlcpy(directory, "receiver.XXXXXX", sizeof(directory));
	CHECK(mkdtemp(directory) != NULL);
	caller_credentials.certificate_fd = open("/dev/null", O_RDONLY);
	caller_credentials.private_key_fd = open("/dev/null", O_RDONLY);
	caller_credentials.trust_fd = open("/dev/null", O_RDONLY);
	memset(caller_credentials.peer_certificate_sha256, 0x42, 32);
	config.recovery_enabled = true;
	config.tls_credentials = &caller_credentials;
	expected_fd = 99;
	if (sandbox) {
		/* Capability mode: the listener and one queued client connection
		 * are created first; the receiver duplicates descriptors, starts
		 * its worker, accepts and serves recovery without any path access. */
		char path[104];
		int listener = make_listener(path, sizeof(path));
		int client = connect_to(path);
		struct migration_dest_result result;
		char byte;

		reset_owner("R");
		source_mode = 2;
		CHECK(cap_enter() == 0);
		CHECK(open("/", O_RDONLY) == -1 && errno == ECAPMODE);
		atomic_store(&fail_create, 1);
		CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener,
		    &config, &result) == EAGAIN);
		CHECK(atomic_load(&source_calls) == 0);
		CHECK(migration_prod_dest_serve_managed(&vm, expected_fd, listener,
		    &config, &result) == 0);
		CHECK(result.resumed && !result.release_ack_sent &&
		    result.reason == MIGRATION_REASON_TRANSPORT);
		CHECK(read(client, &byte, 1) == 0);
		CHECK(owner.resumes == 1 && owner.recoveries == 1);
		ht_test_coverage_finish();
		printf("PASS: receiver setup failure and recovery in capability mode\n");
		return (0);
	}
	test_listener_check();
	test_argument_validation();
	test_setup_failures();
	test_unretained_sources();
	test_retained_running();
	test_worker_failures(false);
	test_quarantine();
	ht_test_coverage_finish();
	printf("PASS: migration_receiver.c production configuration\n");
	return (0);
}
