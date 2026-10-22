/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of usr.sbin/bhyve/hypertrace.c (Capsicum
 * compiled in), covering the fresh-session kernel gate, one-shot recovery
 * witness, initialization, the attested session control channel, the HTX1
 * export path and the inbound ELF helpers.
 *
 * The original source is included so its private state can be observed; the
 * coverage collector credits it only through mappings identical to the
 * production object.  The kernel HyperTrace device is modelled behind a
 * wrapped ioctl(2): an epoch gate per (vmid, epoch) with a suspension token
 * that may only be replaced by naming the previous token, and a liveness
 * flag for the retirement witness.  The daemon is a real AF_UNIX peer
 * speaking the dtraced wire protocol (dtraced_wire.h, dtraced_io.h).
 *
 * Oracles: the documented errno of every refusal; a gate is never resumed or
 * re-suspended under a different token; a stop/release succeeds only when the
 * kernel gate reflects it before and after the daemon reply; an HTX1 export
 * is published only when complete, token-bound and digest-valid; descriptor
 * rights limits are applied (cap_rights_get on the retained descriptors).
 */
#include "hypertrace.c"

#include <sys/endian.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <assert.h>
#include <openssl/sha.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)

struct vmctx { uint16_t vmid; uint64_t epoch; const char *name; int identity_failures;
    int identity_flip_after; int fail_on_read; bool flip_vmid; };
static struct vmctx vm = { 3, 30, "gate-vm", 0, -1 };

uint16_t
vm_get_vmid(struct vmctx *ctx)
{
	return (ctx->vmid);
}

int
vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch)
{
	if (ctx->identity_failures > 0) {
		ctx->identity_failures--;
		errno = ENXIO;
		return (-1);
	}
	/* Fail exactly the n-th read from now. */
	if (ctx->fail_on_read > 0 && --ctx->fail_on_read == 0) {
		errno = ENXIO;
		return (-1);
	}
	*vmid = ctx->vmid;
	*epoch = ctx->epoch;
	/* Simulate a VM reinitialized between two identity reads (another
	 * epoch, or with flip_vmid another VM id). */
	if (ctx->identity_flip_after >= 0 && ctx->identity_flip_after-- == 0) {
		if (ctx->flip_vmid)
			ctx->vmid++;
		else
			ctx->epoch++;
	}
	return (0);
}

const char *
vm_get_name(struct vmctx *ctx)
{
	return (ctx->name);
}

static int fail_attestation;
int
vm_export_attestation_fd(struct vmctx *ctx)
{
	(void)ctx;
	if (fail_attestation) {
		errno = EBADF;
		return (-1);
	}
	return (open("/dev/null", O_RDONLY | O_CLOEXEC));
}

/* ------------------------------------------------- kernel gate model */
static struct {
	uint16_t vmid;
	uint64_t epoch;
	uint32_t suspended;
	uint8_t token[16];
	bool live;
	unsigned long fail_command;	/* fail this ioctl once */
	int malform;		/* corrupt the next reply: field index */
	int suspends;
} kernel;

int __real_ioctl(int, unsigned long, ...);
int
__wrap_ioctl(int fd, unsigned long command, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, command);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (fd != session_gate_fd || fd < 0)
		return (__real_ioctl(fd, command, arg));
	if (kernel.fail_command != 0 && kernel.fail_command == command) {
		kernel.fail_command = 0;
		errno = EIO;
		return (-1);
	}
	if (command == HYPERTRACE_IOC_EPOCH_QUERY) {
		struct hypertrace_epoch_query *q = arg;
		q->live = (q->vmid == kernel.vmid && q->epoch == kernel.epoch && kernel.live);
		switch (kernel.malform) {
		case 1: q->vmid ^= 1; break;
		case 2: q->epoch ^= 1; break;
		case 3: q->live = 2; break;
		case 4: q->reserved[0] = 1; break;
		case 5: q->reserved[1] = 1; break;
		case 6: q->reserved[2] = 1; break;
		case 7: q->reserved2 = 1; break;
		}
		kernel.malform = 0;
		return (0);
	}
	if (command == HYPERTRACE_IOC_EPOCH_GATE_QUERY) {
		struct hypertrace_epoch_gate *g = arg;
		if (g->vmid != kernel.vmid || g->epoch != kernel.epoch) {
			errno = ENOENT;
			return (-1);
		}
		g->suspended = kernel.suspended;
		memcpy(g->token, kernel.token, 16);
		switch (kernel.malform) {
		case 1: g->vmid ^= 1; break;
		case 2: g->epoch ^= 1; break;
		case 3: g->suspended = 2; break;
		case 4: g->reserved[0] = 1; break;
		case 5: g->reserved[1] = 1; break;
		case 6: g->reserved[2] = 1; break;
		case 7: g->reserved2 = 1; break;
		case 8: g->previous_token[3] = 1; break;
		}
		kernel.malform = 0;
		return (0);
	}
	if (command == HYPERTRACE_IOC_EPOCH_SUSPEND) {
		struct hypertrace_epoch_gate *g = arg;
		/* Replacing the token requires naming the current one. */
		if (g->vmid != kernel.vmid || g->epoch != kernel.epoch ||
		    kernel.suspended != 0 || memcmp(g->previous_token, kernel.token, 16) != 0) {
			errno = EBUSY;
			return (-1);
		}
		kernel.suspended = 1;
		memcpy(kernel.token, g->token, 16);
		kernel.suspends++;
		return (0);
	}
	errno = ENOTTY;
	return (-1);
}

static int fail_cap_ioctls;
int __real_cap_ioctls_limit(int, const cap_ioctl_t *, size_t);
int
__wrap_cap_ioctls_limit(int fd, const cap_ioctl_t *cmds, size_t n)
{
	if (fail_cap_ioctls > 0 && --fail_cap_ioctls == 0) {
		errno = ENOTCAPABLE;
		return (-1);
	}
	return (__real_cap_ioctls_limit(fd, cmds, n));
}

static int fail_cap_rights;
int __real_cap_rights_limit(int, const cap_rights_t *);
int
__wrap_cap_rights_limit(int fd, const cap_rights_t *rights)
{
	if (fail_cap_rights > 0 && --fail_cap_rights == 0) {
		errno = ENOTCAPABLE;
		return (-1);
	}
	return (__real_cap_rights_limit(fd, rights));
}

/*
 * Client-side socket faults.  Only calls from the armed thread (the test's
 * forwarder side) count, so the in-process daemon peer is never affected.
 * *_at: fail the n-th call from arming (0: off).  connect_mode: 1 perform
 * the connection and report EALREADY, 2 report EINTR, 3 report EINPROGRESS
 * without connecting.
 */
static pthread_t fault_thread;
static int fail_socket_at, fail_send_at, fail_sendmsg_at, connect_mode;

static bool
fault_here(int *at)
{
	if (*at == 0 || !pthread_equal(pthread_self(), fault_thread))
		return (false);
	return (--*at == 0);
}

int __real_socket(int, int, int);
int
__wrap_socket(int domain, int type, int protocol)
{
	if (fault_here(&fail_socket_at)) {
		errno = EMFILE;
		return (-1);
	}
	return (__real_socket(domain, type, protocol));
}

int __real_connectat(int, int, const struct sockaddr *, socklen_t);
int
__wrap_connectat(int dirfd, int fd, const struct sockaddr *sa, socklen_t len)
{
	int mode = pthread_equal(pthread_self(), fault_thread) ? connect_mode : 0;

	if (mode == 3) {
		connect_mode = 0;
		errno = EINPROGRESS;
		return (-1);
	}
	int r = __real_connectat(dirfd, fd, sa, len);
	if (r == 0 && (mode == 1 || mode == 2)) {
		connect_mode = 0;
		errno = mode == 1 ? EALREADY : EINTR;
		return (-1);
	}
	return (r);
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags)
{
	if (fault_here(&fail_send_at)) {
		errno = EPIPE;
		return (-1);
	}
	return (__real_send(fd, buf, len, flags));
}

ssize_t __real_sendmsg(int, const struct msghdr *, int);
ssize_t
__wrap_sendmsg(int fd, const struct msghdr *msg, int flags)
{
	if (fault_here(&fail_sendmsg_at)) {
		errno = EPIPE;
		return (-1);
	}
	return (__real_sendmsg(fd, msg, flags));
}

static void
arm_faults(void)
{
	fault_thread = pthread_self();
}

/* ------------------------------------------------------- filesystem */
static char root[256];
static int fail_open_path;	/* 1 sockdir, 2 inbound, 3 device */
int __real_open(const char *, int, ...);
int
__wrap_open(const char *path, int flags, ...)
{
	char redirected[400];
	va_list ap;
	int mode;

	va_start(ap, flags);
	mode = va_arg(ap, int);
	va_end(ap);
	if (strcmp(path, "/var/ddtrace") == 0 || strcmp(path, "/var/ddtrace/inbound") == 0 ||
	    strcmp(path, "/dev/dtrace/hypertrace") == 0) {
		int which = path[1] == 'd' ? 3 : strchr(path + 5, '/') != NULL &&
		    strstr(path, "inbound") != NULL ? 2 : 1;
		if (fail_open_path == which) {
			fail_open_path = 0;
			errno = ENOENT;
			return (-1);
		}
		snprintf(redirected, sizeof(redirected), "%s/%s", root,
		    which == 1 ? "ddtrace" : which == 2 ? "ddtrace/inbound" : "hypertrace-dev");
		return (__real_open(redirected, flags, mode));
	}
	return (__real_open(path, flags, mode));
}

static void
reset_state(void)
{
	if (session_gate_fd >= 0)
		close(session_gate_fd);
	if (sockdir >= 0)
		close(sockdir);
	if (inbound_dirfd >= 0)
		close(inbound_dirfd);
	session_gate_fd = sockdir = inbound_dirfd = -1;
	session_gate_error = ENXIO;
	prepared = false;
	memset(&kernel, 0, sizeof(kernel));
	kernel.vmid = 3;
	kernel.epoch = 30;
	vm.vmid = 3;
	vm.epoch = 30;
	vm.identity_failures = 0;
	vm.identity_flip_after = -1;
}

static int
open_gate(void)
{
	char path[400];

	snprintf(path, sizeof(path), "%s/hypertrace-dev", root);
	session_gate_fd = __real_open(path, O_RDONLY | O_CLOEXEC);
	CHECK(session_gate_fd >= 0);
	session_gate_error = 0;
	return (session_gate_fd);
}

/* ------------------------------------------------------- gate tests */
static void
test_retirement_witness(void)
{
	reset_state();
	CHECK(hypertrace_session_retired(0, 1) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_retired(HYPERTRACE_MAX_VMS, 1) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_retired(3, 0) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_retired(3, 30) == -1 && errno == ENXIO);	/* no device */
	open_gate();
	kernel.live = true;
	CHECK(hypertrace_session_retired(3, 30) == -1 && errno == EBUSY);
	kernel.live = false;
	CHECK(hypertrace_session_retired(3, 30) == 0);
	CHECK(hypertrace_session_retired(4, 30) == 0);	/* absent lifetime: not live */
	kernel.fail_command = HYPERTRACE_IOC_EPOCH_QUERY;
	CHECK(hypertrace_session_retired(3, 30) == -1 && errno == EIO);
	for (int field = 1; field <= 7; field++) {
		kernel.malform = field;
		CHECK(hypertrace_session_retired(3, 30) == -1 && errno == EPROTO);
	}
	/* One-shot recovery owner of the witness descriptor. */
	CHECK(hypertrace_session_recovery_open() == EBUSY);	/* already open */
	hypertrace_session_recovery_close();
	CHECK(session_gate_fd == -1 && session_gate_error == ENXIO);
	hypertrace_session_recovery_close();	/* idempotent */
	CHECK(hypertrace_session_recovery_open() == 0 && session_gate_fd >= 0);
	{
		cap_rights_t rights;
		CHECK(cap_rights_get(session_gate_fd, &rights) == 0);
		CHECK(cap_rights_is_set(&rights, CAP_IOCTL) && !cap_rights_is_set(&rights, CAP_READ));
	}
	hypertrace_session_recovery_close();
	fail_open_path = 3;
	CHECK(hypertrace_session_recovery_open() == ENOENT && session_gate_fd == -1);
	fail_cap_ioctls = 1;
	CHECK(hypertrace_session_recovery_open() == ENOTCAPABLE && session_gate_fd == -1);
	prepared = true;
	CHECK(hypertrace_session_recovery_open() == EBUSY);
	open_gate();
	hypertrace_session_recovery_close();	/* prepared: the owner keeps it */
	CHECK(session_gate_fd >= 0);
	printf("hypertrace retirement witness: 27 checks\n");
}

static void
test_host_gate(void)
{
	uint8_t token[16] = { 0x10, 1 }, other[16] = { 0x20, 2 }, zero[16] = {0};

	reset_state();
	CHECK(hypertrace_session_host_stop(NULL, token) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_host_stop(&vm, NULL) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_host_stop(&vm, zero) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_host_stopped(&vm, zero) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ENXIO);
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == ENXIO);
	open_gate();
	vm.identity_failures = 1;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ENXIO);
	vm.identity_failures = 1;
	CHECK(hypertrace_session_host_released(&vm, token) == -1 && errno == ENXIO);
	vm.vmid = 0;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == EPROTO);
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == EPROTO);
	vm.vmid = 3;
	vm.epoch = 0;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == EPROTO);
	vm.epoch = 30;
	/* Gate query failures and malformed replies. */
	kernel.fail_command = HYPERTRACE_IOC_EPOCH_GATE_QUERY;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == EIO);
	for (int field = 1; field <= 8; field++) {
		kernel.malform = field;
		CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == EPROTO);
	}
	/* Not yet stopped; then stop names the previous (zero) token. */
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == EBUSY);
	CHECK(hypertrace_session_host_released(&vm, token) == -1 && errno == EBUSY);
	kernel.fail_command = HYPERTRACE_IOC_EPOCH_SUSPEND;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == EIO);
	CHECK(kernel.suspended == 0);
	CHECK(hypertrace_session_host_stop(&vm, token) == 0);
	CHECK(kernel.suspended == 1 && memcmp(kernel.token, token, 16) == 0 && kernel.suspends == 1);
	/* Idempotent retry with the same token; another token is refused. */
	CHECK(hypertrace_session_host_stop(&vm, token) == 0 && kernel.suspends == 1);
	CHECK(hypertrace_session_host_stop(&vm, other) == -1 && errno == EBUSY);
	CHECK(hypertrace_session_host_stopped(&vm, token) == 0);
	CHECK(hypertrace_session_host_stopped(&vm, other) == -1 && errno == EBUSY);
	CHECK(hypertrace_session_host_released(&vm, token) == -1 && errno == EBUSY);
	/* The VM was reinitialized between the two identity reads. */
	vm.identity_flip_after = 0;
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == ESTALE);
	vm.epoch = 30;
	vm.identity_flip_after = 1;	/* flips after the stop's own query */
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ESTALE);
	vm.epoch = 30;
	vm.identity_failures = 0;
	/* Second identity read failing inside the state check. */
	{
		struct vmctx flaky = vm;
		flaky.identity_failures = 0;
		kernel.suspended = 1;
		/* fail the second read only */
		flaky.identity_flip_after = -1;
		CHECK(hypertrace_session_host_stopped(&flaky, token) == 0);
	}
	/* A released gate. */
	kernel.suspended = 0;
	CHECK(hypertrace_session_host_released(&vm, token) == 0);
	printf("hypertrace host gate: 36 checks\n");
}

/* -------------------------------------------------- initialization */
static void
make_root(void)
{
	char path[400];

	CHECK(getcwd(root, sizeof(root)) != NULL);
	snprintf(path, sizeof(path), "%s/ddtrace", root);
	CHECK(mkdir(path, 0755) == 0 || errno == EEXIST);
	snprintf(path, sizeof(path), "%s/ddtrace/inbound", root);
	CHECK(mkdir(path, 0755) == 0 || errno == EEXIST);
	snprintf(path, sizeof(path), "%s/hypertrace-dev", root);
	int fd = __real_open(path, O_RDWR | O_CREAT, 0600);
	CHECK(fd >= 0);
	close(fd);
}

static void
test_init(void)
{
	cap_rights_t rights;

	reset_state();
	vm.vmid = 0;
	CHECK(hypertrace_init(&vm) == -1 && errno == ENOTSUP);
	vm.vmid = 3;
	fail_open_path = 1;
	CHECK(hypertrace_init(&vm) == -1 && errno == ENOENT && !prepared);
	fail_open_path = 2;
	CHECK(hypertrace_init(&vm) == -1 && errno == ENOENT && sockdir == -1);
	fail_cap_rights = 1;
	CHECK(hypertrace_init(&vm) == -1 && errno == ENOTCAPABLE && sockdir == -1);
	/* Missing device: tracing still initializes, the witness is absent. */
	fail_open_path = 3;
	CHECK(hypertrace_init(&vm) == 0 && prepared);
	CHECK(session_gate_fd == -1 && session_gate_error == ENOENT);
	CHECK(hypertrace_init(&vm) == -1 && errno == EALREADY);
	CHECK(cap_rights_get(sockdir, &rights) == 0 &&
	    cap_rights_is_set(&rights, CAP_CONNECTAT) && !cap_rights_is_set(&rights, CAP_READ));
	reset_state();
	/* Device present but its ioctl limits cannot be applied. */
	fail_cap_ioctls = 1;
	CHECK(hypertrace_init(&vm) == 0 && session_gate_fd == -1 &&
	    session_gate_error == ENOTCAPABLE);
	reset_state();
	CHECK(hypertrace_init(&vm) == 0 && session_gate_fd >= 0);
	CHECK(cap_rights_get(session_gate_fd, &rights) == 0 && cap_rights_is_set(&rights, CAP_IOCTL));
	printf("hypertrace init: 13 checks\n");
}

/* ------------------------------------------------------ daemon peer */
struct daemon {
	int listener;
	int (*script)(int peer, struct daemon *);
	uint64_t expect_subs;
	int ack, remaining;
	uint8_t *bundle;
	size_t bundle_length;
	int sessions;
	pthread_t thread;
};

static void *
daemon_main(void *arg)
{
	struct daemon *d = arg;
	int peer = accept(d->listener, NULL, NULL);
	dtd_initmsg_t hello = { .protocol_version = DTRACED_PROTOCOL_VERSION,
	    .kind = DTRACED_KIND_DTRACED };
	size_t transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;

	if (peer < 0)
		return (NULL);
	d->sessions++;
	CHECK(dtraced_wire_write_init(peer, &hello, deadline, &transferred) == 0);
	CHECK(dtraced_wire_read_init(peer, &hello, deadline, &transferred) == 0);
	CHECK(hello.kind == DTRACED_KIND_FORWARDER && strcmp(hello.ident, "gate-vm") == 0);
	if (hello.subs != d->expect_subs)
		fprintf(stderr, "subs %#jx expected %#jx\n", (uintmax_t)hello.subs,
		    (uintmax_t)d->expect_subs);
	CHECK(hello.subs == d->expect_subs);
	int identity = dtraced_io_recv_fd(peer, deadline);
	CHECK(identity >= 0);
	close(identity);
	if ((hello.subs & DTD_SUB_ADMISSION_ACK) != 0) {
		uint8_t ack = 1;
		CHECK(dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred) == 0);
	}
	if (d->script != NULL)
		d->script(peer, d);
	close(peer);
	return (NULL);
}

static void
daemon_start(struct daemon *d, int (*script)(int, struct daemon *))
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	char path[400];

	snprintf(path, sizeof(path), "%s/ddtrace/sub.sock", root);
	(void)unlink(path);
	d->listener = socket(AF_UNIX, SOCK_STREAM, 0);
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	CHECK(d->listener >= 0 && bind(d->listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0 && listen(d->listener, 2) == 0);
	d->script = script;
	CHECK(pthread_create(&d->thread, NULL, daemon_main, d) == 0);
}

static void
daemon_stop(struct daemon *d)
{
	shutdown(d->listener, SHUT_RDWR);
	CHECK(pthread_join(d->thread, NULL) == 0);
	close(d->listener);
}

/* Session STOP/RELEASE: read the size-prefixed frame, reply ack+remaining.
 * kernel_after: the gate state the daemon leaves behind. */
static int kernel_after = -1;

static int
control_script(int peer, struct daemon *d)
{
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_SESSION_STOP_WIRE_SIZE];
	uint8_t ack = (uint8_t)d->ack, remaining = (uint8_t)d->remaining;

	CHECK(dtraced_io_read_size(peer, &length, deadline, &transferred) == 0);
	CHECK(length == sizeof(frame));
	CHECK(dtraced_io_transfer(peer, frame, length, false, deadline, &transferred) == 0);
	if (kernel_after >= 0)
		kernel.suspended = (uint32_t)kernel_after;
	CHECK(dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred) == 0);
	if (d->ack == 1)
		CHECK(dtraced_io_transfer(peer, &remaining, 1, true, deadline,
		    &transferred) == 0);
	return (0);
}

static int
control_run(bool release, int ack, int remaining, int after)
{
	struct daemon d = { .expect_subs = DTD_SUB_READDATA, .ack = ack,
	    .remaining = remaining };
	uint8_t token[16] = { 0x10, 1 };
	int result;

	kernel_after = after;
	daemon_start(&d, control_script);
	result = release ? hypertrace_session_release(&vm, token) :
	    hypertrace_session_collectors_stop_step(&vm, token);
	int saved = errno;
	daemon_stop(&d);
	kernel_after = -1;
	errno = saved;
	return (result);
}

static void
test_control_step(void)
{
	uint8_t token[16] = { 0x10, 1 };

	reset_state();
	CHECK(hypertrace_init(&vm) == 0);
	/* Unprepared, NULL. */
	CHECK(ht_session_control_step(NULL, token, false) == -1 && errno == EINVAL);
	/* Gate not stopped: refused before connecting. */
	kernel.suspended = 0;
	memset(kernel.token, 0, 16);
	CHECK(hypertrace_session_collectors_stop_step(&vm, token) == -1 && errno == EBUSY);
	/* Stopped gate: daemon replies drive the outcome. */
	kernel.suspended = 1;
	memcpy(kernel.token, token, 16);
	CHECK(control_run(false, 1, 0, -1) == 0);
	CHECK(control_run(false, 1, 1, -1) == 1);	/* collectors remain */
	CHECK(control_run(false, 0, 0, -1) == -1 && errno == EBUSY);
	CHECK(control_run(false, 7, 0, -1) == -1 && errno == EPROTO);
	CHECK(control_run(false, 1, 2, -1) == -1 && errno == EPROTO);
	/* The gate must still be stopped after the daemon reply. */
	CHECK(control_run(false, 1, 0, 0) == -1 && errno == EBUSY);
	kernel.suspended = 1;
	/* Release: a stopped or released gate; only zero remaining. */
	CHECK(control_run(true, 1, 1, -1) == -1 && errno == EPROTO);
	CHECK(control_run(true, 1, 0, 0) == 0);		/* released by the daemon */
	kernel.suspended = 1;
	CHECK(control_run(true, 1, 0, -1) == -1 && errno == EBUSY);	/* still stopped */
	kernel.suspended = 0;
	CHECK(control_run(true, 1, 0, -1) == 0);		/* already released */
	/* No daemon listening. */
	{
		char path[400];
		snprintf(path, sizeof(path), "%s/ddtrace/sub.sock", root);
		(void)unlink(path);
		kernel.suspended = 1;
		CHECK(hypertrace_session_collectors_stop_step(&vm, token) == -1);
	}
	printf("hypertrace session control: 14 checks\n");
}

/* --------------------------------------------------------- HTX1 export */
static size_t
build_htx1(uint8_t *wire, const uint8_t token[16], size_t manifest)
{
	size_t length = DTRACED_TRANSFER_HEADER_SIZE + manifest;

	memset(wire, 0, length + 32);
	memcpy(wire, "HTX1", 4);
	memcpy(wire + 4, token, 16);
	dtraced_wire_put_u32(wire + 20, (uint32_t)manifest);
	dtraced_wire_put_u32(wire + 24, 0);
	if (manifest != 0)
		memcpy(wire + DTRACED_TRANSFER_HEADER_SIZE, "INGR", manifest < 4 ? manifest : 4);
	SHA256(wire, length, wire + length);
	return (length + 32);
}

static int export_mode;	/* 0 valid, 1 nack, 2 short, 3 long, 4 corrupt, 5 eof */

static int
export_script(int peer, struct daemon *d)
{
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_HANDOFF_WIRE_SIZE];
	uint8_t ack = export_mode == 1 ? 0 : 1;

	(void)d;
	CHECK(dtraced_io_read_size(peer, &length, deadline, &transferred) == 0);
	CHECK(length == sizeof(frame));
	CHECK(dtraced_io_transfer(peer, frame, length, false, deadline, &transferred) == 0);
	CHECK(dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred) == 0);
	if (ack != 1)
		return (0);
	switch (export_mode) {
	case 2:
		CHECK(dtraced_io_write_size(peer, 8, deadline, &transferred) == 0);
		return (0);
	case 3:
		CHECK(dtraced_io_write_size(peer, DTRACED_TRANSFER_MAX_SIZE + 1, deadline,
		    &transferred) == 0);
		return (0);
	case 5:
		CHECK(dtraced_io_write_size(peer, d->bundle_length, deadline,
		    &transferred) == 0);
		return (0);
	}
	if (export_mode == 4)
		d->bundle[d->bundle_length - 1] ^= 1;
	CHECK(dtraced_io_write_size(peer, d->bundle_length, deadline, &transferred) == 0);
	CHECK(dtraced_io_transfer(peer, d->bundle, d->bundle_length, true, deadline,
	    &transferred) == 0);
	return (0);
}

static void
test_export(void)
{
	uint8_t token[16] = { 0x33, 4 }, wire[256];
	void *bundle;
	size_t length;
	bool has_state;
	size_t controls;

	reset_state();
	CHECK(hypertrace_init(&vm) == 0);
	CHECK(hypertrace_handoff_source_bundle_fresh(&vm, token, NULL, &length) == -1 &&
	    errno == EINVAL);
	CHECK(hypertrace_handoff_source_bundle_fresh(&vm, token, &bundle, NULL) == -1);
	CHECK(hypertrace_handoff_source_bundle_fresh(NULL, token, &bundle, &length) == -1 &&
	    bundle == NULL && length == 0);
	CHECK(hypertrace_handoff_source_bundle_fresh(&vm, NULL, &bundle, &length) == -1);
	for (export_mode = 0; export_mode <= 5; export_mode++) {
		struct daemon d = { .expect_subs = DTD_SUB_READDATA };
		d.bundle = wire;
		d.bundle_length = build_htx1(wire, token, 0);
		daemon_start(&d, export_script);
		int result = hypertrace_handoff_source_bundle_fresh(&vm, token, &bundle, &length);
		int saved = errno;
		daemon_stop(&d);
		errno = saved;
		if (export_mode == 0) {
			CHECK(result == 0 && length == d.bundle_length &&
			    memcmp(bundle, wire, length) == 0);
			free(bundle);
		} else
			CHECK(result == -1 && bundle == NULL && length == 0);
	}
	/* Transfer inspection of exported bundles. */
	length = build_htx1(wire, token, 0);
	CHECK(hypertrace_transfer_inspect(wire, length, token, &has_state) == 0 && !has_state);
	CHECK(hypertrace_transfer_inspect(wire, length, token, NULL) == -1);
	CHECK(hypertrace_transfer_replay_controls(wire, length, token, &controls) == 0 &&
	    controls == 0);
	length = build_htx1(wire, token, 4);	/* an ingress manifest needs import */
	CHECK(hypertrace_transfer_inspect(wire, length, token, &has_state) == 0 && has_state);
	wire[0] = 'X';
	CHECK(hypertrace_transfer_inspect(wire, length, token, &has_state) == -1);
	CHECK(hypertrace_transfer_replay_controls(wire, length, token, &controls) == -1);
	printf("hypertrace HTX1 export: 16 checks\n");
}

/* ------------------------------------------- forwarder admission */
struct variant {
	int listener;
	int kind;		/* misbehaviour to perform */
	pthread_t thread;
};

static void
encode_kill(unsigned char *wire, int32_t pid, uint16_t vmid, uint64_t epoch, uint8_t seed)
{
	dtraced_replay_kill_t k = { .pid = pid, .vmid = vmid, .epoch = epoch };
	memset(k.source_id, seed, sizeof(k.source_id));
	dtraced_wire_encode_replay_kill(wire, &k);
}

static void *
variant_daemon(void *arg)
{
	struct variant *v = arg;
	int peer = accept(v->listener, NULL, NULL);
	dtd_initmsg_t hello = { .protocol_version = DTRACED_PROTOCOL_VERSION,
	    .kind = DTRACED_KIND_DTRACED };
	size_t transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	unsigned char count[4], kill[DTRACED_REPLAY_KILL_WIRE_SIZE];

	if (peer < 0)
		return (NULL);
	if (v->kind == 2)
		goto out;		/* close before the server init */
	if (v->kind == 1)
		hello.kind = DTRACED_KIND_FORWARDER;	/* not a daemon */
	CHECK(dtraced_wire_write_init(peer, &hello, deadline, &transferred) == 0);
	if (v->kind == 1)
		goto out;
	if (dtraced_wire_read_init(peer, &hello, deadline, &transferred) != 0)
		goto out;
	int identity = dtraced_io_recv_fd(peer, deadline);
	if (identity >= 0)
		close(identity);
	if (v->kind == 12)
		goto out;		/* no admission acknowledgment */
	uint8_t ack = v->kind == 3 ? 2 : 1;
	if (identity < 0 ||
	    dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred) != 0)
		goto out;
	if ((hello.subs & DTD_SUB_REPLAY_MANIFEST) == 0)
		goto out;
	if (v->kind == 15)
		goto out;		/* acknowledged, then lost before the count */
	uint32_t n = v->kind == 4 ? DTRACED_REPLAY_KILL_MAX + 1 : v->kind == 14 ? 0 : 3;
	dtraced_wire_put_u32(count, n);
	if (dtraced_io_transfer(peer, count, 4, true, deadline, &transferred) != 0)
		goto out;
	if (v->kind == 4)
		goto out;
	if (n == 0) {
		char b;
		(void)read(peer, &b, 1);
		goto out;
	}
	for (uint32_t i = 0; i < 3; i++) {
		int32_t pid = 10 + (int32_t)i;
		uint16_t vmid = 3;
		uint8_t seed = (uint8_t)(1 + i);
		if (v->kind == 5 && i == 1)
			vmid = 4;
		if (v->kind == 6 && i == 2)
			pid = 5;
		if (v->kind == 7 && i == 2)
			pid = 11, seed = 2;		/* duplicate of entry 1 */
		if (v->kind == 13 && i == 1)
			pid = 1;			/* not a valid process */
		if (v->kind == 16)
			pid = 10;			/* one process, ordered sources */
		uint64_t kepoch = v->kind == 17 && i == 1 ? 31 : 30;
		encode_kill(kill, pid, vmid, kepoch, seed);
		size_t len = v->kind == 8 && i == 2 ? 10 : sizeof(kill);
		if (dtraced_io_transfer(peer, kill, len, true, deadline, &transferred) != 0)
			break;
		if (len != sizeof(kill))
			break;
	}
	/* Hold the connection until the forwarder is done with it. */
	{
		char b;
		(void)read(peer, &b, 1);
	}
out:
	close(peer);
	return (NULL);
}

static int
variant_connect(int kind, uint64_t subs, struct ht_channel *ch)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	char path[400];
	struct variant v = { .kind = kind };
	int r, saved;

	snprintf(path, sizeof(path), "%s/ddtrace/sub.sock", root);
	(void)unlink(path);
	if (kind != 9) {
		v.listener = socket(AF_UNIX, SOCK_STREAM, 0);
		strlcpy(address.sun_path, path, sizeof(address.sun_path));
		CHECK(v.listener >= 0 && bind(v.listener, (struct sockaddr *)&address,
		    sizeof(address)) == 0 && listen(v.listener, 2) == 0);
		CHECK(pthread_create(&v.thread, NULL, variant_daemon, &v) == 0);
	}
	memset(ch, 0, sizeof(*ch));
	ch->fd = -1;
	r = ht_connect(ch, &vm, subs);
	saved = errno;
	if (r == 0)
		close(ch->fd);
	if (kind != 9) {
		shutdown(v.listener, SHUT_RDWR);
		CHECK(pthread_join(v.thread, NULL) == 0);
		close(v.listener);
	}
	errno = saved;
	return (r);
}

static void
test_admission(void)
{
	struct ht_channel ch;
	const uint64_t subs = DTD_SUB_ELFWRITE | DTD_SUB_KILL | DTD_SUB_CLEANUP |
	    DTD_SUB_ADMISSION_ACK | DTD_SUB_REPLAY_MANIFEST;
	int checks = 0;

	reset_state();
	CHECK(hypertrace_init(&vm) == 0);
	/* A valid admission with a three-entry ordered manifest. */
	CHECK(variant_connect(0, subs, &ch) == 0 && ch.replay_count == 3 &&
	    ch.replay_ready && ch.replay_vmid == 3 && ch.replay_epoch == 30 &&
	    ch.replay_kills[0].pid == 10 && ch.replay_kills[2].pid == 12);
	free(ch.replay_kills);
	checks++;
	/* Without the manifest subscription none is read. */
	CHECK(variant_connect(0, DTD_SUB_READDATA | DTD_SUB_ADMISSION_ACK, &ch) == 0 &&
	    !ch.replay_ready && ch.replay_count == 0);
	checks++;
	static const struct { int kind; int error; } cases[] = {
		{ 1, EPROTO }, { 3, EPROTO }, { 4, EPROTO }, { 5, EPROTO }, { 6, EPROTO },
		{ 7, EPROTO }, { 13, EPROTO },
	};
	for (size_t i = 0; i < nitems(cases); i++) {
		errno = 0;
		CHECK(variant_connect(cases[i].kind, subs, &ch) == -1 && errno == cases[i].error);
		checks++;
	}
	/* Transport losses at each stage. */
	static const int losses[] = { 2, 8, 9, 12 };
	for (size_t i = 0; i < nitems(losses); i++) {
		CHECK(variant_connect(losses[i], subs, &ch) == -1 && errno != 0);
		checks++;
	}
	/* Local refusals: an overlong VM name and no attestation descriptor. */
	{
		char long_name[300];
		const char *saved = vm.name;
		memset(long_name, 'v', sizeof(long_name) - 1);
		long_name[sizeof(long_name) - 1] = '\0';
		vm.name = long_name;
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == ENAMETOOLONG);
		vm.name = saved;
		fail_attestation = 1;
		CHECK(variant_connect(0, subs, &ch) == -1);
		fail_attestation = 0;
		vm.identity_failures = 1;
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == EPROTO);
		vm.identity_failures = 0;
		checks += 3;
	}
	/* An empty manifest; one process with ordered source ids. */
	CHECK(variant_connect(14, subs, &ch) == 0 && ch.replay_ready &&
	    ch.replay_count == 0 && ch.replay_kills == NULL);
	CHECK(variant_connect(16, subs, &ch) == 0 && ch.replay_count == 3 &&
	    ch.replay_kills[0].pid == 10 && ch.replay_kills[2].pid == 10 &&
	    ch.replay_kills[2].source_id[0] == 3);
	free(ch.replay_kills);
	/* A kill naming another epoch; the count lost after admission. */
	CHECK(variant_connect(17, subs, &ch) == -1 && errno == EPROTO);
	CHECK(variant_connect(15, subs, &ch) == -1 && errno != 0);
	/* The local identity cannot name a lifetime to bind the manifest. */
	vm.vmid = 0;
	CHECK(variant_connect(0, subs, &ch) == -1 && errno == EPROTO);
	vm.vmid = 3;
	vm.epoch = 0;
	CHECK(variant_connect(0, subs, &ch) == -1 && errno == EPROTO);
	vm.epoch = 30;
	checks += 6;
	/* Client socket faults, each failing the connection with its errno and
	 * leaking no descriptor; interrupted or in-progress connects complete. */
	{
		int fd_probe = dup(0), fd_after;
		close(fd_probe);
		arm_faults();
		fail_socket_at = 2;	/* after the test daemon's listener */
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == EMFILE);
		fail_cap_rights = 1;
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == ENOTCAPABLE);
		fail_send_at = 1;	/* the forwarder init */
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == EPIPE);
		fail_sendmsg_at = 1;	/* the attestation descriptor */
		CHECK(variant_connect(0, subs, &ch) == -1 && errno == EPIPE);
		connect_mode = 1;
		CHECK(variant_connect(0, subs, &ch) == 0 && ch.replay_count == 3);
		free(ch.replay_kills);
		connect_mode = 2;
		CHECK(variant_connect(0, subs, &ch) == 0 && ch.replay_count == 3);
		free(ch.replay_kills);
		connect_mode = 3;	/* never connected: completion fails */
		CHECK(variant_connect(0, subs, &ch) == -1);
		fd_after = dup(0);
		close(fd_after);
		CHECK(fd_after == fd_probe);	/* no descriptor leaked */
		checks += 8;
	}
	printf("hypertrace forwarder admission: %d checks\n", checks);
}

/* ------------------------------------------- receive and send frames */
static int peer_fd = -1;

static void
attach(struct ht_channel *ch)
{
	int sp[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	if (ch->fd >= 0)
		close(ch->fd);
	ch->fd = sp[0];
	ch->pending_delivery_id = 0;
	atomic_store(&ch->configured, true);
	if (peer_fd >= 0)
		close(peer_fd);
	peer_fd = sp[1];
}

static void
send_header(const dtraced_hdr_t *h)
{
	unsigned char wire[DTRACED_MSGHDRSIZE];

	dtraced_wire_encode_header(wire, h);
	CHECK(write(peer_fd, wire, sizeof(wire)) == (ssize_t)sizeof(wire));
}

static dtraced_hdr_t
elf_header(uint64_t delivery, size_t len)
{
	dtraced_hdr_t h;

	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_ELF;
	h.elf.len = len;
	h.elf.delivery_id = delivery;
	memset(h.elf.program_id, 1, sizeof(h.elf.program_id));
	memset(h.elf.source_id, 2, sizeof(h.elf.source_id));
	return (h);
}

static void
send_entry(const char *data, size_t len)
{
	size_t transferred;
	int64_t deadline = dtraced_io_milliseconds() + 2000;

	CHECK(dtraced_io_write_size(peer_fd, len, deadline, &transferred) == 0);
	CHECK(write(peer_fd, data, len) == (ssize_t)len);
}

static void
test_receive(void)
{
	void *buf;
	dtraced_hdr_t h, got;
	uint64_t epoch, connection;
	int checks = 0;

	/* An ELF frame is delivered whole and must be acknowledged. */
	attach(&rx);
	h = elf_header(77, 5);
	send_header(&h);
	CHECK(write(peer_fd, "\177ELF!", 5) == 5);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == 0 &&
	    got.msg_type == DTRACED_MSG_ELF && got.elf.delivery_id == 77 &&
	    memcmp(buf, "\177ELF!", 5) == 0);
	free(buf);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 && errno == EBUSY);
	CHECK(hypertrace_ack_epoch(epoch, connection, 78) == -1 && errno == ESTALE);
	CHECK(hypertrace_ack_epoch(epoch + 1, connection, 77) == -1 && errno == ESTALE);
	CHECK(hypertrace_ack_epoch(epoch, connection + 1, 77) == -1 && errno == ESTALE);
	CHECK(hypertrace_ack_epoch(epoch, connection, 0) == -1 && errno == ESTALE);
	CHECK(hypertrace_ack_epoch(epoch, connection, 77) == 0 && rx.pending_delivery_id == 0);
	{
		unsigned char ack[16];
		CHECK(read(peer_fd, ack, sizeof(ack)) > 0);
	}
	checks += 8;
	/* A KILL needs no acknowledgment; a cleanup is acknowledged. */
	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_KILL;
	h.kill.pid = 9;
	h.kill.vmid = 3;
	h.kill.epoch = 30;
	memset(h.kill.source_id, 3, sizeof(h.kill.source_id));
	send_header(&h);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == 0 &&
	    got.msg_type == DTRACED_MSG_KILL && rx.pending_delivery_id == 0 && buf == NULL);
	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_CLEANUP;
	DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 55;
	h.cleanup.vmid = 3;
	h.cleanup.epoch = 30;
	h.cleanup.num_entries = 2;
	send_header(&h);
	send_entry("probe-a", 8);
	send_entry("probe-bb", 9);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == 0 &&
	    rx.pending_delivery_id == 55);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 && errno == EBUSY);
	CHECK(hypertrace_ack_epoch(epoch, connection, 55) == 0);
	checks += 4;
	/* Every malformed frame retires the stream. */
	for (int bad = 0; bad < 17; bad++) {
		attach(&rx);
		uint64_t before = rx.connection_generation;
		memset(&h, 0, sizeof(h));
		switch (bad) {
		case 0: h = elf_header(7, 0); send_header(&h); break;
		case 1: h = elf_header(7, HT_MAX_FRAME + 1); send_header(&h); break;
		case 2: h = elf_header(0, 4); send_header(&h); break;
		case 3: h = elf_header(7, 4); memset(h.elf.program_id, 0, sizeof(h.elf.program_id));
			send_header(&h); break;
		case 4: h = elf_header(7, 4); memset(h.elf.source_id, 0, sizeof(h.elf.source_id));
			send_header(&h); break;
		case 5: h = elf_header(7, 4); send_header(&h);
			CHECK(write(peer_fd, "ab", 2) == 2); shutdown(peer_fd, SHUT_WR); break;
		case 6: h.msg_type = DTRACED_MSG_KILL; h.kill.pid = 5; send_header(&h); break;
		case 7: h.msg_type = DTRACED_MSG_CLEANUP; h.cleanup.num_entries = 1;
			send_header(&h); break;	/* delivery 0 */
		case 8: h.msg_type = DTRACED_MSG_CLEANUP; DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 1;
			h.cleanup.vmid = 3; h.cleanup.epoch = 30;
			h.cleanup.num_entries = HT_MAX_CLEANUP + 1; send_header(&h); break;
		case 9: h.msg_type = DTRACED_MSG_CLEANUP; DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 1;
			h.cleanup.vmid = 3; h.cleanup.epoch = 30;
			h.cleanup.num_entries = 1; send_header(&h); send_entry("", 0); break;
		case 10: h.msg_type = DTRACED_MSG_CLEANUP; DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 1;
			h.cleanup.vmid = 3; h.cleanup.epoch = 30;
			h.cleanup.num_entries = 1; send_header(&h);
			{
				size_t transferred;
				CHECK(dtraced_io_write_size(peer_fd, 5000,
				    dtraced_io_milliseconds() + 2000, &transferred) == 0);
			}
			break;
		case 11: h.msg_type = DTRACED_MSG_CLEANUP; DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 1;
			h.cleanup.vmid = 3; h.cleanup.epoch = 30;
			h.cleanup.num_entries = 1; send_header(&h); send_entry("abc", 3); break;
		case 12: h.msg_type = DTRACED_MSG_CLEANUP; DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 1;
			h.cleanup.vmid = 3; h.cleanup.epoch = 30;
			h.cleanup.num_entries = 1; send_header(&h); send_entry("a\0b", 4); break;
		case 13: h.msg_type = 0x77; send_header(&h); break;
		case 14: CHECK(write(peer_fd, "xx", 2) == 2); shutdown(peer_fd, SHUT_WR); break;
		/* A KILL that names a lifetime but no source program. */
		case 15: h.msg_type = DTRACED_MSG_KILL; h.kill.pid = 5; h.kill.vmid = 3;
			h.kill.epoch = 30; send_header(&h); break;
		/* A header that stalls after two bytes: the read deadline (10 s)
		 * expires with a partial frame, which retires the stream. */
		case 16: CHECK(write(peer_fd, "xx", 2) == 2); break;
		}
		buf = (void *)1;
		CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 && buf == NULL);
		CHECK(!atomic_load(&rx.configured) && rx.fd == -1 &&
		    rx.connection_generation == before + 1);
		checks += 2;
	}
	/* Not connected; invalid arguments; an ACK on a lost stream. */
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 && errno == ENOTCONN);
	CHECK(hypertrace_read_epoch(NULL, &got, &epoch, &connection) == -1 && errno == EINVAL);
	CHECK(hypertrace_read_epoch(&buf, NULL, &epoch, &connection) == -1 && errno == EINVAL);
	CHECK(hypertrace_read_epoch(&buf, &got, NULL, &connection) == -1 && errno == EINVAL);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, NULL) == -1 && errno == EINVAL);
	attach(&rx);
	h = elf_header(9, 1);
	send_header(&h);
	CHECK(write(peer_fd, "e", 1) == 1);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == 0);
	free(buf);
	close(peer_fd);
	peer_fd = -1;
	signal(SIGPIPE, SIG_IGN);
	CHECK(hypertrace_ack_epoch(epoch, connection, 9) == -1 && !atomic_load(&rx.configured));
	checks += 6;
	printf("hypertrace receive and acknowledge: %d checks\n", checks);
}

struct writer_peer {
	int fd, mode;	/* 0 ack 1, 1 ack 2, 2 close without ack */
	size_t expected;
	pthread_t thread;
};

static void *
writer_peer_main(void *arg)
{
	struct writer_peer *w = arg;
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	unsigned char frame[4096];

	if (dtraced_io_read_size(w->fd, &length, deadline, &transferred) == 0 &&
	    length <= sizeof(frame) &&
	    dtraced_io_transfer(w->fd, frame, length, false, deadline, &transferred) == 0) {
		w->expected = length;
		uint8_t ack = w->mode == 1 ? 2 : 1;
		if (w->mode != 2)
			(void)dtraced_io_transfer(w->fd, &ack, 1, true, deadline, &transferred);
	}
	close(w->fd);
	return (NULL);
}

static void
test_send(void)
{
	dtraced_hdr_t h;
	int checks = 0;
	char payload[64] = "payload";

	for (int mode = 0; mode < 3; mode++) {
		struct writer_peer w = { .mode = mode };
		attach(&wx);
		w.fd = peer_fd;
		peer_fd = -1;
		CHECK(pthread_create(&w.thread, NULL, writer_peer_main, &w) == 0);
		h = elf_header(4, 7);
		int r = hypertrace_write(&h, payload, 7);
		CHECK(pthread_join(w.thread, NULL) == 0);
		if (mode == 0)
			CHECK(r == 0 && w.expected == DTRACED_MSGHDRSIZE + 7 &&
			    atomic_load(&wx.configured));
		else
			CHECK(r == -1 && (mode != 1 || errno == EPROTO) && !atomic_load(&wx.configured));
		checks++;
	}
	/* A frame without payload. */
	{
		struct writer_peer w = { .mode = 0 };
		attach(&wx);
		w.fd = peer_fd;
		peer_fd = -1;
		CHECK(pthread_create(&w.thread, NULL, writer_peer_main, &w) == 0);
		memset(&h, 0, sizeof(h));
		h.msg_type = DTRACED_MSG_KILL_APPLIED;
		CHECK(hypertrace_write(&h, NULL, 0) == 0);
		CHECK(pthread_join(w.thread, NULL) == 0 && w.expected == DTRACED_MSGHDRSIZE);
		checks++;
	}
	/* Argument rules. */
	h = elf_header(4, 7);
	CHECK(hypertrace_write(NULL, payload, 7) == -1 && errno == EINVAL);
	CHECK(hypertrace_write(&h, NULL, 7) == -1 && errno == EINVAL);
	CHECK(hypertrace_write(&h, payload, 6) == -1 && errno == EINVAL);
	CHECK(hypertrace_write(&h, payload, HT_MAX_FRAME) == -1 && errno == EINVAL);
	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_KILL_APPLIED;
	CHECK(hypertrace_write(&h, payload, 1) == -1 && errno == EINVAL);
	ht_disconnect(&wx);
	CHECK(hypertrace_write(&h, NULL, 0) == -1 && errno == ENOTCONN);
	checks += 6;
	printf("hypertrace send: %d checks\n", checks);
}

/*
 * hypertrace_delivery_status()/hypertrace_ingress_status(): the daemon peer
 * reads one size-prefixed header, acknowledges it and replies with a 48-byte
 * status record written here by hand from the wire layout (delivery id LE64,
 * phase, revoked, replay, 5 reserved bytes, 32-byte digest).  Oracle: the
 * acceptance rule of the protocol for each reply (delivery status: phase in
 * {0,p,a,i,t,u}, a replay grant only for a live a/i owner with a digest, no
 * 'u' for a revoked source, a digest exactly when replay is granted; ingress
 * status: no replay, phase in {0,p,a}, a digest exactly when phase != 0);
 * a refused reply returns -1/EPROTO, zeroes the output and disconnects.
 */
struct status_peer {
	int fd, mode;			/* 0 reply, 1 ack 2, 2 close before ack, 3 short */
	unsigned char reply[48];
	pthread_t thread;
};

static void *
status_peer_main(void *arg)
{
	struct status_peer *p = arg;
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	unsigned char frame[DTRACED_MSGHDRSIZE];
	uint8_t ack = p->mode == 1 ? 2 : 1;

	if (dtraced_io_read_size(p->fd, &length, deadline, &transferred) == 0 &&
	    length == sizeof(frame) &&
	    dtraced_io_transfer(p->fd, frame, length, false, deadline, &transferred) == 0 &&
	    p->mode != 2) {
		(void)dtraced_io_transfer(p->fd, &ack, 1, true, deadline, &transferred);
		if (p->mode == 0)
			(void)dtraced_io_transfer(p->fd, p->reply, 48, true, deadline,
			    &transferred);
		else if (p->mode == 3)
			(void)dtraced_io_transfer(p->fd, p->reply, 20, true, deadline,
			    &transferred);
	}
	close(p->fd);
	return (NULL);
}

static dtraced_hdr_t
status_request(uint64_t type)
{
	dtraced_hdr_t h;

	memset(&h, 0, sizeof(h));
	h.msg_type = type;
	h.installed.delivery_id = 0x51;
	h.installed.vmid = 3;
	h.installed.epoch = 30;
	h.installed.program_id[0] = 1;
	h.installed.source_id[0] = 2;
	return (h);
}

static int
status_query(bool ingress, int mode, uint64_t id, uint8_t phase, uint8_t revoked,
    uint8_t replay, bool digest, dtraced_delivery_status_t *out)
{
	struct status_peer p = { .mode = mode };
	dtraced_hdr_t h = status_request(ingress ? DTRACED_MSG_INGRESS_STATUS :
	    DTRACED_MSG_STATUS);
	int r, saved;

	le64enc(p.reply, id);
	p.reply[8] = phase;
	p.reply[9] = revoked;
	p.reply[10] = replay;
	if (digest)
		memset(p.reply + 16, 0xd1, 32);
	attach(&wx);
	p.fd = peer_fd;
	peer_fd = -1;
	CHECK(pthread_create(&p.thread, NULL, status_peer_main, &p) == 0);
	r = ingress ? hypertrace_ingress_status(&h, out) : hypertrace_delivery_status(&h, out);
	saved = errno;
	CHECK(pthread_join(p.thread, NULL) == 0);
	errno = saved;
	return (r);
}

static void
test_query_status(void)
{
	static const struct { bool ingress; int mode; uint64_t id; uint8_t phase, revoked, replay;
	    bool digest, accept; } rows[] = {
		/* delivery status */
		{ false, 0, 0x51, 0, 0, 0, false, true },
		{ false, 0, 0x51, 'p', 0, 0, false, true },
		{ false, 0, 0x51, 'a', 0, 0, false, true },
		{ false, 0, 0x51, 'i', 1, 0, false, true },
		{ false, 0, 0x51, 't', 1, 0, false, true },
		{ false, 0, 0x51, 'u', 0, 0, false, true },
		{ false, 0, 0x51, 'x', 0, 0, false, false },	/* decodable, not a delivery phase */
		{ false, 0, 0x52, 'a', 0, 0, false, false },	/* another delivery */
		{ false, 0, 0x51, 'a', 0, 1, true, true },	/* replay grant, live owner */
		{ false, 0, 0x51, 'i', 0, 1, true, true },
		{ false, 0, 0x51, 'a', 1, 1, true, false },	/* revoked owner */
		{ false, 0, 0x51, 'p', 0, 1, true, false },	/* not accepted */
		{ false, 0, 0x51, 'a', 0, 1, false, false },	/* grant without digest */
		{ false, 0, 0x51, 'a', 0, 0, true, false },	/* digest without grant */
		{ false, 0, 0x51, 'u', 1, 0, false, false },	/* unavailable but revoked */
		{ false, 0, 0x51, 'q', 0, 0, false, false },	/* undecodable phase */
		{ false, 0, 0x51, 'a', 2, 0, false, false },	/* undecodable revoked */
		{ false, 1, 0x51, 'a', 0, 0, false, false },	/* daemon refused (ack 2) */
		{ false, 2, 0x51, 'a', 0, 0, false, false },	/* closed before ack */
		{ false, 3, 0x51, 'a', 0, 0, false, false },	/* short reply */
		/* ingress status */
		{ true, 0, 0x51, 0, 0, 0, false, true },
		{ true, 0, 0x51, 'p', 0, 0, true, true },
		{ true, 0, 0x51, 'a', 1, 0, true, true },
		{ true, 0, 0x51, 'a', 0, 0, false, false },	/* accepted without digest */
		{ true, 0, 0x51, 0, 0, 0, true, false },	/* absent with digest */
		{ true, 0, 0x51, 'i', 0, 0, true, false },	/* not an ingress phase */
		{ true, 0, 0x51, 'a', 0, 1, true, false },	/* ingress never replays */
	};
	dtraced_delivery_status_t st;
	int checks = 0;

	for (size_t i = 0; i < nitems(rows); i++) {
		memset(&st, 0x77, sizeof(st));
		errno = 0;
		int r = status_query(rows[i].ingress, rows[i].mode, rows[i].id, rows[i].phase,
		    rows[i].revoked, rows[i].replay, rows[i].digest, &st);
		if ((r == 0) != rows[i].accept)
			fprintf(stderr, "status row %zu: %d errno %d\n", i, r, errno);
		CHECK((r == 0) == rows[i].accept);
		if (rows[i].accept) {
			CHECK(st.delivery_id == 0x51 && st.phase == rows[i].phase &&
			    st.revoked == rows[i].revoked && st.replay == rows[i].replay &&
			    (st.digest[0] == (rows[i].digest ? 0xd1 : 0)));
			CHECK(atomic_load(&wx.configured));
		} else {
			dtraced_delivery_status_t zero = { 0 };
			CHECK(memcmp(&st, &zero, sizeof(st)) == 0 && !atomic_load(&wx.configured));
			if (rows[i].mode == 1 || (rows[i].mode == 0 && rows[i].revoked < 2 &&
			    rows[i].phase != 'q'))
				CHECK(errno == EPROTO);
		}
		checks += 2;
	}
	/* The request cannot be sent: the size prefix, then the header. */
	for (int at = 1; at <= 2; at++) {
		dtraced_delivery_status_t zero = { 0 };
		arm_faults();
		fail_send_at = at;
		CHECK(status_query(false, 0, 0x51, 'a', 0, 0, false, &st) == -1 && errno == EPIPE &&
		    !atomic_load(&wx.configured) && memcmp(&st, &zero, sizeof(st)) == 0);
		fail_send_at = 0;
		checks++;
	}
	/* Request contracts: each is EINVAL without any I/O. */
	{
		dtraced_hdr_t h;
		attach(&wx);
#define BAD(mutation) do { h = status_request(DTRACED_MSG_STATUS); mutation; \
	CHECK(hypertrace_delivery_status(&h, &st) == -1 && errno == EINVAL); checks++; } while (0)
		h = status_request(DTRACED_MSG_STATUS);
		CHECK(hypertrace_delivery_status(NULL, &st) == -1 && errno == EINVAL);
		CHECK(hypertrace_delivery_status(&h, NULL) == -1 && errno == EINVAL);
		CHECK(hypertrace_ingress_status(&h, &st) == -1 && errno == EINVAL);
		checks += 3;
		BAD(h.installed.delivery_id = 0);
		BAD(h.installed.vmid = 0);
		BAD(h.installed.epoch = 0);
		BAD(h.installed.program_id[0] = 0);
		BAD(h.installed.source_id[0] = 0);
#undef BAD
		CHECK(atomic_load(&wx.configured));	/* nothing was sent */
		ht_disconnect(&wx);
		h = status_request(DTRACED_MSG_STATUS);
		CHECK(hypertrace_delivery_status(&h, &st) == -1 && errno == ENOTCONN);
		checks += 2;
	}
	printf("hypertrace status queries: %zu replies, %d checks\n", nitems(rows), checks);
}

/*
 * Remaining receive, acknowledgment, send and replay-hand-over edges.
 * Oracles: the documented errno; a failure that loses stream position
 * disconnects the channel; an idle receive does not; replay kills are handed
 * over once, only to the lifetime that was admitted.
 */
static int
script_close(int peer, struct daemon *d)
{
	(void)peer;
	(void)d;
	return (0);
}

static int
script_ack_only(int peer, struct daemon *d)
{
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_SESSION_STOP_WIRE_SIZE], ack = 1;

	(void)d;
	if (dtraced_io_read_size(peer, &length, deadline, &transferred) == 0 &&
	    length == sizeof(frame) &&
	    dtraced_io_transfer(peer, frame, length, false, deadline, &transferred) == 0)
		(void)dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred);
	return (0);
}

static int
script_read_close(int peer, struct daemon *d)
{
	size_t length, transferred;
	int64_t deadline = dtraced_io_milliseconds() + 3000;
	uint8_t frame[DTRACED_MSGHDRSIZE + DTRACED_SESSION_STOP_WIRE_SIZE];

	(void)d;
	if (dtraced_io_read_size(peer, &length, deadline, &transferred) == 0)
		(void)dtraced_io_transfer(peer, frame, sizeof(frame), false, deadline,
		    &transferred);
	return (0);
}

static int
control_with(int (*script)(int, struct daemon *), bool release)
{
	struct daemon d = { .expect_subs = DTD_SUB_READDATA };
	uint8_t token[16] = { 0x10, 1 };
	int r, saved;

	daemon_start(&d, script);
	r = release ? hypertrace_session_release(&vm, token) :
	    hypertrace_session_collectors_stop_step(&vm, token);
	saved = errno;
	daemon_stop(&d);
	errno = saved;
	return (r);
}

static void
test_edges(void)
{
	void *buf;
	dtraced_hdr_t h, got;
	uint64_t epoch, connection;
	uint8_t token[16] = { 0x10, 1 }, zero[16] = { 0 };
	int checks = 0;

	/* Receive: an idle stream times out without losing the channel. */
	attach(&rx);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 &&
	    errno == EAGAIN && atomic_load(&rx.configured));
	/* A KILL without a source; a frame type the forwarder never reads. */
	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_KILL;
	h.kill.pid = 9;
	h.kill.vmid = 3;
	h.kill.epoch = 30;
	send_header(&h);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 &&
	    errno == EPROTO && !atomic_load(&rx.configured));
	attach(&rx);
	memset(&h, 0, sizeof(h));
	h.msg_type = DTRACED_MSG_KILL_APPLIED;
	h.kill.pid = 9;
	h.kill.vmid = 3;
	h.kill.epoch = 30;
	memset(h.kill.source_id, 3, sizeof(h.kill.source_id));
	send_header(&h);
	CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 &&
	    errno == EPROTO && !atomic_load(&rx.configured));
	/* A cleanup whose entry size, then entry body, never arrive. */
	for (int cut = 0; cut < 2; cut++) {
		attach(&rx);
		memset(&h, 0, sizeof(h));
		h.msg_type = DTRACED_MSG_CLEANUP;
		DTRACED_MSG_CLEANUP_DELIVERY_ID(h) = 55;
		h.cleanup.vmid = 3;
		h.cleanup.epoch = 30;
		h.cleanup.num_entries = 1;
		send_header(&h);
		if (cut == 1) {
			size_t transferred;
			CHECK(dtraced_io_write_size(peer_fd, 6,
			    dtraced_io_milliseconds() + 1000, &transferred) == 0);
		}
		shutdown(peer_fd, SHUT_WR);
		CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == -1 &&
		    !atomic_load(&rx.configured) && buf == NULL);
	}
	checks += 5;
	/* Acknowledgment: a channel lost since the read; a failed ack write. */
	for (int mode = 0; mode < 2; mode++) {
		attach(&rx);
		h = elf_header(77, 5);
		send_header(&h);
		CHECK(write(peer_fd, "\177ELF!", 5) == 5);
		CHECK(hypertrace_read_epoch(&buf, &got, &epoch, &connection) == 0);
		free(buf);
		if (mode == 0) {
			atomic_store(&rx.configured, false);
			CHECK(hypertrace_ack_epoch(epoch, connection, 77) == -1 && errno == ESTALE);
			atomic_store(&rx.configured, true);
			CHECK(hypertrace_ack_epoch(epoch, connection, 77) == 0);
		} else {
			arm_faults();
			fail_send_at = 1;
			CHECK(hypertrace_ack_epoch(epoch, connection, 77) == -1 &&
			    errno == EPIPE && !atomic_load(&rx.configured));
		}
		checks += 2;
	}
	/* Send: the header, then the payload, fails to go out. */
	for (int at = 2; at <= 3; at++) {
		char payload[8] = "payload";
		attach(&wx);
		arm_faults();
		fail_send_at = at;
		h = elf_header(4, 7);
		CHECK(hypertrace_write(&h, payload, 7) == -1 && errno == EPIPE &&
		    !atomic_load(&wx.configured));
		fail_send_at = 0;
		checks++;
	}
	/* Replay hand-over. */
	{
		dtraced_replay_kill_t *kills, *mine = calloc(1, sizeof(*mine));
		size_t count;
		CHECK(hypertrace_take_replay_kills(NULL, &kills, &count) == EINVAL);
		CHECK(hypertrace_take_replay_kills(&vm, NULL, &count) == EINVAL);
		CHECK(hypertrace_take_replay_kills(&vm, &kills, NULL) == EINVAL);
		attach(&rx);
		atomic_store(&restore_mode, false);
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ENOTCONN);
		atomic_store(&restore_mode, true);
		rx.replay_ready = false;
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ENOTCONN);
		rx.replay_ready = true;
		atomic_store(&rx.configured, false);
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ENOTCONN);
		atomic_store(&rx.configured, true);
		rx.replay_vmid = 3;
		rx.replay_epoch = 30;
		rx.replay_kills = mine;
		rx.replay_count = 1;
		vm.identity_failures = 1;
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ESTALE);
		rx.replay_vmid = 4;
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ESTALE);
		rx.replay_vmid = 3;
		rx.replay_epoch = 31;
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ESTALE &&
		    kills == NULL && count == 0);
		rx.replay_epoch = 30;
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == 0 &&
		    kills == mine && count == 1 && rx.replay_kills == NULL &&
		    !rx.replay_ready && !atomic_load(&restore_mode));
		CHECK(hypertrace_take_replay_kills(&vm, &kills, &count) == ENOTCONN);
		free(mine);
		ht_disconnect(&rx);
		checks += 11;
	}
	/* Session control: argument and gate refusals, then transport losses
	 * at each step of the exchange. */
	reset_state();
	CHECK(hypertrace_session_collectors_stop_step(&vm, token) == -1 && errno == EINVAL);
	CHECK(hypertrace_init(&vm) == 0);
	CHECK(ht_session_control_step(&vm, NULL, false) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_collectors_stop_step(&vm, zero) == -1);
	kernel.suspended = 1;
	memset(kernel.token, 0x99, 16);	/* stopped under another token */
	CHECK(hypertrace_session_release(&vm, token) == -1 && errno == EBUSY);
	memcpy(kernel.token, token, 16);
	CHECK(control_with(script_close, false) == -1);
	CHECK(control_with(script_read_close, false) == -1);
	CHECK(control_with(script_ack_only, false) == -1);
	for (int at = 2; at <= 3; at++) {
		struct daemon d = { .expect_subs = DTD_SUB_READDATA };
		daemon_start(&d, script_read_close);
		arm_faults();
		fail_send_at = at;	/* 1 is the forwarder init */
		CHECK(hypertrace_session_collectors_stop_step(&vm, token) == -1 && errno == EPIPE);
		fail_send_at = 0;
		daemon_stop(&d);
	}
	checks += 9;
	printf("hypertrace receive/ack/send/replay/control edges: %d checks\n", checks);
}

/*
 * Identity edges of the kernel gate helpers.  Oracle: EINVAL for missing
 * arguments, EPROTO for an identity that cannot name a lifetime, the
 * identity errno when any read fails, and ESTALE when the VM id or epoch
 * changes between the reads that bracket the gate query.
 */
static void
test_gate_identity(void)
{
	uint8_t token[16] = { 0x10, 1 };
	int checks = 0;

	reset_state();
	open_gate();
	kernel.suspended = 1;
	memcpy(kernel.token, token, 16);
	CHECK(hypertrace_session_host_stopped(NULL, token) == -1 && errno == EINVAL);
	CHECK(hypertrace_session_host_stopped(&vm, NULL) == -1 && errno == EINVAL);
	vm.vmid = HYPERTRACE_MAX_VMS;
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == EPROTO);
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == EPROTO);
	vm.vmid = 3;
	vm.epoch = 0;
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == EPROTO);
	vm.epoch = 30;
	checks += 5;
	/* The re-read inside the state check fails, or names another VM. */
	vm.fail_on_read = 2;
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == ENXIO);
	vm.flip_vmid = true;
	vm.identity_flip_after = 0;
	CHECK(hypertrace_session_host_stopped(&vm, token) == -1 && errno == ESTALE);
	vm.vmid = 3;
	checks += 2;
	/* host_stop's own final read: reads 1 (stop), 2-3 (state check), 4. */
	vm.fail_on_read = 4;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ENXIO);
	vm.flip_vmid = true;
	vm.identity_flip_after = 2;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ESTALE);
	vm.vmid = 3;
	vm.flip_vmid = false;
	vm.identity_flip_after = 2;
	CHECK(hypertrace_session_host_stop(&vm, token) == -1 && errno == ESTALE);
	vm.epoch = 30;
	vm.identity_flip_after = -1;
	vm.fail_on_read = 0;
	CHECK(hypertrace_session_host_stop(&vm, token) == 0);
	checks += 4;
	printf("hypertrace gate identity edges: %d checks\n", checks);
}

/*
 * Lifecycle: the connector thread admits both channels (rx, with the replay
 * manifest in restore mode, and wx), start_ready() waits for both, a
 * cancellation or timeout ends the wait, and retirement joins the connector.
 * The daemon accepts any number of channels and answers each handshake.
 * Oracles: start_ready's result and errno; both channels configured exactly
 * when it succeeds; the rx channel carries a replay manifest only in restore
 * mode; retirement leaves no channel configured.
 */
struct multi_daemon {
	int listener, accepted;
	bool replay_seen;
	pthread_t thread;
};

static void *
multi_daemon_main(void *arg)
{
	struct multi_daemon *m = arg;
	int peers[8], n = 0;

	for (;;) {
		int peer = accept(m->listener, NULL, NULL);
		if (peer < 0)
			break;
		dtd_initmsg_t hello = { .protocol_version = DTRACED_PROTOCOL_VERSION,
		    .kind = DTRACED_KIND_DTRACED };
		size_t transferred;
		int64_t deadline = dtraced_io_milliseconds() + 3000;
		uint8_t ack = 1;
		if (dtraced_wire_write_init(peer, &hello, deadline, &transferred) != 0 ||
		    dtraced_wire_read_init(peer, &hello, deadline, &transferred) != 0) {
			close(peer);
			continue;
		}
		int identity = dtraced_io_recv_fd(peer, deadline);
		if (identity >= 0)
			close(identity);
		if ((hello.subs & DTD_SUB_ADMISSION_ACK) != 0)
			(void)dtraced_io_transfer(peer, &ack, 1, true, deadline, &transferred);
		if ((hello.subs & DTD_SUB_REPLAY_MANIFEST) != 0) {
			unsigned char count[4] = { 0 };
			m->replay_seen = true;
			(void)dtraced_io_transfer(peer, count, 4, true, deadline, &transferred);
		}
		m->accepted++;
		if (n < 8)
			peers[n++] = peer;
		else
			close(peer);
	}
	for (int i = 0; i < n; i++)
		close(peers[i]);
	return (NULL);
}

static void
multi_start(struct multi_daemon *m)
{
	struct sockaddr_un address = { .sun_family = AF_UNIX };
	char path[400];

	memset(m, 0, sizeof(*m));
	snprintf(path, sizeof(path), "%s/ddtrace/sub.sock", root);
	(void)unlink(path);
	m->listener = socket(AF_UNIX, SOCK_STREAM, 0);
	strlcpy(address.sun_path, path, sizeof(address.sun_path));
	CHECK(m->listener >= 0 && bind(m->listener, (struct sockaddr *)&address,
	    sizeof(address)) == 0 && listen(m->listener, 4) == 0);
	CHECK(pthread_create(&m->thread, NULL, multi_daemon_main, m) == 0);
}

static void
multi_stop(struct multi_daemon *m)
{
	shutdown(m->listener, SHUT_RDWR);
	close(m->listener);
	CHECK(pthread_join(m->thread, NULL) == 0);
}

static void *
retire_later(void *arg)
{
	(void)arg;
	usleep(200000);
	CHECK(hypertrace_retire_transport() == 0);
	return (NULL);
}

static void
test_lifecycle(void)
{
	struct multi_daemon m;
	int checks = 0;

	/* One channel configured is not a configured transport. */
	reset_state();
	attach(&rx);
	ht_disconnect(&wx);
	CHECK(!hypertrace_configured());
	ht_disconnect(&rx);
	/* The recovery witness descriptor refuses a failed rights limit. */
	fail_cap_rights = 1;
	CHECK(hypertrace_session_recovery_open() == ENOTCAPABLE && session_gate_fd == -1);
	checks += 2;
	/* Init: a gate descriptor whose rights cannot be limited is dropped
	 * (session_gate_error records why) but init succeeds. */
	reset_state();
	fail_cap_rights = 2;	/* 1 is the socket directory */
	CHECK(hypertrace_init(&vm) == 0 && session_gate_fd == -1 &&
	    session_gate_error == ENOTCAPABLE);
	CHECK(hypertrace_start(NULL) == -1 && errno == EINVAL);
	checks += 2;
	/* start_ready before init. */
	CHECK(hypertrace_retire_transport() == 0);
	CHECK(hypertrace_start_ready(&vm, 100) == -1 && errno == EINVAL &&
	    !atomic_load(&restore_mode));
	checks++;
	/* Restore admission of both channels, then one idle connector pass. */
	reset_state();
	CHECK(hypertrace_init(&vm) == 0);
	multi_start(&m);
	CHECK(hypertrace_start_ready(&vm, 2999) == 0 && hypertrace_configured() &&
	    rx.replay_ready && m.replay_seen && m.accepted == 2);
	pthread_mutex_lock(&lifecycle);
	pthread_cond_broadcast(&reconnect);
	pthread_mutex_unlock(&lifecycle);
	usleep(100000);
	CHECK(m.accepted == 2);	/* nothing reconnected */
	CHECK(hypertrace_retire_transport() == 0 && !hypertrace_configured() && !started);
	multi_stop(&m);
	checks += 3;
	/* Ordinary start: rx is admitted without a replay manifest. */
	reset_state();
	CHECK(hypertrace_init(&vm) == 0);
	multi_start(&m);
	CHECK(hypertrace_start(&vm) == 0);
	for (int i = 0; i < 300 && !hypertrace_configured(); i++)
		usleep(10000);
	CHECK(hypertrace_configured() && !m.replay_seen && !rx.replay_ready);
	CHECK(hypertrace_retire_transport() == 0);
	multi_stop(&m);
	checks += 2;
	/* No daemon: the wait times out, or is cancelled by retirement. */
	{
		char path[400];
		pthread_t t;
		snprintf(path, sizeof(path), "%s/ddtrace/sub.sock", root);
		(void)unlink(path);
		reset_state();
		CHECK(hypertrace_init(&vm) == 0);
		CHECK(hypertrace_start_ready(&vm, 300) == -1 && errno == ETIMEDOUT);
		CHECK(hypertrace_retire_transport() == 0);
		reset_state();
		CHECK(hypertrace_init(&vm) == 0);
		CHECK(pthread_create(&t, NULL, retire_later, NULL) == 0);
		CHECK(hypertrace_start_ready(&vm, 5000) == -1 && errno == ECANCELED);
		CHECK(pthread_join(t, NULL) == 0);
		/* Starting again while running: start_ready restores the mode. */
		reset_state();
		CHECK(hypertrace_init(&vm) == 0 && hypertrace_start(&vm) == 0);
		CHECK(hypertrace_start_ready(&vm, 100) == -1 && errno == EALREADY &&
		    !atomic_load(&restore_mode));
		CHECK(hypertrace_retire_transport() == 0);
		checks += 5;
	}
	reset_state();
	printf("hypertrace lifecycle: %d checks\n", checks);
}

int
main(void)
{
	make_root();
	test_retirement_witness();
	test_host_gate();
	test_init();
	test_control_step();
	test_export();
	test_admission();
	test_receive();
	test_send();
	test_query_status();
	test_edges();
	test_gate_identity();
	test_lifecycle();
	/* Destroying the transport with the recovery witness open closes it. */
	hypertrace_session_recovery_close();
	prepared = false;
	CHECK(hypertrace_session_recovery_open() == 0 && session_gate_fd >= 0);
	hypertrace_destroy();
	CHECK(session_gate_fd == -1 && session_gate_error == ENXIO);
	printf("PASS: hypertrace.c production configuration\n");
	return (0);
}
