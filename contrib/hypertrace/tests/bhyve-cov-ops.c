/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Direct tests of migration_session.c internals in the production compile
 * configuration.  This translation unit includes the ORIGINAL source (its
 * coverage mapping names usr.sbin/bhyve/migration_session.c; coverage-bhyve.py
 * credits it only when every function's mapping equals the production
 * object's) and the adapter harness for the VM/device/HyperTrace boundaries.
 *
 * The production adapter operations are called in states the session core
 * never produces (defensive guards), with injected allocation and descriptor
 * failures, and with crafted retained owners and reconstruction states.  Each
 * case asserts the exact documented result and, where state is involved, that
 * no VM was resumed, retired or destroyed by a refused call.
 */
#include "migration_session.c"

#define main adapter_main
#include "bhyve-cov-adapter.c"
#undef main

#define OCHECK(x) CHECK(x)

/* ---------------------------------------------- allocation/I/O faults */
static atomic_int fail_malloc_at = 0;	/* fail the Nth large allocation */
static atomic_int large_allocs = 0;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);

static bool
allocation_fails(size_t size)
{
	if (size < 4096 || atomic_load(&fail_malloc_at) == 0)
		return (false);
	if (atomic_fetch_add(&large_allocs, 1) + 1 == atomic_load(&fail_malloc_at)) {
		atomic_store(&fail_malloc_at, 0);
		return (true);
	}
	return (false);
}

void *
__wrap_malloc(size_t size)
{
	if (allocation_fails(size)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_malloc(size));
}

void *
__wrap_calloc(size_t n, size_t size)
{
	if (n != 0 && size != 0 && n <= SIZE_MAX / size && allocation_fails(n * size)) {
		errno = ENOMEM;
		return (NULL);
	}
	return (__real_calloc(n, size));
}

static void
arm_large_allocation(int nth)
{
	atomic_store(&large_allocs, 0);
	atomic_store(&fail_malloc_at, nth);
}

static int
large_allocation_count(void)
{
	return (atomic_load(&large_allocs));
}

static void
fail_next_large_allocation(int nth)
{
	atomic_store(&large_allocs, 0);
	atomic_store(&fail_malloc_at, nth);
}

/* Descriptor-level faults for the plain transport (merged: send/recv with
 * MSG_DONTWAIT and a monotonic deadline). */
static int io_fd = -1;
static int poll_result = 99, poll_errno, poll_revents = -1, poll_eintr;
static int recv_eintr, send_eintr, send_zero, send_eagain, recv_error, send_error;
static int clock_fail_at, clock_calls, clock_errno;
int __real_poll(struct pollfd *, nfds_t, int);
ssize_t __real_recv(int, void *, size_t, int);
ssize_t __real_send(int, const void *, size_t, int);
int __real_clock_gettime(clockid_t, struct timespec *);

int
__wrap_poll(struct pollfd *fds, nfds_t n, int timeout)
{
	if (n == 1 && fds[0].fd == io_fd && poll_eintr > 0) {
		poll_eintr--;
		errno = EINTR;
		return (-1);
	}
	if (n == 1 && fds[0].fd == io_fd && poll_revents >= 0) {
		fds[0].revents = (short)poll_revents;
		poll_revents = -1;
		return (1);
	}
	if (n == 1 && fds[0].fd == io_fd && poll_result != 99) {
		int r = poll_result;
		poll_result = 99;
		if (r < 0)
			errno = poll_errno;
		return (r);
	}
	return (__real_poll(fds, n, timeout));
}

ssize_t
__wrap_recv(int fd, void *buf, size_t len, int flags)
{
	if (fd == io_fd && recv_eintr > 0) {
		recv_eintr--;
		errno = EINTR;
		return (-1);
	}
	if (fd == io_fd && recv_error != 0) {
		errno = recv_error == FAULT_NOERRNO ? 0 : recv_error;
		recv_error = 0;
		return (-1);
	}
	return (__real_recv(fd, buf, len, flags));
}

ssize_t
__wrap_send(int fd, const void *buf, size_t len, int flags)
{
	if (fd == io_fd && send_eintr > 0) {
		send_eintr--;
		errno = EINTR;
		return (-1);
	}
	if (fd == io_fd && send_eagain > 0) {
		send_eagain--;
		errno = EAGAIN;
		return (-1);
	}
	if (fd == io_fd && send_zero > 0) {
		send_zero--;
		return (0);
	}
	if (fd == io_fd && send_error != 0) {
		errno = send_error == FAULT_NOERRNO ? 0 : send_error;
		send_error = 0;
		return (-1);
	}
	return (__real_send(fd, buf, len, flags));
}

/* Fail the Nth monotonic clock read after arming (deadline or remaining). */
int
__wrap_clock_gettime(clockid_t clock, struct timespec *ts)
{
	if (clock == CLOCK_MONOTONIC && clock_fail_at > 0 && ++clock_calls == clock_fail_at) {
		clock_fail_at = 0;
		errno = clock_errno;
		return (-1);
	}
	return (__real_clock_gettime(clock, ts));
}

static void
arm_clock(int nth, int error)
{
	clock_calls = 0;
	clock_errno = error;
	clock_fail_at = nth;
}

/* Socket-setup faults for the destination vsock pair (nth call of NAME). */
static const char *sk_name;
static int sk_at, sk_calls, sk_errno, gso_got = -1;
static bool
sk_hit(const char *name)
{
	if (sk_name == NULL || strcmp(sk_name, name) != 0 || ++sk_calls != sk_at)
		return (false);
	sk_name = NULL;
	errno = sk_errno;
	return (true);
}
int __real_socketpair(int, int, int, int *);
int __real_setsockopt(int, int, int, const void *, socklen_t);
int __real_getsockopt(int, int, int, void *, socklen_t *);
int __real_cap_rights_limit(int, const cap_rights_t *);
int __real_cap_xfer_limit(int, int);
int __real_cap_cloexec_limit(int, int);
int __real_cap_clofork_limit(int, int);
int __wrap_socketpair(int d, int t, int p, int *sv)
{ return (sk_hit("socketpair") ? -1 : __real_socketpair(d, t, p, sv)); }
int __wrap_setsockopt(int fd, int l, int o, const void *v, socklen_t n)
{ return (sk_hit("setsockopt") ? -1 : __real_setsockopt(fd, l, o, v, n)); }
int __wrap_getsockopt(int fd, int l, int o, void *v, socklen_t *n)
{
	int r;

	if (sk_hit("getsockopt"))
		return (-1);
	r = __real_getsockopt(fd, l, o, v, n);
	if (r == 0 && gso_got == -2) {	/* a short reply */
		*n = sizeof(char);
		gso_got = -1;
	} else if (r == 0 && gso_got >= 0) {	/* a smaller buffer than asked */
		*(int *)v = gso_got;
		gso_got = -1;
	}
	return (r);
}
int __wrap_cap_rights_limit(int fd, const cap_rights_t *r)
{ return (sk_hit("cap_rights_limit") ? -1 : __real_cap_rights_limit(fd, r)); }
int __wrap_cap_xfer_limit(int fd, int st)
{ return (sk_hit("cap_xfer_limit") ? -1 : __real_cap_xfer_limit(fd, st)); }
int __wrap_cap_cloexec_limit(int fd, int st)
{ return (sk_hit("cap_cloexec_limit") ? -1 : __real_cap_cloexec_limit(fd, st)); }
int __wrap_cap_clofork_limit(int fd, int st)
{ return (sk_hit("cap_clofork_limit") ? -1 : __real_cap_clofork_limit(fd, st)); }

static void
arm_socket(const char *name, int nth, int error)
{
	sk_name = name;
	sk_at = nth;
	sk_calls = 0;
	sk_errno = error;
}

/* ------------------------------------------------------- transport */
static void
test_fd_transport(void)
{
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	uint8_t buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 }, in[8];
	uint64_t deadline;
	int pair[2], timeout_ms, cases = 0;

	/* Deadlines: none for a non-positive timeout; remaining time is
	 * unbounded without one, ETIMEDOUT once passed, clamped to INT_MAX. */
	CHECK(migration_fd_deadline(0, &deadline) == 0 && deadline == UINT64_MAX);
	CHECK(migration_fd_deadline(-5, &deadline) == 0 && deadline == UINT64_MAX);
	CHECK(migration_fd_remaining(UINT64_MAX, &timeout_ms) == 0 && timeout_ms == -1);
	CHECK(migration_fd_remaining(1, &timeout_ms) == ETIMEDOUT);
	CHECK(migration_fd_remaining(UINT64_MAX - 1, &timeout_ms) == 0 && timeout_ms == INT_MAX);
	CHECK(migration_fd_deadline(1000, &deadline) == 0 && deadline != UINT64_MAX);
	CHECK(migration_fd_remaining(deadline, &timeout_ms) == 0 &&
	    timeout_ms > 0 && timeout_ms <= 1000);
	arm_clock(1, ENXIO);
	CHECK(migration_fd_deadline(10, &deadline) == ENXIO);
	arm_clock(1, 0);
	CHECK(migration_fd_deadline(10, &deadline) == EIO);
	arm_clock(1, EFAULT);
	CHECK(migration_fd_remaining(5, &timeout_ms) == EFAULT);
	arm_clock(1, 0);
	CHECK(migration_fd_remaining(5, &timeout_ms) == EIO);
	cases += 11;

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	migration_transport_fd_init(&xp, &fdx, pair[0], 20);
	CHECK(fdx.fd == pair[0] && fdx.io_timeout_ms == 20);
	io_fd = pair[0];
	/* Timeout with no data. */
	CHECK(xp.xp_recv(xp.xp_cookie, in, sizeof(in)) == ETIMEDOUT);
	/* poll failure is reported with its errno, or EIO without one; an
	 * interrupted poll is retried until the deadline. */
	poll_result = -1;
	poll_errno = ENOMEM;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ENOMEM);
	poll_result = -1;
	poll_errno = 0;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == EIO);
	poll_eintr = 2;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ETIMEDOUT && poll_eintr == 0);
	/* An invalid descriptor reported by poll; revents without the
	 * requested event, error or hangup keeps waiting. */
	poll_revents = POLLNVAL;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == EBADF);
	poll_revents = POLLPRI;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ETIMEDOUT);
	/* Clock failures while computing the deadline or the remaining time. */
	arm_clock(1, ENXIO);
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ENXIO);
	arm_clock(2, ENXIO);
	CHECK(xp.xp_send(xp.xp_cookie, buf, 1) == ENXIO);
	arm_clock(1, EFAULT);
	CHECK(xp.xp_send(xp.xp_cookie, buf, 1) == EFAULT);
	arm_clock(2, EROFS);
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == EROFS);
	/* recv EAGAIN, then the poll wait's own clock read fails. */
	arm_clock(3, ENOSPC);
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ENOSPC);
	cases += 11;
	/* Interrupted and would-block sends and receives are retried. */
	send_eintr = 2;
	send_eagain = 1;
	CHECK(xp.xp_send(xp.xp_cookie, buf, sizeof(buf)) == 0);
	CHECK(read(pair[1], in, sizeof(in)) == (ssize_t)sizeof(in) && memcmp(in, buf, 8) == 0);
	CHECK(write(pair[1], buf, sizeof(buf)) == (ssize_t)sizeof(buf));
	recv_eintr = 2;
	CHECK(xp.xp_recv(xp.xp_cookie, in, sizeof(in)) == 0 && memcmp(in, buf, 8) == 0);
	/* A zero-length send is a closed stream; other errors are returned,
	 * EIO when errno is unset. */
	send_zero = 1;
	CHECK(xp.xp_send(xp.xp_cookie, buf, sizeof(buf)) == EPIPE);
	send_error = ENOBUFS;
	CHECK(xp.xp_send(xp.xp_cookie, buf, sizeof(buf)) == ENOBUFS);
	send_error = FAULT_NOERRNO;
	CHECK(xp.xp_send(xp.xp_cookie, buf, sizeof(buf)) == EIO);
	recv_error = ENOTCONN;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ENOTCONN);
	recv_error = FAULT_NOERRNO;
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == EIO);
	cases += 7;
	/* A full send buffer: the bounded wait times out. */
	{
		uint8_t block[4096];
		struct migration_transport_fd *c = xp.xp_cookie;
		memset(block, 0x5a, sizeof(block));
		while (send(pair[0], block, sizeof(block), MSG_DONTWAIT) > 0)
			;
		CHECK(xp.xp_send(xp.xp_cookie, block, sizeof(block)) == ETIMEDOUT);
		/* No timeout: a poll failure is still reported. */
		c->io_timeout_ms = 0;
		poll_result = -1;
		poll_errno = EINVAL;
		CHECK(xp.xp_send(xp.xp_cookie, block, sizeof(block)) == EINVAL);
		c->io_timeout_ms = 20;
		cases += 2;
	}
	/* Peer close: EOF on receive, EPIPE on send (never SIGPIPE). */
	{
		uint8_t drain[4096];
		while (recv(pair[1], drain, sizeof(drain), MSG_DONTWAIT) > 0)
			;
	}
	close(pair[1]);
	{
		uint8_t drain[4096];
		while (recv(pair[0], drain, sizeof(drain), MSG_DONTWAIT) > 0)
			;
	}
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == ECONNRESET);
	CHECK(xp.xp_send(xp.xp_cookie, buf, sizeof(buf)) == EPIPE);
	io_fd = -1;
	/* A closed descriptor fails at once. */
	close(pair[0]);
	CHECK(xp.xp_recv(xp.xp_cookie, in, 1) == EBADF);
	CHECK(xp.xp_send(xp.xp_cookie, buf, 1) == EBADF);
	cases += 4;
	printf("ops transport: %d cases\n", cases);
}

/* ----------------------------------------------------- send/recv core */
static atomic_int progress_calls;
static struct migration_stat last_stat;

static void
progress_update(void *cookie, const struct migration_stat *stat)
{
	CHECK(cookie == &progress_calls);
	last_stat = *stat;
	atomic_fetch_add(&progress_calls, 1);
}

static void
test_session_helpers(void)
{
	struct migration_session sess;
	struct migration_transport xp;
	struct migration_transport_fd fdx;
	struct migration_session_config config = {0};
	struct migration_progress progress = { .mp_update = progress_update,
	    .mp_cookie = &progress_calls };
	struct migration_progress silent = { .mp_update = NULL };
	struct migration_frame_header hdr;
	uint8_t *payload;
	size_t len;
	volatile int cancel = 0;
	int pair[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	migration_transport_fd_init(&xp, &fdx, pair[0], 1000);
	memset(&sess, 0, sizeof(sess));
	sess.xp = &xp;
	/* Progress: absent configuration, absent callback, delivered stats. */
	migration_progress_report(&sess, MIGRATION_PHASE_PRECOPY, 1, 2, 3, false);
	sess.config = &config;
	migration_progress_report(&sess, MIGRATION_PHASE_PRECOPY, 1, 2, 3, false);
	config.progress = &silent;
	migration_progress_report(&sess, MIGRATION_PHASE_PRECOPY, 1, 2, 3, false);
	config.progress = &progress;
	migration_progress_report(&sess, MIGRATION_PHASE_STOPCOPY, 4, 5, 6, true);
	CHECK(progress_calls == 1 && last_stat.phase == MIGRATION_PHASE_STOPCOPY &&
	    last_stat.round == 4 && last_stat.bytes_sent == 5 &&
	    last_stat.last_dirty_pages == 6 && last_stat.converged);
	/* Cancellation flag. */
	CHECK(!migration_cancelled(&sess));
	config.cancel = &cancel;
	CHECK(!migration_cancelled(&sess));
	cancel = 1;
	CHECK(migration_cancelled(&sess));
	/* Send limits. */
	CHECK(migration_send(&sess, MIGRATION_MSG_HELLO, 0, NULL,
	    (size_t)MIGRATION_MAX_PAYLOAD + 1) == EMSGSIZE);
	sess.send_seq = UINT32_MAX;
	CHECK(migration_send(&sess, MIGRATION_MSG_HELLO, 0, NULL, 0) == EOVERFLOW);
	sess.send_seq = 0;
	CHECK(migration_send(&sess, 0, 0, NULL, 0) == EINVAL && sess.send_seq == 0);
	fail_next_large_allocation(1);
	{
		uint8_t big[8192] = {0};
		CHECK(migration_send(&sess, MIGRATION_MSG_DEV_STATE, 0, big, sizeof(big)) == ENOMEM);
	}
	CHECK(sess.send_seq == 0);
	/* Receive: sequence overflow, version pinning, allocation, payload. */
	sess.recv_seq = UINT32_MAX;
	CHECK(migration_send_reason(&sess, MIGRATION_MSG_ABORT, 1, 2) == 0);
	{
		struct migration_session peer = { .xp = &xp };
		struct migration_transport pxp;
		struct migration_transport_fd pfd;
		migration_transport_fd_init(&pxp, &pfd, pair[1], 1000);
		peer.xp = &pxp;
		int first = migration_recv(&peer, &hdr, &payload, &len);
		if (first != 0)
			fprintf(stderr, "first recv %d\n", first);
		CHECK(first == 0);
		CHECK(hdr.type == MIGRATION_MSG_ABORT && len == MIGRATION_REASON_SIZE);
		free(payload);
		peer.recv_seq = UINT32_MAX;
		CHECK(migration_send_reason(&sess, MIGRATION_MSG_ABORT, 1, 2) == 0);
		CHECK(migration_recv(&peer, &hdr, &payload, &len) == EOVERFLOW);
		/* Merged: the exhausted sequence is refused before the header is
		 * read, so the whole frame is still queued; drain it. */
		uint8_t sink[MIGRATION_FRAME_HDR_SIZE + MIGRATION_REASON_SIZE];
		CHECK(read(pair[1], sink, sizeof(sink)) == (ssize_t)sizeof(sink));
		peer.recv_seq = 2;
		peer.version = MIGRATION_PROTO_VERSION;
		sess.version = MIGRATION_PROTO_VERSION;
		CHECK(migration_send_reason(&sess, MIGRATION_MSG_ABORT, 1, 2) == 0);
		CHECK(migration_recv(&peer, &hdr, &payload, &len) == 0);
		free(payload);
		/* A large payload that cannot be allocated. */
		{
			uint8_t big[8192] = {0};
			CHECK(migration_send(&sess, MIGRATION_MSG_DEV_STATE, 0, big, sizeof(big)) == 0);
			fail_next_large_allocation(1);
			CHECK(migration_recv(&peer, &hdr, &payload, &len) == ENOMEM);
			uint8_t sink2[8192];
			size_t got = 0;
			while (got < sizeof(sink2)) {
				ssize_t r = read(pair[1], sink2 + got, sizeof(sink2) - got);
				CHECK(r > 0);
				got += (size_t)r;
			}
		}
		/* Payload truncated by the peer closing mid-frame. */
		CHECK(migration_send_reason(&sess, MIGRATION_MSG_ABORT, 1, 2) == 0);
		peer.recv_seq = 4;	/* the unallocatable frame was seq 4 */
		{
			/* Consume the header only, then make the payload read fail. */
			struct migration_transport_fd *pc = pxp.xp_cookie;
			pc->io_timeout_ms = 1000;
		}
		close(pair[0]);
		/* The whole frame is still buffered: it is received intact. */
		CHECK(migration_recv(&peer, &hdr, &payload, &len) == 0);
		free(payload);
		CHECK(migration_recv(&peer, &hdr, &payload, &len) == ECONNRESET);
	}
	close(pair[1]);
	printf("ops session helpers: 22 cases\n");
}

/* --------------------------------------------------- adapter guards */
static struct migration_prod_source *
fresh_source(void)
{
	struct migration_prod_source *src = calloc(1, sizeof(*src));
	struct hypertrace_session_record r = { .vmid = 7, .epoch = 70, .stop_token = 1,
	    .features = HYPERTRACE_SESSION_FEATURES };

	src->ctx = &vm;
	src->recovery_dirfd = -1;
	src->controller_fd = -1;
	CHECK(hypertrace_session_record_encode(src->fresh_record,
	    sizeof(src->fresh_record), &r) == 0);
	return (src);
}

static void
test_source_guards(void)
{
	struct migration_prod_source *src;
	struct migration_commit_binding binding;
	uint8_t challenge[32] = { 9 };
	bool runnable;
	int error;

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	devices_init();
	tracing_mode = false;
	src = fresh_source();
	/* prod_next_backed without highmem: everything past lowmem ends. */
	src->lowmem_len = 4 * PAGE;
	src->track_len = 4 * PAGE;
	CHECK(prod_next_backed(src, 2 * PAGE) == 2 * PAGE);
	CHECK(prod_next_backed(src, 4 * PAGE) == 4 * PAGE);
	src->highmem_base = 8 * PAGE;
	src->highmem_len = 2 * PAGE;
	src->track_len = 10 * PAGE;
	CHECK(prod_next_backed(src, 5 * PAGE) == 8 * PAGE);
	CHECK(prod_next_backed(src, 9 * PAGE) == 9 * PAGE);
	CHECK(prod_next_backed(src, 10 * PAGE) == 10 * PAGE);
	/* Hello failure propagates from the fill helper. */
	src->ctx = NULL;
	{
		struct migration_hello h;
		CHECK(prod_local_hello(src, &h) == EINVAL);
		CHECK(prod_dest_local_hello(&(struct migration_prod_dest){ .ctx = NULL }, &h) == EINVAL);
	}
	src->ctx = &vm;
	/* Merged: pre-copy refuses a VM without low memory, or regions that
	 * are not dirty-granule aligned, or a high region below or overlapping
	 * low memory or past the address space (EINVAL, before arming). */
	fake_lowmem = 0;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_lowmem = LOWMEM + MIGRATION_DIRTY_GRANULARITY / 2;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_lowmem = LOWMEM;
	fake_highmem = HIGHMEM + MIGRATION_DIRTY_GRANULARITY / 2;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_highmem = HIGHMEM;
	fake_highbase = LOWMEM - MIGRATION_DIRTY_GRANULARITY;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_highbase = HIGHBASE + MIGRATION_DIRTY_GRANULARITY / 2;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_highbase = UINT64_MAX - MIGRATION_DIRTY_GRANULARITY + 1;
	CHECK(prod_precopy_enable(src) == EINVAL);
	fake_highbase = HIGHBASE;
	/* Pre-copy round: an invalid range, allocation failure, a full chunk. */
	{
		uint8_t buf[2 * (12 + PAGE)];
		struct migration_memgen gen;
		size_t written;
		uint64_t dirty;
		bool converged, more;

		/* Merged baseline walk: the first generation copies every backed
		 * page without a bitmap; only later generations collect dirty
		 * bits.  The final (stop-copy) round needs a completed baseline. */
		CHECK(prod_precopy_enable(src) == 0);
		CHECK(prod_precopy_round(src, true, &gen, buf, sizeof(buf), &written,
		    &dirty, &converged, &more) == EPROTO);
		CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
		    &dirty, &converged, &more) == 0);
		CHECK(more && dirty == 2 && written == sizeof(buf) && !converged);
		CHECK(src->gen_active && src->cursor == 2 * PAGE && src->bitmap == NULL);
		CHECK(le64dec(buf) == 0 && le64dec(buf + 12 + PAGE) == PAGE &&
		    memcmp(buf + 12, vm.low, PAGE) == 0);
		{
			/* The baseline covers exactly the backed pages: all of low
			 * memory and all of high memory, nothing in the hole. */
			uint64_t total = dirty;
			while (more) {
				CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf),
				    &written, &dirty, &converged, &more) == 0);
				total += dirty;
			}
			CHECK(total == (LOWMEM + HIGHMEM) / PAGE);
			CHECK(src->baseline_done && !src->gen_active && !converged);
			CHECK(gen.cpu_identity == 0 && gen.length == TRACK_LEN);
		}
		/* A dirty generation: misaligned range, bitmap allocation failure
		 * and a failed collection each leave no generation active. */
		src->track_gpa = 1;
		CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
		    &dirty, &converged, &more) == EINVAL && !src->gen_active);
		src->track_gpa = 0;
		fail_next_large_allocation(1);
		/* The tracked-range bitmap is 128 KiB here, a large allocation. */
		CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
		    &dirty, &converged, &more) == ENOMEM && !src->gen_active);
		/* Generations continue until the dirty set is exhausted; with the
		 * guest stopped a later round converges. */
		{
			int calls = 0;
			do {
				CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf),
				    &written, &dirty, &converged, &more) == 0);
				calls++;
			} while (more);
			CHECK(calls > 0 && !src->gen_active && gen.cpu_identity != 0);
			vm.cpus_paused = true;	/* the guest writes no more */
			CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
			    &dirty, &converged, &more) == 0);
			if (dirty != 0) {	/* the last generation's writes */
				while (more)
					CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf),
					    &written, &dirty, &converged, &more) == 0);
				CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf),
				    &written, &dirty, &converged, &more) == 0);
			}
			vm.cpus_paused = false;
			CHECK(dirty == 0 && converged && !more && written == 0);
			/* The final round is admitted after the baseline. */
			vm.cpus_paused = true;
			CHECK(prod_precopy_round(src, true, &gen, buf, sizeof(buf), &written,
			    &dirty, &converged, &more) == 0);
			vm.cpus_paused = false;
			/* A failed collection frees the bitmap; the tracker is then
			 * cleanup-only (an earlier chunk may have cleared bits), so
			 * every later generation is refused until re-enabled. */
			inject("vm_dirty_log_request", 1, EIO);
			CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
			    &dirty, &converged, &more) == EIO);
			nfaults = 0;
			CHECK(!src->gen_active && src->bitmap == NULL);
			CHECK(prod_precopy_round(src, false, &gen, buf, sizeof(buf), &written,
			    &dirty, &converged, &more) != 0 && !src->gen_active);
		}
		/* A backed page that cannot be mapped fails the generation. */
		CHECK(prod_precopy_disable(src) == 0);
		CHECK(prod_precopy_enable(src) == 0);
		src->lowmem_len = LOWMEM + PAGE;
		do {
			error = prod_precopy_round(src, false, &gen, buf, sizeof(buf),
			    &written, &dirty, &converged, &more);
		} while (error == 0 && more);
		CHECK(error == EFAULT && !src->gen_active && src->bitmap == NULL);
		src->lowmem_len = LOWMEM;
		CHECK(prod_precopy_disable(src) == 0 && src->bitmap == NULL);
		/* Without high memory the tracked range ends at low memory. */
		fake_highmem = 0;
		CHECK(prod_precopy_enable(src) == 0 && src->track_len == fake_lowmem);
		CHECK(prod_precopy_disable(src) == 0);
		fake_highmem = HIGHMEM;
	}
	/* Quiesce: device pause fails and its own rollback cannot resume. */
	nfaults = 2;
	faults[0] = (typeof(faults[0])){ 'S', "vm_pause_devices",
	    *boundary_count("vm_pause_devices") + 1, EIO };
	faults[1] = (typeof(faults[1])){ 'S', "vm_resume_devices",
	    *boundary_count("vm_resume_devices") + 1, EBUSY };
	CHECK(prod_quiesce(src, &runnable) == EBUSY && !runnable && src->quiesced);
	CHECK(vm.cpus_paused && vm.console_paused);	/* never restarted */
	src->quiesced = false;
	vm.cpus_paused = vm.console_paused = false;
	faults[1] = (typeof(faults[1])){ 'S', "fbsdrun_migration_resume_cpus",
	    *boundary_count("fbsdrun_migration_resume_cpus") + 1, EAGAIN };
	faults[0].occurrence = *boundary_count("vm_pause_devices") + 1;
	CHECK(prod_quiesce(src, &runnable) == EAGAIN && !runnable && src->quiesced);
	nfaults = 0;
	vm.cpus_paused = vm.console_paused = vm.devices_paused = false;
	/* Resume after retirement began is cancelled without touching state. */
	src->retirement_started = true;
	CHECK(prod_resume(src) == ECANCELED);
	src->retirement_started = false;
	/* Fresh device state failure leaves no digest. */
	src->fresh_stopped = true;
	vm.cpus_paused = vm.devices_paused = true;
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'S', "vm_snapshot_fresh_dev_state_to_mem",
	    *boundary_count("vm_snapshot_fresh_dev_state_to_mem") + 1, ENOSPC };
	{
		uint8_t *blob = NULL;
		size_t len = 0;
		CHECK(prod_dev_state(src, &blob, &len) == ENOSPC && blob == NULL);
	}
	nfaults = 0;
	/* COMMIT binding guards. */
	memset(&binding, 0, sizeof(binding));
	binding.destination_vmid = 9;
	binding.destination_epoch = 90;
	src->fresh_stopped = false;
	/* Protocol 2 ordinary mode: the binding must name a real destination and
	 * echo the digest of the device state this source sent. */
	memset(src->recovery.state_digest, 0x6b, 32);
	memset(binding.state_digest, 0x6b, 32);
	memset(binding.challenge, 0x2c, 32);
	src->recovery.phase = 1;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	src->recovery.phase = 0;
	binding.destination_vmid = 0;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_vmid = 9;
	binding.destination_epoch = 0;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_epoch = 90;
	binding.state_digest[31] ^= 1;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	CHECK(src->recovery.destination_vmid == 0);
	binding.state_digest[31] ^= 1;
	CHECK(prod_accept_commit(src, &binding) == 0 &&
	    src->recovery.destination_vmid == 9 && src->recovery.destination_epoch == 90 &&
	    src->recovery.challenge[0] == 0x2c);
	memset(&src->recovery, 0, sizeof(src->recovery));
	memset(&binding, 0, sizeof(binding));
	binding.destination_vmid = 9;
	binding.destination_epoch = 90;
	src->fresh_stopped = true;
	src->recovery.phase = 1;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	src->recovery.phase = 0;
	src->fresh_record[0] ^= 1;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	src->fresh_record[0] ^= 1;
	binding.destination_vmid = 0;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_vmid = HYPERTRACE_MAX_VMS;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_vmid = 9;
	binding.destination_epoch = 0;
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_epoch = 70;	/* the stopped source epoch */
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	binding.destination_epoch = 90;
	binding.state_digest[0] = 1;	/* not the digest of the sent state */
	CHECK(prod_accept_commit(src, &binding) == EPROTO);
	memcpy(binding.state_digest, src->recovery.state_digest, 32);
	src->recovery_dirfd = -1;
	CHECK(prod_accept_commit(src, &binding) == EBADF);	/* journal root check */
	/* Recovery record guards. */
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT - 1, challenge) == EPROTO);
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_CONFIRMED + 1, challenge) == EPROTO);
	src->quiesced = false;
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT, challenge) == EPROTO);
	src->quiesced = true;
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT, challenge) == EPROTO);
	memcpy(src->recovery.challenge, challenge, 32);
	src->retired = true;
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT, challenge) == EPROTO);
	src->retired = false;
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_RETIRED, challenge) == EPROTO);
	/* An ordinary source whose handoff journal cannot take INTENT: the
	 * record fails and INTENT stays pending (no lock taken). */
	{
		int ro = private_dir("ro-journal", 0500);
		bool saved = src->fresh_stopped;
		src->fresh_stopped = false;
		src->recovery_dirfd = ro;
		CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT, challenge) != 0);
		CHECK(!src->controller_held && src->intent_pending);
		src->fresh_stopped = saved;
		src->recovery_dirfd = -1;
		src->intent_pending = false;
		close(ro);
	}
	/* Rollback repair is refused once retirement began, before any resume
	 * attempt; a source that is not quiesced needs no repair. */
	{
		struct migration_prod_source *r = fresh_source();
		unsigned attempts = 0;
		r->quiesced = true;
		r->retirement_started = true;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM && attempts == 0);
		r->retirement_started = false;
		r->quiesced = false;
		CHECK(prod_repair_rollback(r, &attempts) == EALREADY && attempts == 0);
		free(r);
	}
	/* INTENT with an undecodable session record cannot take the lock. */
	quarantined = 0;
	CHECK(prod_source_record(src, MIGRATION_REC_SOURCE_INTENT, challenge) == EPROTO);
	CHECK(src->retirement_started && src->intent_pending && quarantined == 1);
	CHECK(!src->controller_held);
	/* Retirement guards. */
	{
		struct migration_prod_source *r = fresh_source();
		CHECK(prod_retire(r) == EBUSY && r->retirement_started);	/* not quiesced */
		r->quiesced = true;
		r->fresh_stopped = true;
		r->fresh_record[4] = 9;		/* corrupt the stopped session */
		CHECK(prod_retire(r) == EPROTO && !vm.destroyed);
		free(r);
	}
	/* Destruction while another retirement is draining is refused. */
	{
		struct vmctx *ctx = &vm;
		migration_retiring_ctx = &vm;
		CHECK(prod_retire_destroy(&ctx, false, 0, 0) == EBUSY && ctx == &vm);
		migration_retiring_ctx = NULL;
		CHECK(prod_retire_drain() == 0);
		/* A failed destroy without errno is reported as EIO. */
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'S', "vm_destroy_request_checked",
		    *boundary_count("vm_destroy_request_checked") + 1, FAULT_NOERRNO };
		errno = 0;
		CHECK(prod_retire_destroy(&ctx, false, 0, 0) == EIO && ctx == &vm);
		nfaults = 0;
		cpus_retiring = false;
	}
	/* Repair refusals. */
	{
		struct migration_prod_source *r = fresh_source();
		unsigned attempts = 0;
		r->quiesced = true;
		r->retirement_started = true;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM);
		r->retirement_started = false;
		r->retired = true;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM);
		r->retired = false;
		r->intent_pending = true;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM);
		r->intent_pending = false;
		r->ctx = NULL;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM);
		r->ctx = &vm;
		cpus_retiring = true;
		CHECK(prod_repair_rollback(r, &attempts) == EPERM);
		cpus_retiring = false;
		CHECK(attempts == 0);
		free(r);
	}
	free(src);
	printf("ops source guards: 52 cases\n");
}

/* A source that was not retired must never be made defunct. */
static void
test_defunct_guard(void)
{
	struct migration_prod_source *src;

	role = 'S';
	src = fresh_source();
	prod_defunct(src);	/* errx(1, ...) */
	abort();
}

static void
test_dest_guards(void)
{
	struct migration_prod_dest *dst = calloc(1, sizeof(*dst));
	struct migration_memgen gen;
	struct migration_commit_binding binding;
	uint8_t page[12 + PAGE];
	uint8_t challenge[32] = { 3 };

	role = 'D';
	fresh_workdir();
	vm_model_init(9, 90, 0x99);
	devices_init();
	vm.fenced = true;
	dst->ctx = &vm;
	dst->controller_fd = -1;
	dst->recovery_dirfd = -1;
	/* Memory staging guards (merged: round 1 is a complete, ordered RAM
	 * baseline; later rounds are increasing, backed and contiguous in round
	 * number). */
	memset(&gen, 0, sizeof(gen));
	gen.mode = MIGRATION_DIRTY_CLEAR;
	gen.length = HIGHBASE + HIGHMEM;
	CHECK(prod_dest_stage_mem(dst, NULL, NULL, 0) == EBADMSG);
	gen.mode = MIGRATION_DIRTY_OBSERVE;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.mode = MIGRATION_DIRTY_CLEAR;
	gen.final = 2;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.final = 0;
	gen.gpa = PAGE;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.gpa = 0;
	gen.length = LOWMEM;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.length = HIGHBASE + HIGHMEM;
	gen.round = 1;
	gen.final = 1;	/* the baseline can never be the final round */
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.final = 0;
	gen.round = 3;	/* the first round is the baseline */
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.round = 1;
	gen.page_count = 1;
	le64enc(page, PAGE);	/* the baseline starts at page 0 */
	le32enc(page + 8, PAGE);
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	le64enc(page, 1);	/* misaligned record */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	le64enc(page, 0);
	le32enc(page + 8, PAGE + 1);	/* past the buffer */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	le32enc(page + 8, PAGE / 2);	/* not one granule */
	CHECK(prod_dest_stage_mem(dst, &gen, page, 12 + PAGE / 2) == EBADMSG);
	le32enc(page + 8, PAGE);
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'D', "vm_map_gpa",
	    *boundary_count("vm_map_gpa") + 1, EIO };
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EFAULT);
	nfaults = 0;
	gen.page_count = 2;	/* count mismatch (the page itself is staged) */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	CHECK(dst->mem_last_end == PAGE);
	gen.page_count = 1;
	le64enc(page, PAGE);
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page) - 1) == EBADMSG);	/* trailing */
	/* An incomplete baseline cannot advance to round 2. */
	gen.round = 2;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.round = 1;
	/* Complete the baseline: low pages in order, then high memory. */
	for (uint64_t gpa = PAGE; gpa < LOWMEM; gpa += PAGE) {
		le64enc(page, gpa);
		memset(page + 12, (int)(gpa / PAGE), PAGE);
		CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == 0);
	}
	le64enc(page, LOWMEM);	/* the hole is never backed */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	for (uint64_t gpa = HIGHBASE; gpa < HIGHBASE + HIGHMEM; gpa += PAGE) {
		le64enc(page, gpa);
		CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == 0);
	}
	CHECK(vm.low[5 * PAGE] == 5 && dst->mem_last_end == HIGHBASE + HIGHMEM);
	/* Round 2 is sparse but increasing; rounds never skip or go back. */
	gen.round = 4;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.round = 2;
	gen.page_count = 0;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == 0);	/* empty generation */
	gen.page_count = 1;
	le64enc(page, 9 * PAGE);
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == 0);
	le64enc(page, 3 * PAGE);	/* behind the previous record */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == EBADMSG);
	gen.round = 1;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	gen.round = 3;
	le64enc(page, 3 * PAGE);	/* a new round restarts the order */
	CHECK(prod_dest_stage_mem(dst, &gen, page, sizeof(page)) == 0);
	dst->mem_round = UINT32_MAX;	/* no round after the last */
	gen.round = 0;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == EBADMSG);
	dst->mem_round = 3;
	/* Without high memory the expected length is low memory. */
	fake_highmem = 0;
	gen.round = 4;
	gen.length = LOWMEM;
	gen.page_count = 0;
	CHECK(prod_dest_stage_mem(dst, &gen, NULL, 0) == 0);
	fake_highmem = HIGHMEM;
	gen.length = HIGHBASE + HIGHMEM;
	/* Device staging allocation failure keeps the previous blob. */
	{
		uint8_t blob[8192] = { 1 };
		CHECK(prod_dest_stage_dev(dst, blob, sizeof(blob)) == 0);
		fail_next_large_allocation(1);
		CHECK(prod_dest_stage_dev(dst, blob, sizeof(blob)) == ENOMEM);
		CHECK(dst->dev_len == sizeof(blob));
		CHECK(prod_dest_stage_dev(dst, blob, 0) == 0 && dst->dev_len == 0);
	}
	/* Fresh commit of an undecodable blob is refused. */
	tracing_mode = true;
	CHECK(prod_dest_commit(dst) == EBADMSG && !dst->committed);
	/* Resume guards. */
	CHECK(prod_dest_resume(dst) == EBUSY);
	dst->committed = true;
	CHECK(prod_dest_resume(dst) == EPROTO && vm.resumes == 0);
	/* Prepare-commit guards. */
	/* Ordinary mode (no fresh device): COMMIT binds this VM's identity and
	 * the SHA-256 of the staged DEV_STATE; no journal is consulted. */
	{
		uint8_t digest[32];
		memset(&binding, 0, sizeof(binding));
		memset(binding.challenge, 0x31, 32);
		SHA256_CTX h;
		SHA256_Init(&h);
		SHA256_Update(&h, dst->dev_blob, dst->dev_len);
		SHA256_Final(digest, &h);
		CHECK(prod_prepare_commit(dst, &binding) == 0 &&
		    binding.destination_vmid == vm.vmid &&
		    binding.destination_epoch == vm.epoch &&
		    memcmp(binding.state_digest, digest, 32) == 0 &&
		    memcmp(dst->retained_binding.challenge, binding.challenge, 32) == 0);
		memset(&binding, 0, sizeof(binding));
	}
	dst->fresh_device = &fresh_device;
	dst->running = true;
	CHECK(prod_prepare_commit(dst, &binding) == EBUSY);
	dst->running = false;
	dst->committed = false;
	CHECK(prod_prepare_commit(dst, &binding) == EBUSY);
	dst->committed = true;
	CHECK(prod_prepare_commit(dst, &binding) == EBADF);	/* journal root */
	dst->recovery_dirfd = private_dir("dest", 0700);
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'D', "vm_get_identity",
	    *boundary_count("vm_get_identity") + 1, ENXIO };
	CHECK(prod_prepare_commit(dst, &binding) == ENXIO);
	nfaults = 0;
	/* Record guards. */
	CHECK(prod_dest_record(dst, MIGRATION_REC_DEST_STAGED - 1, challenge) == EPROTO);
	CHECK(prod_dest_record(dst, MIGRATION_REC_DEST_RUNNING + 1, challenge) == EPROTO);
	CHECK(prod_dest_record(dst, MIGRATION_REC_DEST_STAGED, challenge) == EPROTO);
	memcpy(dst->recovery.challenge, challenge, 32);
	CHECK(prod_dest_record(dst, MIGRATION_REC_DEST_RUNNING, challenge) == EPROTO);
	dst->committed = false;
	CHECK(prod_dest_record(dst, MIGRATION_REC_DEST_STAGED, challenge) == EPROTO);
	dst->committed = true;
	/* Preservation guards: a committed, paused fresh owner without a lock
	 * and without staged device state has nothing to preserve. */
	memset(&binding, 0, sizeof(binding));
	dst->committed = true;
	dst->running = false;
	dst->fresh_device = &fresh_device;
	dst->controller_fd = -1;
	free(dst->dev_blob);
	dst->dev_blob = NULL;
	dst->dev_len = 0;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);	/* no blob */
	{
		uint8_t blob[64] = { 1 };
		CHECK(prod_dest_stage_dev(dst, blob, sizeof(blob)) == 0);
	}
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);	/* challenge differs */
	memcpy(binding.challenge, challenge, 32);
	binding.state_digest[0] = 1;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);	/* digest differs */
	memcpy(binding.state_digest, dst->recovery.state_digest, 32);
	dst->controller_fd = 5;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);	/* already locked */
	dst->controller_fd = -1;
	dst->running = true;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);
	dst->running = false;
	dst->fresh_device = NULL;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);
	dst->fresh_device = &fresh_device;
	dst->committed = false;
	CHECK(prod_dest_preserve(dst, &binding) == EPROTO);
	dst->committed = true;
	{
		int saved = dst->recovery_dirfd;
		dst->recovery_dirfd = -1;
		CHECK(prod_dest_preserve(dst, &binding) == EBADF);	/* lock */
		dst->recovery_dirfd = saved;
	}
	/* Image retirement is housekeeping: only a running locked owner. */
	dst->running = false;
	prod_dest_image_retire(dst);
	dst->running = true;
	prod_dest_image_retire(dst);	/* no controller lock */
	dst->controller_fd = open("/dev/null", O_RDONLY);
	prod_dest_image_retire(dst);	/* no image: warns, state unchanged */
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'D', "unlinkat", *boundary_count("unlinkat") + 1, EIO };
	prod_dest_image_retire(dst);	/* removal fails: warns, state unchanged */
	nfaults = 0;
	CHECK(dst->running && vm.resumes == 0);
	/* Staged memory whose record count disagrees with its records. */
	{
		/* Rounds are monotonic per destination: continue from the last. */
		struct migration_memgen gen = { .round = dst->mem_round + 1,
		    .mode = MIGRATION_DIRTY_CLEAR, .gpa = 0, .length = HIGHBASE + HIGHMEM,
		    .page_count = 2 };
		uint8_t rec[12 + PAGE] = { 0 };
		le64enc(rec, 0);
		le32enc(rec + 8, PAGE);
		CHECK(prod_dest_stage_mem(dst, &gen, rec, sizeof(rec)) == EBADMSG);
		gen.round = dst->mem_round + 1;	/* records of one round arrive in order */
		gen.page_count = 1;
		CHECK(prod_dest_stage_mem(dst, &gen, rec, sizeof(rec)) == 0);
		/* Without high memory the expected range is low memory alone. */
		fake_highmem = 0;
		gen.round = dst->mem_round + 1;
		gen.length = LOWMEM;
		CHECK(prod_dest_stage_mem(dst, &gen, rec, sizeof(rec)) == 0);
		/* Trailing bytes too short for another record header. */
		{
			uint8_t rec2[12 + PAGE + 4] = { 0 };
			memcpy(rec2, rec, sizeof(rec));
			gen.round = dst->mem_round + 1;
			CHECK(prod_dest_stage_mem(dst, &gen, rec2, sizeof(rec2)) == EBADMSG);
		}
		{
			struct migration_dest_geometry g;
			prod_dest_geometry(&vm, &g);
			CHECK(g.highmem_length == 0 && g.highmem_base == 0 &&
			    g.lowmem_length == LOWMEM);
		}
		fake_highmem = HIGHMEM;
	}
	prod_dest_free(dst, open("/dev/null", O_RDONLY));
	printf("ops destination guards: 45 cases\n");
}

/* Retained owner validation (recovery). */
static void
test_owner_validation(void)
{
	struct migration_prod_dest *dst = calloc(1, sizeof(*dst));
	enum migration_recovery_destination observed;
	struct hypertrace_session_record r = { .vmid = 3, .epoch = 30, .stop_token = 5,
	    .features = HYPERTRACE_SESSION_FEATURES };
	uint8_t blob[100];
	SHA256_CTX hash;

	role = 'D';
	fresh_workdir();
	vm_model_init(9, 90, 0x99);
	vm.fenced = true;
	tracing_mode = true;
	CHECK(prod_dest_recovery_validate(NULL) == EINVAL);
	dst->ctx = &vm;
	dst->controller_fd = -1;
	CHECK(prod_dest_recovery_validate(dst) == EBUSY);
	dst->retained = dst->committed = true;
	dst->fresh_device = &fresh_device;
	memset(blob, 7, sizeof(blob));
	dst->dev_blob = malloc(sizeof(blob));
	memcpy(dst->dev_blob, blob, sizeof(blob));
	dst->dev_len = sizeof(blob);
	CHECK(hypertrace_session_record_encode(dst->fresh_record, sizeof(dst->fresh_record), &r) == 0);
	memcpy(dst->recovery.session, dst->fresh_record, sizeof(dst->fresh_record));
	dst->recovery.destination_vmid = dst->retained_binding.destination_vmid = 9;
	dst->recovery.destination_epoch = dst->retained_binding.destination_epoch = 90;
	SHA256_Init(&hash);
	SHA256_Update(&hash, blob, sizeof(blob));
	SHA256_Final(dst->recovery.state_digest, &hash);
	memcpy(dst->retained_binding.state_digest, dst->recovery.state_digest, 32);
	CHECK(prod_dest_recovery_validate(dst) == 0);
	/* Each missing element of a retained committed image is EBUSY. */
	dst->committed = false;
	CHECK(prod_dest_recovery_validate(dst) == EBUSY);
	dst->committed = true;
	dst->fresh_device = NULL;
	CHECK(prod_dest_recovery_validate(dst) == EBUSY);
	dst->fresh_device = &fresh_device;
	{
		uint8_t *saved = dst->dev_blob;
		dst->dev_blob = NULL;
		CHECK(prod_dest_recovery_validate(dst) == EBUSY);
		dst->dev_blob = saved;
	}
	dst->dev_len = 0;
	CHECK(prod_dest_recovery_validate(dst) == EBUSY);
	dst->dev_len = sizeof(blob);
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'D', "vm_get_identity",
	    *boundary_count("vm_get_identity") + 1, ENXIO };
	CHECK(prod_dest_recovery_validate(dst) == ENXIO);
	faults[0] = (typeof(faults[0])){ 'D', "vm_get_identity",
	    *boundary_count("vm_get_identity") + 1, FAULT_NOERRNO };
	CHECK(prod_dest_recovery_validate(dst) == EIO);
	nfaults = 0;
	vm.epoch = 91;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	vm.epoch = 90;
	vm.vmid = 8;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	vm.vmid = 9;
	dst->retained_binding.destination_vmid = 8;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->retained_binding.destination_vmid = 9;
	dst->retained_binding.destination_epoch = 1;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->retained_binding.destination_epoch = 90;
	dst->retained_binding.challenge[0] = 1;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->retained_binding.challenge[0] = 0;
	dst->recovery.session[30] ^= 1;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->recovery.session[30] ^= 1;
	dst->dev_blob[0] ^= 1;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->dev_blob[0] ^= 1;
	dst->retained_binding.state_digest[0] ^= 1;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->retained_binding.state_digest[0] ^= 1;
	/* A successor validates its own incarnation, not the original one. */
	dst->reconstructed = true;
	dst->incarnation_vmid = 9;
	dst->incarnation_epoch = 90;
	CHECK(prod_dest_recovery_validate(dst) == 0);
	dst->incarnation_epoch = 95;
	CHECK(prod_dest_recovery_validate(dst) == ESTALE);
	dst->reconstructed = false;
	/* Observation. */
	tracing_mode = false;
	CHECK(prod_dest_recovery_observe(dst, &observed) == EOPNOTSUPP &&
	    observed == MIGRATION_REC_VM_UNAVAILABLE);
	tracing_mode = true;
	vm.fenced = false;	/* paused owner must still hold the fence */
	CHECK(prod_dest_recovery_observe(dst, &observed) == EBUSY);
	vm.fenced = true;
	CHECK(prod_dest_recovery_observe(dst, &observed) == 0 &&
	    observed == MIGRATION_REC_VM_PAUSED);
	dst->running = true;
	CHECK(prod_dest_recovery_observe(dst, &observed) == EBUSY);
	vm.fenced = false;
	CHECK(prod_dest_recovery_observe(dst, &observed) == 0 &&
	    observed == MIGRATION_REC_VM_RUNNING);
	/* Resume through recovery only from PAUSED. */
	CHECK(prod_dest_recovery_resume(dst) == EBUSY && vm.resumes == 0);
	dst->running = false;
	vm.fenced = true;
	/* The resume itself fails: no image housekeeping, nothing resumed. */
	nfaults = 1;
	faults[0] = (typeof(faults[0])){ 'D', "vm_migrate_fresh_resume",
	    *boundary_count("vm_migrate_fresh_resume") + 1, EIO };
	CHECK(prod_dest_recovery_resume(dst) == EIO && vm.resumes == 0 && !dst->running);
	nfaults = 0;
	dst->dev_blob[0] ^= 1;
	CHECK(prod_dest_recovery_resume(dst) == ESTALE && vm.resumes == 0);
	dst->dev_blob[0] ^= 1;
	/* Release attempts. */
	dst->run_state.ack_sent = true;
	CHECK(migration_prod_dest_recover_release(dst, -1, NULL) == EINVAL &&
	    !dst->run_state.ack_sent);
	dst->run_state.resume_uncertain = true;
	CHECK(migration_prod_dest_recover_release(dst, -1, &(struct migration_tls_credentials){0}) == EBUSY);
	dst->run_state.resume_uncertain = false;
	vm.fenced = false;
	CHECK(migration_prod_dest_recover_release(dst, -1, &(struct migration_tls_credentials){0}) == EBUSY);
	vm.fenced = true;
	{
		struct migration_tls_credentials c = { -1, -1, -1, {0} };
		CHECK(migration_prod_dest_recover_release(dst, dead_peer(), &c) != 0);
	}
	{
		bool running, uncertain, ack;
		migration_prod_dest_recovery_status(dst, &running, &uncertain, &ack);
		CHECK(!running && !uncertain && !ack);
	}
	/* Recovery refuses a running owner that the startup fence says is
	 * paused, and an owner that no longer retains its image. */
	{
		struct migration_tls_credentials c = { -1, -1, -1, {0} };
		dst->running = true;
		CHECK(migration_prod_dest_recover_release(dst, 3, &c) == EBUSY);
		dst->running = false;
		dst->retained = false;
		CHECK(migration_prod_dest_recover_release(dst, 3, &c) == EBUSY);
		dst->retained = true;
	}
	/* Kernel-witness adapters map errno-less failures to EIO. */
	CHECK(prod_reconstruct_retired(NULL, 9, 90) == EBUSY);	/* live */
	CHECK(prod_reconstruct_retired(NULL, 99, 990) == ENOENT);
	CHECK(prod_reconstruct_destroy(NULL, "migrating-vm", 99, 990) == ENOENT);
	CHECK(prod_reconstruct_destroy(NULL, "migrating-vm", 9, 90) == 0);
	CHECK(prod_reconstruct_retired(NULL, 9, 90) == 0);
	printf("ops owner validation: 40 cases\n");
}

/* ------------------------------------------- adapter edges (in-process) */
/*
 * A TLS peer for in-process recovery calls: it completes the mutual
 * handshake with the given credentials, then closes, so the caller's later
 * I/O fails fast.  Oracle for the callers: the documented errno.
 */
struct tls_peer {
	struct migration_tls_credentials creds;
	int fd;
	pthread_t thread;
};

static void *
tls_peer_main(void *arg)
{
	struct tls_peer *p = arg;
	struct migration_channel ch;
	struct migration_transport xp;
	char b;

	if (migration_channel_init(&ch, &xp, p->fd, true, &p->creds, 5000) == 0) {
		(void)read(p->fd, &b, 1);	/* until the caller is done */
		migration_channel_cleanup(&ch);
	}
	close(p->fd);
	return (NULL);
}

static int
tls_peer_start(struct tls_peer *p, bool stranger)
{
	int sp[2];
	char hex[65];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sp) == 0);
	if (stranger) {
		p->creds.certificate_fd = open_file("stranger.pem");
		p->creds.private_key_fd = open_file("stranger.key");
		p->creds.trust_fd = open_file("source.pem");
		read_pin("source.pin", hex);
		CHECK(migration_credentials_pin(hex, p->creds.peer_certificate_sha256) == 0);
	} else
		destination_credentials(&p->creds);
	p->fd = sp[1];
	CHECK(pthread_create(&p->thread, NULL, tls_peer_main, p) == 0);
	return (sp[0]);
}

static void
tls_peer_stop(struct tls_peer *p, int fd)
{
	shutdown(fd, SHUT_RDWR);
	close(fd);
	CHECK(pthread_join(p->thread, NULL) == 0);
	close(p->creds.certificate_fd);
	close(p->creds.private_key_fd);
	close(p->creds.trust_fd);
}

static void
pins(uint8_t source[32], uint8_t destination[32])
{
	char hex[65];

	read_pin("source.pin", hex);
	CHECK(migration_credentials_pin(hex, source) == 0);
	read_pin("destination.pin", hex);
	CHECK(migration_credentials_pin(hex, destination) == 0);
}

static int
recover_ipc(int fd)
{
	nvlist_t *req = nvlist_create(0), *reply;
	int error;

	nvlist_move_descriptor(req, "fd", fd);
	source_credentials(req);
	reply = ipc_call("migrate_recover", req);
	nvlist_destroy(req);
	error = nvlist_exists_number(reply, "error_code") ?
	    (int)nvlist_get_number(reply, "error_code") : 0;
	nvlist_destroy(reply);
	return (error);
}

static void
test_adapter_edges(void)
{
	struct migration_prod_source *src = &migration_ipc_source;
	int checks = 0;

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	devices_init();
	tracing_mode = false;

	/* Handoff journal entries record whether the attempt was authenticated:
	 * both pins set, source only, or neither. */
	{
		struct migration_recovery_record r = intent_record(MIGRATION_REC_SOURCE_INTENT, 7, 70);
		struct migration_prod_dest dst = { .recovery_dirfd = -1 };
		int dirfd = private_dir("handoff", 0700);
		memset(r.source_certificate_sha256, 0, 32);
		memset(r.destination_certificate_sha256, 0, 32);
		CHECK(prod_handoff_phase(dirfd, MIGRATION_HANDOFF_SOURCE, &r) == 0);
		CHECK(prod_handoff_phase(-1, MIGRATION_HANDOFF_SOURCE, &r) == 0);
		memset(r.source_certificate_sha256, 0x33, 32);
		r.challenge[0] ^= 1;	/* another attempt: no mixing of tls flags */
		CHECK(prod_handoff_phase(dirfd, MIGRATION_HANDOFF_SOURCE, &r) == 0);
		memset(r.destination_certificate_sha256, 0x34, 32);
		r.challenge[0] ^= 2;
		CHECK(prod_handoff_phase(dirfd, MIGRATION_HANDOFF_SOURCE, &r) == 0);
		/* Resolution entries: none without a journal; tls flag variants. */
		CHECK(prod_handoff_resolution(&dst, MIGRATION_HANDOFF_RESOLVE,
		    MIGRATION_HANDOFF_RESUME, NULL, 0) == 0);
		dst.recovery_dirfd = dirfd;
		dst.recovery = r;
		dst.recovery.phase = MIGRATION_REC_DEST_STAGED;
		dst.recovery.challenge[0] ^= 4;
		CHECK(prod_handoff_phase(dirfd, MIGRATION_HANDOFF_DEST, &dst.recovery) == 0);
		CHECK(prod_handoff_resolution(&dst, MIGRATION_HANDOFF_RESOLVE,
		    MIGRATION_HANDOFF_DISCARD, NULL, 0) == 0);
		memset(dst.recovery.destination_certificate_sha256, 0, 32);
		/* A different tls flag than the attempt's phases: refused. */
		CHECK(prod_handoff_resolution(&dst, MIGRATION_HANDOFF_OUTCOME,
		    MIGRATION_HANDOFF_DISCARD, NULL, 0) == EPROTO);
		memset(dst.recovery.source_certificate_sha256, 0, 32);
		CHECK(prod_handoff_resolution(&dst, MIGRATION_HANDOFF_OUTCOME,
		    MIGRATION_HANDOFF_DISCARD, NULL, 0) == EPROTO);
		close(dirfd);
		checks += 9;
	}
	/* The local topology limit applies to every record kind: PCI devices,
	 * fwcfg, the TPM and the boot ROM identity (merged); an unencodable
	 * compatibility envelope is refused. */
	{
		struct migration_topology *t = calloc(1, sizeof(*t));
		many_devices_init(MIGRATION_MAX_DEVICES);	/* PCI alone overflows */
		CHECK(migration_prod_fill_topology(&vm, t) == E2BIG);
		many_devices_init(MIGRATION_MAX_DEVICES - 2);	/* PCI exactly full */
		CHECK(migration_prod_fill_topology(&vm, t) == E2BIG);	/* fwcfg */
		fwcfg_enabled = false;
		tpm_present = true;
		CHECK(migration_prod_fill_topology(&vm, t) == E2BIG);	/* TPM */
		tpm_present = false;
		CHECK(migration_prod_fill_topology(&vm, t) == E2BIG);	/* boot ROM */
		bootrom_absent = true;
		memset(t, 0, sizeof(*t));
		CHECK(migration_prod_fill_topology(&vm, t) == 0 &&
		    t->device_count == MIGRATION_MAX_DEVICES);
		many_devices_init(0);
		memset(t, 0, sizeof(*t));
		CHECK(migration_prod_fill_topology(&vm, t) == 0 && t->device_count == 2);
		bootrom_absent = false;
		fwcfg_enabled = true;
		compat_invalid = true;
		CHECK(migration_prod_fill_topology(&vm, t) != 0);
		compat_invalid = false;
		free(t);
		checks += 7;
	}
	/* A quarantined source refuses a new migration; repair reports it. */
	{
		nvlist_t *req = nvlist_create(0), *reply;
		memset(src, 0, sizeof(*src));
		src->ctx = &vm;
		src->retirement_started = true;
		reply = ipc_call("migrate", req);
		CHECK(strcmp(nvlist_get_string(reply, "error"), "migration source is quarantined") == 0 &&
		    !nvlist_get_bool(reply, "source_runnable"));
		nvlist_destroy(reply);
		reply = ipc_call("migrate_repair", req);
		CHECK(!nvlist_get_bool(reply, "repaired") && !nvlist_get_bool(reply, "source_runnable") &&
		    nvlist_get_number(reply, "error_code") == EPERM);
		nvlist_destroy(reply);
		src->retirement_started = false;
		src->quiesced = true;
		reply = ipc_call("migrate", req);
		CHECK(strcmp(nvlist_get_string(reply, "error"), "migration source is quarantined") == 0);
		nvlist_destroy(reply);
		/* A repair whose every resume attempt fails leaves the source
		 * quiesced and not runnable. */
		nfaults = 3;
		for (int i = 0; i < 3; i++)
			faults[i] = (typeof(faults[0])){ 'S', "vm_resume_devices",
			    *boundary_count("vm_resume_devices") + 1 + i, EIO };
		reply = ipc_call("migrate_repair", req);
		nfaults = 0;
		CHECK(!nvlist_get_bool(reply, "repaired") && !nvlist_get_bool(reply, "source_runnable") &&
		    nvlist_get_number(reply, "error_code") == EIO &&
		    nvlist_get_number(reply, "repair_attempts") == 3 && src->quiesced);
		nvlist_destroy(reply);
		memset(src, 0, sizeof(*src));
		nvlist_destroy(req);
		checks += 4;
	}
	/* Reconstruction's kernel callbacks map errno-less failures to EIO. */
	{
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'S', "hypertrace_session_retired",
		    *boundary_count("hypertrace_session_retired") + 1, FAULT_NOERRNO };
		CHECK(prod_reconstruct_retired(NULL, 7, 70) == EIO);
		faults[0] = (typeof(faults[0])){ 'S', "vm_destroy_name_identity_checked",
		    *boundary_count("vm_destroy_name_identity_checked") + 1, FAULT_NOERRNO };
		CHECK(prod_reconstruct_destroy(NULL, "migrating-vm", 7, 70) == EIO);
		nfaults = 0;
		checks += 2;
	}
	/* Destination admission edges through the prepared entry point. */
	{
		struct migration_session_config config = { .plaintext_unix = true };
		struct migration_dest_result result;
		struct migration_prod_dest *owner = (void *)&config, *none = NULL;
		int devnull = open("/dev/null", O_RDWR);
		role = 'D';
		CHECK(migration_prod_dest_serve_prepared(&vm, devnull, &config, &result, &owner) == EBUSY);
		/* The prepared entry point needs an owner slot (the caller holds
		 * the retained image); the implementation never sees NULL. */
		CHECK(migration_prod_dest_serve_prepared(&vm, devnull, &config, &result, NULL) == EINVAL);
		config.recovery_image = true;
		CHECK(migration_prod_dest_serve(&vm, devnull, &config, &result) == EINVAL &&
		    result.reason == MIGRATION_REASON_STATE);
		config.recovery_image = false;
		/* No owner, no recovery: the policy refuses a non-socket. */
		CHECK(migration_prod_dest_serve_prepared(&vm, devnull, &config, &result, &none) ==
		    EPROTONOSUPPORT && none == NULL && result.reason == MIGRATION_REASON_TRANSPORT);
		close(devnull);
		role = 'S';
		checks += 4;
	}
	/* Operator recovery through the original source process. */
	{
		struct tls_peer peer;
		int fd, error, dirfd;
		memset(src, 0, sizeof(*src));
		src->ctx = &vm;
		src->retirement_started = true;
		src->fresh_stopped = false;
		src->recovery_dirfd = -1;
		CHECK(recover_ipc(open("/dev/null", O_RDONLY)) == EOPNOTSUPP);
		src->fresh_stopped = true;
		CHECK(recover_ipc(open("/dev/null", O_RDONLY)) == EOPNOTSUPP);
		dirfd = private_dir("recover", 0700);
		src->recovery_dirfd = dirfd;
		pins(src->recovery.source_certificate_sha256,
		    src->recovery.destination_certificate_sha256);
		src->recovery.destination_certificate_sha256[0] ^= 1;
		fd = tls_peer_start(&peer, false);
		CHECK(recover_ipc(dup(fd)) == EACCES);
		tls_peer_stop(&peer, fd);
		src->recovery.destination_certificate_sha256[0] ^= 1;
		src->recovery.source_certificate_sha256[0] ^= 1;
		fd = tls_peer_start(&peer, false);
		CHECK(recover_ipc(dup(fd)) == EACCES);
		tls_peer_stop(&peer, fd);
		src->recovery.source_certificate_sha256[0] ^= 1;
		/* An unpublished INTENT can be retried only by the original,
		 * still quiesced, unretired process. */
		src->intent_pending = true;
		src->ctx = NULL;
		fd = tls_peer_start(&peer, false);
		CHECK(recover_ipc(dup(fd)) == ESTALE);
		tls_peer_stop(&peer, fd);
		src->ctx = &vm;
		src->retired = true;
		fd = tls_peer_start(&peer, false);
		CHECK(recover_ipc(dup(fd)) == ESTALE);
		tls_peer_stop(&peer, fd);
		src->retired = false;
		src->quiesced = false;
		fd = tls_peer_start(&peer, false);
		CHECK(recover_ipc(dup(fd)) == ESTALE);
		tls_peer_stop(&peer, fd);
		/* The record itself fails (journal not writable). */
		src->quiesced = true;
		memset(src->recovery.challenge, 0x31, 32);
		src->recovery.phase = 0;
		{
			int ro = private_dir("recover-ro", 0500);
			src->recovery_dirfd = ro;
			fd = tls_peer_start(&peer, false);
			error = recover_ipc(dup(fd));
			tls_peer_stop(&peer, fd);
			CHECK(error != 0 && error != ESTALE && error != EACCES);
			close(ro);
			src->recovery_dirfd = dirfd;
		}
		/* INTENT published, the VM context gone (restarted process state
		 * without a VM): the live lifetime cannot be retired here, EBUSY. */
		{
			struct migration_recovery_record rec = intent_record(MIGRATION_REC_SOURCE_INTENT, 7, 70);
			int dir3 = private_dir("recover-ctx", 0700);
			pins(rec.source_certificate_sha256, rec.destination_certificate_sha256);
			CHECK(migration_source_owner_at(dir3, &rec, true) == 0);
			CHECK(migration_recovery_store_at(dir3, &rec) == 0);
			src->recovery = rec;
			src->recovery_dirfd = dir3;
			src->intent_pending = false;
			src->ctx = NULL;
			fd = tls_peer_start(&peer, false);
			CHECK(recover_ipc(dup(fd)) == EBUSY);
			tls_peer_stop(&peer, fd);
			src->ctx = &vm;
			src->recovery_dirfd = dirfd;
			close(dir3);
			checks++;
		}
		pins(src->recovery.source_certificate_sha256,
		    src->recovery.destination_certificate_sha256);
		memset(src->recovery.challenge, 0x31, 32);
		src->recovery.destination_vmid = 0;	/* no destination binding */
		/* INTENT stands, then completion fails: the retained attempt
		 * record has no destination binding, so it cannot name a journal
		 * owner (EINVAL from the record codec). */
		src->intent_pending = false;
		src->recovery.phase = MIGRATION_REC_SOURCE_INTENT;
		fd = tls_peer_start(&peer, false);
		error = recover_ipc(dup(fd));
		tls_peer_stop(&peer, fd);
		CHECK(error == EINVAL);
		memset(src, 0, sizeof(*src));
		close(dirfd);
		checks += 8;
	}
	/* Restarted-process recovery: the authenticated connection must match
	 * the attempt's certificate pins; the named retirement path's faults. */
	{
		struct migration_tls_credentials creds;
		struct migration_recovery_record expected;
		struct tls_peer peer;
		int dirfd = private_dir("restart", 0700), fd, controller;
		restart_credentials(&creds);
		expected = intent_record(MIGRATION_REC_SOURCE_INTENT, 7, 70);
		CHECK(migration_source_owner_at(dirfd, &expected, true) == 0);
		CHECK(migration_recovery_store_at(dirfd, &expected) == 0);
		fd = tls_peer_start(&peer, false);
		CHECK(migration_prod_source_recover_restart_named(fd, dirfd, 7, 70, &creds, NULL) == EACCES);
		tls_peer_stop(&peer, fd);
		/* The source pin matches but the destination's does not. */
		{
			int dir2 = private_dir("restart-dest-pin", 0700);
			struct migration_recovery_record half = expected;
			pins(half.source_certificate_sha256, half.destination_certificate_sha256);
			half.destination_certificate_sha256[0] ^= 1;
			CHECK(migration_source_owner_at(dir2, &half, true) == 0);
			CHECK(migration_recovery_store_at(dir2, &half) == 0);
			fd = tls_peer_start(&peer, false);
			CHECK(migration_prod_source_recover_restart_named(fd, dir2, 7, 70, &creds,
			    NULL) == EACCES);
			tls_peer_stop(&peer, fd);
			close(dir2);
		}
		(void)controller;
		/* Named retirement of a live source lifetime: the witness query
		 * fails, fails without errno, the destroy fails (with and
		 * without errno), and succeeds. */
		{
			int ro_dir = private_dir("restart2", 0700);
			struct migration_recovery_record live = intent_record(MIGRATION_REC_SOURCE_INTENT, 7, 70);
			pins(live.source_certificate_sha256, live.destination_certificate_sha256);
			CHECK(migration_source_owner_at(ro_dir, &live, true) == 0);
			CHECK(migration_recovery_store_at(ro_dir, &live) == 0);
			/* flock order on this path: owner_load_at, controller_lock_at,
			 * then finish_intent's owner_at and load_at (3, 4), then the
			 * re-read of the journal after EBUSY (5).  `retired` is how
			 * many witness queries the call makes before failing. */
			static const struct { const char *name; int extra, fault, error, retired; } rows[] = {
				{ "flock", 3, EIO, EIO, 0 },
				{ "flock", 4, EIO, EIO, 0 },
				{ "flock", 5, EIO, EIO, 1 },
				{ "hypertrace_session_retired", 2, EIO, EIO, 2 },
				{ "hypertrace_session_retired", 2, FAULT_NOERRNO, EIO, 2 },
				{ "vm_destroy_name_identity_checked", 1, EIO, EIO, 2 },
				{ "vm_destroy_name_identity_checked", 1, FAULT_NOERRNO, EIO, 2 },
			};
			for (size_t i = 0; i < nitems(rows); i++) {
				uint16_t phase = 0;
				int retired_before = *boundary_count("hypertrace_session_retired");
				nfaults = 1;
				faults[0] = (typeof(faults[0])){ 'S', "", *boundary_count(rows[i].name) +
				    rows[i].extra, rows[i].fault };
				strlcpy(faults[0].name, rows[i].name, sizeof(faults[0].name));
				fd = tls_peer_start(&peer, false);
				CHECK(migration_prod_source_recover_restart_named(fd, ro_dir, 7, 70, &creds,
				    "migrating-vm") == rows[i].error);
				tls_peer_stop(&peer, fd);
				nfaults = 0;
				CHECK(*boundary_count("hypertrace_session_retired") - retired_before ==
				    rows[i].retired);
				CHECK(!kernel_has("destroyed", 7, 70));
				CHECK(migration_recovery_load_at(ro_dir, &live, &phase) == 0 &&
				    phase == MIGRATION_REC_SOURCE_INTENT);
			}
			/* Success: the lifetime is destroyed by name and INTENT becomes
			 * RETIRED; the peer closed, so the recovery exchange fails. */
			fd = tls_peer_start(&peer, false);
			{
				uint16_t phase = 0;
				int e = migration_prod_source_recover_restart_named(fd, ro_dir, 7, 70,
				    &creds, "migrating-vm");
				tls_peer_stop(&peer, fd);
				CHECK(e != 0 && kernel_has("destroyed", 7, 70));
				CHECK(migration_recovery_load_at(ro_dir, &live, &phase) == 0 &&
				    phase >= MIGRATION_REC_SOURCE_RETIRED);
			}
			close(ro_dir);
		}
		close(creds.certificate_fd);
		close(creds.private_key_fd);
		close(creds.trust_fd);
		close(dirfd);
		checks += 9;
	}
	printf("adapter edges: %d checks\n", checks);
}

/* ------------------------------------------------------ migrate_resolve */
/*
 * Operator resolution of a retained ordinary destination (item 4).  Runs in
 * the destination process after migration_prod_dest_serve() returned with a
 * retained owner.  Oracles: every refusal leaves the owner retained and the
 * waiting main thread blocked; resume runs the guest exactly once and
 * releases the main thread with 0; discard releases it with ECANCELED and
 * never runs the guest; the owner's recovery-directory duplicate is closed
 * either way; nothing remains to resolve afterwards.  A resume that was
 * already attempted is retried only when the kernel run witness shows no
 * guest entry and no running vCPU for this incarnation.
 */
static void *
resolution_waiter(void *arg)
{
	int *result = arg;
	*result = migration_prod_dest_wait_resolution();
	return (NULL);
}

static nvlist_t *
resolve_call(const char *action, const char *flag)
{
	nvlist_t *request = nvlist_create(0);
	nvlist_t *reply;
	if (action != NULL)
		nvlist_add_string(request, "action", action);
	if (flag != NULL)
		nvlist_add_bool(request, flag, true);
	reply = ipc_call("migrate_resolve", request);
	nvlist_destroy(request);
	return (reply);
}

static int
resolve_expect(const char *action, const char *flag, int error)
{
	nvlist_t *reply = resolve_call(action, flag);
	int got = nvlist_exists_number(reply, "error_code") ?
	    (int)nvlist_get_number(reply, "error_code") : 0;
	bool resolved = nvlist_get_bool(reply, "resolved");
	bool retained = nvlist_get_bool(reply, "retained");
	nvlist_destroy(reply);
	if (got != error)
		fprintf(stderr, "migrate_resolve %s/%s: %d, expected %d\n",
		    action ? action : "-", flag ? flag : "-", got, error);
	CHECK(got == error && resolved == (error == 0));
	CHECK(retained == (error != 0 && error != ENOENT));
	return (1);
}

/* Entries of this attempt's destination handoff journal (128 bytes each). */
static int
handoff_entries(int dirfd, const uint8_t challenge[32], struct migration_handoff_entry *last)
{
	char name[80];
	struct stat st;
	int fd, n;

	migration_handoff_name(MIGRATION_HANDOFF_DEST, challenge, name);
	if (fstatat(dirfd, name, &st, 0) != 0)
		return (0);
	CHECK(st.st_size % MIGRATION_HANDOFF_SIZE == 0);
	n = (int)(st.st_size / MIGRATION_HANDOFF_SIZE);
	if (last != NULL && n > 0) {
		uint8_t wire[MIGRATION_HANDOFF_SIZE];
		fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC);
		CHECK(fd >= 0 && pread(fd, wire, sizeof(wire),
		    (off_t)(n - 1) * MIGRATION_HANDOFF_SIZE) == (ssize_t)sizeof(wire));
		close(fd);
		CHECK(migration_handoff_decode(wire, last) == 0);
	}
	return (n);
}

static int
dest_resolve(const struct scenario *s, const struct migration_dest_result *r, int error)
{
	pthread_t waiter;
	int waited = -1, checks = 0, dirdup;
	bool uncertain;

	CHECK(error != 0 && r->retained && !r->resumed && migration_prod_dest_retained());
	uncertain = migration_dest_retained->run_state.resume_uncertain;
	CHECK(uncertain == (s->resolve_variant == 2));
	/* A request without a body, and confirmations given as false. */
	{
		nvlist_t *reply = vm_do_migrate_resolve(&vm, NULL);
		CHECK(!nvlist_get_bool(reply, "resolved") && nvlist_get_bool(reply, "retained") &&
		    nvlist_get_number(reply, "error_code") == EINVAL);
		nvlist_destroy(reply);
		nvlist_t *req = nvlist_create(0);
		nvlist_add_string(req, "action", "resume");
		nvlist_add_bool(req, "source_retired", false);
		reply = ipc_call("migrate_resolve", req);
		CHECK(nvlist_get_number(reply, "error_code") == EINVAL);
		nvlist_destroy(reply);
		nvlist_destroy(req);
		checks += 2;
	}
	dirdup = migration_dest_retained->recovery_dirfd;
	uint8_t challenge[32];
	int journal_dir = -1, entries = 0;
	struct migration_handoff_entry last;
	memcpy(challenge, migration_dest_retained->recovery.challenge, 32);
	if (s->dest_recovery) {
		CHECK(dirdup >= 0 && fcntl(dirdup, F_GETFD) >= 0);
		journal_dir = dup(dirdup);
		entries = handoff_entries(journal_dir, challenge, NULL);
		CHECK(entries >= 1);	/* STAGED at least: written for ordinary migrations */
	} else
		CHECK(dirdup == -1);
	CHECK(pthread_create(&waiter, NULL, resolution_waiter, &waited) == 0);
	/* Refusals: the owner stays retained and the main thread stays blocked. */
	checks += resolve_expect(NULL, NULL, EINVAL);
	checks += resolve_expect("bogus", "source_retired", EINVAL);
	checks += resolve_expect("resume", NULL, EINVAL);
	checks += resolve_expect("resume", "acknowledge_loss", EINVAL);
	checks += resolve_expect("discard", NULL, EINVAL);
	checks += resolve_expect("discard", "source_retired", EINVAL);
	if (uncertain) {
		/* The first resume may have run the guest: retry only when the
		 * kernel witness proves it did not. */
		vm.guest_entries = 1;
		checks += resolve_expect("resume", "source_retired", EBUSY);
		vm.guest_entries = 0;
		vm.running_vcpus = 1;
		checks += resolve_expect("resume", "source_retired", EBUSY);
		vm.running_vcpus = 0;
		vm.witness_identity_delta = 1;
		checks += resolve_expect("resume", "source_retired", ESTALE);
		vm.witness_identity_delta = 0;
		witness_vmid_delta = 1;
		checks += resolve_expect("resume", "source_retired", ESTALE);
		witness_vmid_delta = 0;
		/* The identity read after the witness fails, with and without errno. */
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'D', "vm_get_identity",
		    *boundary_count("vm_get_identity") + 1, ENXIO };
		checks += resolve_expect("resume", "source_retired", ENXIO);
		faults[0] = (typeof(faults[0])){ 'D', "vm_get_identity",
		    *boundary_count("vm_get_identity") + 1, FAULT_NOERRNO };
		checks += resolve_expect("resume", "source_retired", EIO);
		nfaults = 0;
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'D', "vm_get_run_witness",
		    *boundary_count("vm_get_run_witness") + 1, ENXIO };
		checks += resolve_expect("resume", "source_retired", ENXIO);
		nfaults = 0;
	}
	usleep(50000);
	CHECK(waited == -1 && vm.resumes == 0 && vm.fenced);
	/* Refusals journal nothing. */
	if (s->dest_recovery)
		CHECK(handoff_entries(journal_dir, challenge, NULL) == entries);
	/* Variant 5: the resume itself fails; the image stays retained and the
	 * next attempt is gated by the run witness (nothing ran). */
	if (s->resolve_variant == 5) {
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'D', "vm_migrate_resume",
		    *boundary_count("vm_migrate_resume") + 1, EIO };
		checks += resolve_expect("resume", "source_retired", EIO);
		nfaults = 0;
		CHECK(migration_dest_retained->run_state.resume_uncertain && vm.resumes == 0);
		/* RESOLVE and a failed OUTCOME were journaled. */
		CHECK(handoff_entries(journal_dir, challenge, &last) >= entries + 2 &&
		    last.kind == MIGRATION_HANDOFF_OUTCOME && last.result == EIO);
		entries = handoff_entries(journal_dir, challenge, NULL);
		checks += 2;
	}
	/* Variant 0 with a journal: the RELEASED record (second durable write
	 * of the attempt) fails after RESOLVE was journaled: refused, retained. */
	if (s->resolve_variant == 0 && s->dest_recovery) {
		nfaults = 1;
		faults[0] = (typeof(faults[0])){ 'D', "fsync", *boundary_count("fsync") + 2, EIO };
		checks += resolve_expect("resume", "source_retired", EIO);
		nfaults = 0;
		CHECK(vm.resumes == 0 && vm.fenced && migration_prod_dest_retained());
		entries = handoff_entries(journal_dir, challenge, NULL);
		checks++;
	}
	/* A journal that cannot take the decision refuses it and acts on
	 * nothing (not checkable as root, which ignores the file mode). */
	if (s->dest_recovery && geteuid() != 0) {
		char name[80];
		migration_handoff_name(MIGRATION_HANDOFF_DEST, challenge, name);
		CHECK(fchmodat(journal_dir, name, 0400, 0) == 0);
		nvlist_t *reply = resolve_call(s->resolve_variant == 1 ? "discard" : "resume",
		    s->resolve_variant == 1 ? "acknowledge_loss" : "source_retired");
		CHECK(!nvlist_get_bool(reply, "resolved") && nvlist_get_bool(reply, "retained") &&
		    nvlist_get_number(reply, "error_code") == EACCES);
		nvlist_destroy(reply);
		CHECK(fchmodat(journal_dir, name, 0600, 0) == 0);
		usleep(20000);
		CHECK(waited == -1 && vm.resumes == 0 && vm.fenced &&
		    handoff_entries(journal_dir, challenge, NULL) == entries);
		checks += 2;
	}
	checks += 2;
	if (s->resolve_variant == 1) {
		checks += resolve_expect("discard", "acknowledge_loss", 0);
		CHECK(pthread_join(waiter, NULL) == 0 && waited == ECANCELED);
		CHECK(vm.resumes == 0 && vm.fenced);
	} else {
		if (s->resolve_variant != 2) {
			/* The source process died before destroying its VM. Its
			 * confirmation is the operator's own act: destroy it. */
			kernel_set("destroyed", 7, 70);
			event("E destroyed vm7 operator");
		}
		if (s->resolve_variant == 3 || s->resolve_variant == 4) {
			/* The RUNNING record (3) or the OUTCOME entry (4) fails
			 * after the guest resumed: resolved, with journal_error. */
			nvlist_t *reply;
			nfaults = 1;
			faults[0] = (typeof(faults[0])){ 'D', "fsync",
			    *boundary_count("fsync") + (s->resolve_variant == 3 ? 3 : 4), EIO };
			reply = resolve_call("resume", "source_retired");
			nfaults = 0;
			CHECK(nvlist_get_bool(reply, "resolved") && !nvlist_get_bool(reply, "retained") &&
			    nvlist_exists_number(reply, "journal_error") &&
			    nvlist_get_number(reply, "journal_error") == EIO);
			nvlist_destroy(reply);
			checks++;
		} else
			checks += resolve_expect("resume", "source_retired", 0);
		CHECK(pthread_join(waiter, NULL) == 0 && waited == 0);
		CHECK(vm.resumes == 1 && !vm.fenced && vm.guest_entries == 1);
	}
	/* The decision and its outcome were journaled, in that order (unless
	 * the journal failed after the decision: variants 3 and 4). */
	if (s->dest_recovery && s->resolve_variant != 3 && s->resolve_variant != 4) {
		int after = handoff_entries(journal_dir, challenge, &last);
		uint8_t action = s->resolve_variant == 1 ? MIGRATION_HANDOFF_DISCARD :
		    MIGRATION_HANDOFF_RESUME;
		CHECK(after >= entries + 2 && last.kind == MIGRATION_HANDOFF_OUTCOME &&
		    last.action == action && last.result == 0);
		checks++;
	}
	if (journal_dir >= 0)
		close(journal_dir);
	/* The retained owner's recovery-directory duplicate is closed. */
	if (s->dest_recovery)
		CHECK(fcntl(dirdup, F_GETFD) == -1 && errno == EBADF);
	CHECK(!migration_prod_dest_retained());
	checks += resolve_expect("resume", "source_retired", ENOENT);
	checks += 3;
	return (checks);
}

static void
test_migrate_resolve(void)
{
	static const struct {
		const char *name, *fault;
		int variant;
	} cases[] = {
		/* The source dies after accepting COMMIT, before RELEASE. */
		{ "resolve-resume", "S:vm_destroy_request_checked:1:999", 0 },
		{ "resolve-discard", "S:vm_destroy_request_checked:1:999", 1 },
		/* RELEASE arrived but the destination's resume failed. */
		{ "resolve-uncertain", "D:vm_migrate_resume:1:5", 2 },
		/* The journal fails after the resume (RUNNING, then OUTCOME). */
		{ "resolve-journal-running", "S:vm_destroy_request_checked:1:999", 3 },
		{ "resolve-journal-outcome", "S:vm_destroy_request_checked:1:999", 4 },
		/* The operator's resume fails, then succeeds under the witness. */
		{ "resolve-resume-fails", "S:vm_destroy_request_checked:1:999", 5 },
		/* No recovery directory: nothing is journaled. */
		{ "resolve-nojournal", "S:vm_destroy_request_checked:1:999", 6 },
	};
	struct outcome o;
	int total = 0;

	/* Nothing retained in this process: ENOENT, and missing arguments. */
	CHECK(!migration_prod_dest_retained());
	total += resolve_expect("resume", "source_retired", ENOENT);
	total += resolve_expect(NULL, NULL, ENOENT);
	for (size_t i = 0; i < nitems(cases); i++) {
		struct scenario sc = { .name = cases[i].name, .dest_resolve = dest_resolve,
		    .resolve_variant = cases[i].variant,
		    .dest_recovery = cases[i].variant != 6 };
		run_scenario(&sc, cases[i].fault, &o);
		CHECK(o.fault_fired);
		int n = kv_int("destination-result", "resolve");
		if (n <= 0)
			fprintf(stderr, "%s: destination resolution checks %d\n", cases[i].name, n);
		CHECK(n > 0);
		total += n;
	}
	printf("migrate_resolve: refusals, witness-gated resume, resume, discard: %d checks\n",
	    total);
}


/* ---------------------------------------------------- active vsock */
/*
 * Merged active-vsock adapter: capture into a bundle at the source, staging,
 * matching and restoring at the destination, and the relay socket pairs.
 * Oracles: the documented refusal of each malformed input, the decoded
 * bundle naming exactly the captured devices and endpoints, and no endpoint
 * left recorded after a failure.
 */
static void
test_vsock_adapter(void)
{
	struct migration_prod_source *src;
	struct migration_prod_dest *dst;
	struct migration_vsock_bundle_item items[MIGRATION_VSOCK_BUNDLE_MAX_DEVICES];
	uint8_t *wire = NULL, *saved;
	size_t len = 0, saved_len;
	uint32_t count, endpoints;
	int pair[2], checks = 0;

	role = 'S';
	fresh_workdir();
	vm_model_init(7, 70, 0x11);
	devices_init();
	vsock_present = true;
	src = calloc(1, sizeof(*src));
	src->ctx = &vm;
	src->stream_fd = -1;
	/* Guards: outputs, quiesce, a capture already taken. */
	CHECK(prod_vsock_state(src, NULL, &len) == EINVAL);
	CHECK(prod_vsock_state(src, &wire, NULL) == EINVAL);
	CHECK(prod_vsock_state(src, &wire, &len) == EINVAL);	/* not quiesced */
	src->quiesced = true;
	vm.cpus_paused = vm.devices_paused = true;
	src->vsock_endpoint_count = 1;
	CHECK(prod_vsock_state(src, &wire, &len) == EINVAL);
	src->vsock_endpoint_count = 0;
	checks += 4;
	/* A capture: one device, VSOCK_CONNS endpoints of alternating type. */
	CHECK(prod_vsock_state(src, &wire, &len) == 0 && wire != NULL);
	CHECK(src->vsock_endpoint_count == VSOCK_CONNS);
	CHECK(migration_vsock_bundle_decode(wire, len, items, nitems(items), &count,
	    &endpoints) == 0 && count == 1 && endpoints == VSOCK_CONNS &&
	    strcmp(items[0].name, "vsock0") == 0);
	for (int i = 0; i < VSOCK_CONNS; i++)
		CHECK(fcntl(src->vsock_endpoints[i].fd, F_GETFD) >= 0 &&
		    src->vsock_endpoints[i].type == ((i & 1) ? VSOCK_MIGRATION_TYPE_SEQPACKET :
		    VSOCK_MIGRATION_TYPE_STREAM));
	saved = malloc(len);
	memcpy(saved, wire, len);
	saved_len = len;
	free(wire);
	wire = NULL;
	checks += 4;
	/* Device capture failure, and a table that names another count. */
	src->vsock_endpoint_count = 0;
	inject("pci_vtvsock_migration_capture", 1, EIO);
	CHECK(prod_vsock_state(src, &wire, &len) == EIO && wire == NULL &&
	    src->vsock_endpoint_count == 0);
	nfaults = 0;
	vsock_count_skew = 1;
	CHECK(prod_vsock_state(src, &wire, &len) == EPROTO && src->vsock_endpoint_count == 0);
	vsock_count_skew = 0;
	checks += 2;
	/* The wire allocation fails (a table large enough to be "large"). */
	vsock_conns = 64;
	fail_next_large_allocation(2);	/* the device table, then the wire */
	CHECK(prod_vsock_state(src, &wire, &len) == ENOMEM && src->vsock_endpoint_count == 0);
	vsock_conns = VSOCK_CONNS;
	checks++;
	/* Too many devices, too many endpoints, duplicate device names. */
	many_vsock = true;
	vsock_conns = 0;
	many_devices_init(MIGRATION_VSOCK_BUNDLE_MAX_DEVICES);	/* + vsock0 */
	CHECK(prod_vsock_state(src, &wire, &len) == E2BIG && src->vsock_endpoint_count == 0);
	vsock_conns = 200;
	many_devices_init(1);	/* vsock0 then many-0: 400 > 256 endpoints */
	CHECK(prod_vsock_state(src, &wire, &len) == E2BIG && src->vsock_endpoint_count == 0);
	vsock_conns = 1;
	many_same_name = true;
	many_devices_init(2);	/* many-0 twice */
	CHECK(prod_vsock_state(src, &wire, &len) == EINVAL && src->vsock_endpoint_count == 0);
	many_same_name = false;
	vsock_conns = VSOCK_CONNS;
	checks += 3;
	/* Two devices: the destination matches each by name. */
	many_devices_init(1);
	CHECK(prod_vsock_state(src, &wire, &len) == 0 && src->vsock_endpoint_count ==
	    2 * VSOCK_CONNS);
	checks++;

	/* Destination. */
	role = 'D';
	vm_model_init(9, 90, 0x99);
	devices_init();
	vm.fenced = true;
	vsock_present = true;
	many_devices_init(0);	/* only vsock0 here */
	dst = calloc(1, sizeof(*dst));
	dst->ctx = &vm;
	dst->controller_fd = -1;
	dst->recovery_dirfd = -1;
	CHECK(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
	dst->stream_fd = pair[0];
	CHECK(prod_dest_stage_vsock(dst, NULL, 1) == EINVAL);
	CHECK(prod_dest_stage_vsock(dst, wire, 0) == EINVAL);
	/* The local device set must equal the bundle's: two named devices. */
	CHECK(prod_dest_stage_vsock(dst, wire, len) == EINVAL && dst->vsock_blob == NULL);
	CHECK(prod_dest_stage_vsock(dst, saved, saved_len - 1) == EINVAL);	/* undecodable */
	many_devices_init(1);
	CHECK(prod_dest_stage_vsock(dst, saved, saved_len) == EINVAL);	/* count differs */
	fail_next_large_allocation(1);
	{
		/* Too large a bundle copy to allocate (the bundle is padded). */
		uint8_t *big = __real_calloc(1, 8192);
		CHECK(prod_dest_stage_vsock(dst, big, 8192) == ENOMEM);
		free(big);
	}
	arm_large_allocation(0);
	CHECK(prod_dest_stage_vsock(dst, wire, len) == 0 && dst->vsock_blob != NULL);
	CHECK(prod_dest_stage_vsock(dst, wire, len) == EINVAL);	/* already staged */
	checks += 8;
	/* Restore: both devices, then the relay owner is prepared. */
	CHECK(prod_dest_restore_vsock(dst) == 0);
	CHECK(dst->vsock_endpoint_count == 2 * VSOCK_CONNS && dst->vsock_relay_prepared);
	prod_dest_discard(dst);
	CHECK(dst->vsock_blob == NULL && dst->vsock_endpoint_count == 0);
	CHECK(prod_dest_restore_vsock(dst) == EINVAL);	/* nothing staged */
	checks += 4;
	/* A staged bundle no longer matching the devices; a device restore
	 * failure; an owner that refuses the endpoints. */
	CHECK(prod_dest_stage_vsock(dst, wire, len) == 0);
	many_devices_init(0);
	CHECK(prod_dest_restore_vsock(dst) == EINVAL);
	many_devices_init(1);
	inject("pci_vtvsock_migration_restore", 1, EIO);
	CHECK(prod_dest_restore_vsock(dst) == EIO);
	nfaults = 0;
	prod_dest_discard(dst);
	CHECK(prod_dest_stage_vsock(dst, wire, len) == 0);
	inject("migration_vsock_owner_prepare", 1, EPIPE);
	CHECK(prod_dest_restore_vsock(dst) == EPIPE && dst->vsock_relay_prepared);
	nfaults = 0;
	prod_dest_discard(dst);
	checks += 3;
	/* Relay socket pairs: every setup step can fail; the pair is closed. */
	{
		int p[2];
		static const char *const steps[] = { "socketpair", "setsockopt",
		    "getsockopt", "cap_rights_limit", "cap_xfer_limit",
		    "cap_cloexec_limit", "cap_clofork_limit" };
		CHECK(prod_dest_vsock_pair(0, p) == EINVAL);
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_SEQPACKET + 1, p) == EINVAL);
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_SEQPACKET, p) == 0);
		close(p[0]);
		close(p[1]);
		for (size_t i = 0; i < nitems(steps); i++) {
			arm_socket(steps[i], 1, ENOBUFS);
			CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_SEQPACKET, p) == ENOBUFS);
			CHECK(i == 0 || (p[0] == -1 && p[1] == -1));
		}
		/* The second SO_RCVBUF and an errno-less failure. */
		arm_socket("setsockopt", 2, ENOMEM);
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_STREAM, p) == ENOMEM);
		arm_socket("setsockopt", 1, 0);
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_STREAM, p) == EIO);
		/* A sequential-packet buffer smaller than required, or a short reply. */
		gso_got = 1;
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_SEQPACKET, p) == ENOBUFS);
		gso_got = -2;
		CHECK(prod_dest_vsock_pair(VSOCK_MIGRATION_TYPE_SEQPACKET, p) == ENOBUFS);
		checks += 13;
	}
	/* A pair failure in the middle of a device's endpoints closes the
	 * device ends already created. */
	CHECK(prod_dest_stage_vsock(dst, wire, len) == 0);
	arm_socket("socketpair", 2, EMFILE);
	CHECK(prod_dest_restore_vsock(dst) == EMFILE);
	prod_dest_discard(dst);
	checks++;
	/* Relay cancel without a prepared owner, and a failed cancel. */
	{
		struct migration_prod_source r = { .vsock_relay_prepared = true };
		inject("migration_vsock_owner_cancel", 1, EBUSY);
		CHECK(prod_cancel_vsock_relay(&r) == EBUSY && r.vsock_relay_prepared);
		nfaults = 0;
		checks++;
	}
	/* A first endpoint whose pair cannot be created leaves nothing to close. */
	CHECK(prod_dest_stage_vsock(dst, wire, len) == 0);
	arm_socket("socketpair", 1, EMFILE);
	CHECK(prod_dest_restore_vsock(dst) == EMFILE);
	prod_dest_discard(dst);
	/* Cancelling an unprepared relay is a no-op. */
	{
		struct migration_prod_source r = { .vsock_relay_prepared = false };
		CHECK(prod_cancel_vsock_relay(&r) == 0);
	}
	/* A rollback whose deferred-event merge fails resumes nothing. */
	{
		struct migration_prod_source r = { .ctx = &vm, .quiesced = true };
		r.capture.active = true;
		vm.cpus_paused = vm.devices_paused = true;
		inject("vm_snapshot_dev_state_finish", 1, EIO);
		CHECK(prod_resume(&r) == EIO && r.quiesced && vm.devices_paused);
		nfaults = 0;
		checks += 2;
	}
	/* The destination HELLO advertises V2_RESTORE only on opt-in. */
	{
		struct migration_hello h;
		struct migration_prod_dest d = { .ctx = &vm, .recovery_dirfd = -1 };
		tracing_mode = false;
		config_restore_abi_v2 = true;
		CHECK(prod_dest_local_hello(&d, &h) == 0 &&
		    (h.capability_flags & MIGRATION_CAP_V2_RESTORE) != 0);
		config_restore_abi_v2 = false;
		CHECK(prod_dest_local_hello(&d, &h) == 0 &&
		    (h.capability_flags & MIGRATION_CAP_V2_RESTORE) == 0);
		checks += 2;
	}
	/* Serving refuses missing arguments before any allocation. */
	{
		struct migration_session_config c = {0};
		struct migration_dest_result res;
		struct migration_prod_dest *owner = NULL;
		CHECK(migration_prod_dest_serve_prepared(NULL, -1, &c, &res, &owner) == EINVAL);
		CHECK(migration_prod_dest_serve_prepared(&vm, -1, &c, NULL, &owner) == EINVAL);
		CHECK(migration_prod_dest_serve_prepared(&vm, -1, NULL, &res, &owner) == EINVAL);
		CHECK(migration_prod_dest_serve_prepared(&vm, -1, &c, &res, NULL) == EINVAL);
		checks += 4;
	}
	/* Topology: no vCPU, memory sizes that overflow, a PCI option ROM
	 * whose identity cannot be read. */
	{
		struct migration_topology *t = __real_calloc(1, sizeof(*t));
		guest_ncpus = 0;
		CHECK(migration_prod_fill_topology(&vm, t) == EINVAL);
		guest_ncpus = 2;
		fake_lowmem = UINT64_MAX - PAGE;
		CHECK(migration_prod_fill_topology(&vm, t) == EINVAL);
		fake_lowmem = LOWMEM;
		bootrom_absent = true;
		devmem_error = EIO;
		devmem_error_seg = VM_PCIROM;
		CHECK(migration_prod_fill_topology(&vm, t) == EIO);
		devmem_error = 0;
		devmem_error_seg = -1;
		bootrom_absent = false;
		free(t);
		checks += 3;
	}
	/* prod_is_vsock: an unconfigured slot is not a vsock device. */
	{
		struct pci_devinst bare = {0};
		CHECK(!prod_is_vsock(NULL) && !prod_is_vsock(&bare));
		checks++;
	}
	free(wire);
	free(saved);
	close(pair[0]);
	close(pair[1]);
	many_vsock = false;
	many_devices_init(0);
	printf("ops vsock adapter: %d checks\n", checks);
}

int
main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	signal(SIGPIPE, SIG_IGN);
	test_fd_transport();
	test_session_helpers();
	in_child("ops source guards", test_source_guards);
	{
		pid_t child;
		int status;
		fflush(stdout);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			fresh_workdir();
			vm_model_init(7, 70, 0x11);
			test_defunct_guard();
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 1);
		printf("ops defunct guard: unretired source refused\n");
	}
	in_child("ops destination guards", test_dest_guards);
	in_child("ops owner validation", test_owner_validation);
	in_child("ops adapter edges", test_adapter_edges);
	in_child("ops vsock adapter", test_vsock_adapter);
	test_migrate_resolve();
	{
		extern void protocol_allocation_faults(void (*)(int), int (*)(void));
		protocol_allocation_faults(arm_large_allocation, large_allocation_count);
	}
	printf("PASS: migration adapter internals\n");
	return (0);
}
