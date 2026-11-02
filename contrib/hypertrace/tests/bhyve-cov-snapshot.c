/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Production-configuration tests of usr.sbin/bhyve/snapshot.c with the
 * original checkpoint_*.c, snapshot_devmem.c and checkpoint_compat.c, real
 * libucl/libxo, real checkpoint generation files and manifests.
 *
 * The original snapshot.c is included in this translation unit (its static
 * coordinators are called directly); coverage-bhyve.py credits it only
 * through mappings identical to the production object.  A fake VM supplies
 * guest RAM (low and high memory in one reserved mapping, like vmmapi), a
 * kernel-record ABI (vm_snapshot_req), the descriptor-owned snapshot session
 * ABI and CPUID.  Devices are two PCI models (one with a compatibility
 * envelope), the amd64 keyboard controller record and the fw_cfg record.
 *
 * Oracles: after save/restore the destination's RAM, every kernel record and
 * every device state equal the source exactly; a failed checkpoint never
 * publishes a manifest and removes its generation members, keeps the previous
 * checkpoint restorable, and restarts the source only when no kernel session
 * or device ownership is unresolved; a failed restore never releases the
 * startup fence; malformed generations are refused before any state changes.
 */
#include "snapshot.c"

#include <sys/mman.h>
#include <dirent.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <sys/ioctl.h>
#include <ctype.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: CHECK(%s) failed (errno %d)\n", \
	__FILE__, __LINE__, #x, errno); abort(); } } while (0)

int guest_ncpus = 2;
uint16_t cpu_cores = 2, cpu_sockets = 1, cpu_threads = 1;
int raw_stdio = 0;

/* ------------------------------------------------------------- faults */
#define MAX_POINTS 128
static struct { const char *name; int count; } points[MAX_POINTS];
static char fault_name[64], fault2_name[64];
static int fault_occurrence, fault_error, fault2_occurrence, fault2_error;
static bool recording;
static struct { char name[64]; int last; } seen[MAX_POINTS];
static int nseen;

static bool armed;
/* The production-config probe stubs answer the USDT is-enabled test
 * alternately; a fault child seeds the parity from its occurrence so each
 * trace site sees both answers across the enumeration. */
extern unsigned long ht_probe_queries;
#define BOTH_PARITIES(stmt) do { stmt; ht_probe_queries++; raw_stdio ^= 1; stmt; \
	raw_stdio ^= 1; } while (0)

static int
boundary(const char *name)
{
	int i, n;

	if (!armed)
		return (0);
	for (i = 0; i < MAX_POINTS && points[i].name != NULL; i++)
		if (strcmp(points[i].name, name) == 0)
			break;
	CHECK(i < MAX_POINTS);
	points[i].name = name;
	n = ++points[i].count;
	if (recording) {
		int j;
		for (j = 0; j < nseen; j++)
			if (strcmp(seen[j].name, name) == 0)
				break;
		if (j == nseen) {
			CHECK(nseen < MAX_POINTS);
			strlcpy(seen[nseen++].name, name, sizeof(seen[0].name));
		}
		seen[j].last = n;
	}
	if (n == fault_occurrence && strcmp(name, fault_name) == 0)
		return (fault_error);
	if (fault2_name[0] != '\0' && (fault2_occurrence == 0 || n == fault2_occurrence) &&
	    strcmp(name, fault2_name) == 0)
		return (fault2_error);
	return (0);
}

static void
reset_points(void)
{
	memset(points, 0, sizeof(points));
}

/* ------------------------------------------------- libc boundaries */
#include <stdarg.h>
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
char *__real_strdup(const char *);
int __real_open(const char *, int, ...);
int __real_openat(int, const char *, int, ...);
int __real_fstat(int, struct stat *);
int __real_fsync(int);
int __real_unlinkat(int, const char *, int);
int __real_linkat(int, const char *, int, const char *, int);
int __real_renameat(int, const char *, int, const char *);
ssize_t __real_write(int, const void *, size_t);
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __real_read(int, void *, size_t);
off_t __real_lseek(int, off_t, int);
int __real_flock(int, int);
void *__real_mmap(void *, size_t, int, int, int, off_t);
int __real_memfd_create(const char *, unsigned int);
FILE *__real_fdopen(int, const char *);
size_t __real_fwrite(const void *, size_t, size_t, FILE *);
size_t __real_fread(void *, size_t, size_t, FILE *);
int __real_fseek(FILE *, long, int);
long __real_ftell(FILE *);
struct ucl_parser *__real_ucl_parser_new(int);
bool __real_ucl_parser_add_fd(struct ucl_parser *, int);
xo_handle_t *__real_xo_create_to_file(FILE *, xo_style_t, xo_xof_flags_t);
int __real_close(int);
int __real_fclose(FILE *);
int __real_fflush(FILE *);
xo_ssize_t __real_xo_finish_h(xo_handle_t *);
int __real_clock_gettime(clockid_t, struct timespec *);
int __real_nanosleep(const struct timespec *, struct timespec *);
void __real_exit(int) __attribute__((noreturn));

/* FAULT_NOERRNO: fail the call without setting errno (libc boundaries).
 * FAULT_ZERO: a transfer call returns 0 (no progress) instead of failing. */
#define FAULT_NOERRNO 998
#define FAULT_ZERO 997
#define LIBC_FAULT(name, failure) do {				\
	int e_ = boundary(name);					\
	if (e_ != 0) {							\
		errno = e_ == FAULT_NOERRNO ? 0 : e_;			\
		return (failure);					\
	}								\
} while (0)

void *__wrap_malloc(size_t n) { LIBC_FAULT("malloc", NULL); return (__real_malloc(n)); }
/* A failed close still releases the descriptor; a failed fclose still
 * releases the stream (FreeBSD semantics). */
/* The descriptor holding the checkpoint's exclusive lock: a stop_vm
 * checkpoint caught at its exit never closes it (see checkpoint_stop_vm). */
static int held_exclusive_fd = -1;
int __wrap_close(int fd)
{
	int e_ = boundary("close");
	if (fd == held_exclusive_fd)
		held_exclusive_fd = -1;
	if (e_ != 0) {
		__real_close(fd);
		errno = e_ == FAULT_NOERRNO ? 0 : e_;
		return (-1);
	}
	return (__real_close(fd));
}
int __wrap_fclose(FILE *f)
{
	int e_ = boundary("fclose");
	if (e_ != 0) {
		__real_fclose(f);
		errno = e_ == FAULT_NOERRNO ? 0 : e_;
		return (EOF);
	}
	return (__real_fclose(f));
}
int __wrap_fflush(FILE *f) { LIBC_FAULT("fflush", EOF); return (__real_fflush(f)); }
xo_ssize_t __wrap_xo_finish_h(xo_handle_t *h) { LIBC_FAULT("xo_finish_h", -1); return (__real_xo_finish_h(h)); }
int __wrap_asprintf(char **ret, const char *fmt, ...)
{
	va_list ap;
	int n;

	LIBC_FAULT("asprintf", -1);
	va_start(ap, fmt);
	n = vasprintf(ret, fmt, ap);
	va_end(ap);
	return (n);
}
/* clock_gettime: faultable, and after pci_vtdtr_session_checkpoint_begin()
 * the Nth reading can fail or be moved to or past the stop deadline. */
static int clock_calls, clock_calls_after_begin = -1, clock_fail_call, clock_fail_error;
static int clock_fail_after_begin, clock_jump_after_begin, clock_jump_mode;
static bool clock_track;
static struct timespec clock_last, clock_deadline_base;
int __wrap_clock_gettime(clockid_t id, struct timespec *ts)
{
	int r;

	LIBC_FAULT("clock_gettime", -1);
	clock_calls++;
	if (clock_calls == clock_fail_call) {
		errno = clock_fail_error == FAULT_NOERRNO ? 0 : clock_fail_error;
		return (-1);
	}
	r = __real_clock_gettime(id, ts);
	if (r != 0)
		return (r);
	clock_last = *ts;
	if (clock_calls_after_begin >= 0) {
		clock_calls_after_begin++;
		if (clock_calls_after_begin == clock_fail_after_begin) {
			errno = clock_fail_error == FAULT_NOERRNO ? 0 : clock_fail_error;
			return (-1);
		}
		if (clock_calls_after_begin == clock_jump_after_begin) {
			switch (clock_jump_mode) {
			case 1:	/* past the deadline */
				ts->tv_sec += 601;
				break;
			case 2:	/* exactly the deadline */
				*ts = clock_deadline_base;
				ts->tv_sec += 600;
				break;
			case 3:	/* the deadline's second, a nanosecond early */
				*ts = clock_deadline_base;
				ts->tv_sec += 600;
				if (ts->tv_nsec > 0)
					ts->tv_nsec--;
				else
					ts->tv_sec--;
				break;
			}
		}
	}
	return (r);
}
int __wrap_nanosleep(const struct timespec *rq, struct timespec *rm) { LIBC_FAULT("nanosleep", -1); return (__real_nanosleep(rq, rm)); }
/* A stop_vm checkpoint exits the process on success; catch that exit so a
 * fresh stopped checkpoint can run in-process (fault enumeration). */
static jmp_buf suspend_jmp;
static volatile bool suspend_catch;
void __wrap_exit(int status) __attribute__((noreturn));
/* A stop_vm checkpoint that published but could not stop the source exits
 * with BHYVE_EXIT_ERROR (cbm-v2h); the harness reports it as this value. */
#define CHECKPOINT_EXITED_ERROR 1000
/* ipc.c is not linked: model the IPC acknowledgement.  A suspend that exits
 * BHYVE_EXIT_SUSPEND must have acknowledged bhyvectl first (it used to exit
 * with the request unanswered); a failed stop must not claim success. */
static int ipc_success_replies;
void
ipc_reply_success_before_exit(void)
{
	ipc_success_replies++;
}
void
__wrap_exit(int status)
{
	if (status == BHYVE_EXIT_SUSPEND && ipc_success_replies != 1)
		abort();
	if (status == BHYVE_EXIT_ERROR && ipc_success_replies != 0)
		abort();
	ipc_success_replies = 0;
	if (suspend_catch && (status == BHYVE_EXIT_SUSPEND || status == BHYVE_EXIT_ERROR)) {
		suspend_catch = false;
		longjmp(suspend_jmp, status == BHYVE_EXIT_SUSPEND ? 1 : 2);
	}
	__real_exit(status);
}
void *__wrap_calloc(size_t n, size_t m) { LIBC_FAULT("calloc", NULL); return (__real_calloc(n, m)); }
char *__wrap_strdup(const char *x) { LIBC_FAULT("strdup", NULL); return (__real_strdup(x)); }
int
__wrap_open(const char *path, int flags, ...)
{
	va_list ap;
	int mode;

	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	LIBC_FAULT("open", -1);
	return (__real_open(path, flags, mode));
}
int
__wrap_openat(int fd, const char *path, int flags, ...)
{
	va_list ap;
	int mode;

	va_start(ap, flags);
	mode = (flags & O_CREAT) != 0 ? va_arg(ap, int) : 0;
	va_end(ap);
	LIBC_FAULT("openat", -1);
	return (__real_openat(fd, path, flags, mode));
}
int __wrap_fstat(int fd, struct stat *st) { LIBC_FAULT("fstat", -1); return (__real_fstat(fd, st)); }
int __wrap_fsync(int fd) { LIBC_FAULT("fsync", -1); return (__real_fsync(fd)); }
int __wrap_unlinkat(int fd, const char *p, int f) { LIBC_FAULT("unlinkat", -1); return (__real_unlinkat(fd, p, f)); }
int __wrap_linkat(int a, const char *b, int c, const char *d, int e) { LIBC_FAULT("linkat", -1); return (__real_linkat(a, b, c, d, e)); }
int __wrap_renameat(int a, const char *b, int c, const char *d) { LIBC_FAULT("renameat", -1); return (__real_renameat(a, b, c, d)); }
#define XFER_FAULT(name) do {					\
	int e_ = boundary(name);					\
	if (e_ == FAULT_ZERO)						\
		return (0);						\
	if (e_ != 0) {							\
		errno = e_ == FAULT_NOERRNO ? 0 : e_;			\
		return (-1);						\
	}								\
} while (0)
ssize_t __wrap_write(int fd, const void *b, size_t n) { XFER_FAULT("write"); return (__real_write(fd, b, n)); }
ssize_t __wrap_pwrite(int fd, const void *b, size_t n, off_t o) { XFER_FAULT("pwrite"); return (__real_pwrite(fd, b, n, o)); }
ssize_t __wrap_pread(int fd, void *b, size_t n, off_t o) { XFER_FAULT("pread"); return (__real_pread(fd, b, n, o)); }
/* A terminal on stdout: progress output during memory transfer. */
int __real_isatty(int);
int __real_ioctl(int, unsigned long, ...);
static bool fake_tty;
static unsigned short fake_cols = 80;
int __wrap_isatty(int fd) { return (fd == STDOUT_FILENO && fake_tty ? 1 : __real_isatty(fd)); }
int
__wrap_ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	void *arg;

	va_start(ap, req);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (fd == STDOUT_FILENO && req == TIOCGWINSZ && fake_tty) {
		struct winsize *w = arg;
		memset(w, 0, sizeof(*w));
		w->ws_col = fake_cols;
		w->ws_row = 24;
		return (0);
	}
	return (__real_ioctl(fd, req, arg));
}
ssize_t __wrap_read(int fd, void *b, size_t n) { LIBC_FAULT("read", -1); return (__real_read(fd, b, n)); }
/* One-shot size overrides: the next SEEK_END / ftell reports this size. */
static off_t lseek_end_override = -1;
static long ftell_override = -1;
off_t __wrap_lseek(int fd, off_t o, int w)
{
	LIBC_FAULT("lseek", -1);
	if (w == SEEK_END && lseek_end_override >= 0) {
		off_t v = lseek_end_override;
		lseek_end_override = -1;
		return (v);
	}
	return (__real_lseek(fd, o, w));
}
int __wrap_flock(int fd, int op)
{
	int r;

	LIBC_FAULT("flock", -1);
	r = __real_flock(fd, op);
	if (r == 0 && (op & LOCK_EX) != 0)
		held_exclusive_fd = fd;
	return (r);
}
void *__wrap_mmap(void *a, size_t n, int p, int f, int fd, off_t o) { LIBC_FAULT("mmap", MAP_FAILED); return (__real_mmap(a, n, p, f, fd, o)); }
int __wrap_memfd_create(const char *n, unsigned int f) { LIBC_FAULT("memfd_create", -1); return (__real_memfd_create(n, f)); }
FILE *__wrap_fdopen(int fd, const char *m) { LIBC_FAULT("fdopen", NULL); return (__real_fdopen(fd, m)); }
size_t __wrap_fwrite(const void *b, size_t s, size_t n, FILE *f) { LIBC_FAULT("fwrite", 0); return (__real_fwrite(b, s, n, f)); }
size_t __wrap_fread(void *b, size_t s, size_t n, FILE *f) { LIBC_FAULT("fread", 0); return (__real_fread(b, s, n, f)); }
int __wrap_fseek(FILE *f, long o, int w) { LIBC_FAULT("fseek", -1); return (__real_fseek(f, o, w)); }
long __wrap_ftell(FILE *f)
{
	LIBC_FAULT("ftell", -1);
	if (ftell_override >= 0) {
		long v = ftell_override;
		ftell_override = -1;
		return (v);
	}
	return (__real_ftell(f));
}
struct ucl_parser *__wrap_ucl_parser_new(int f) { LIBC_FAULT("ucl_parser_new", NULL); return (__real_ucl_parser_new(f)); }
bool __wrap_ucl_parser_add_fd(struct ucl_parser *p, int fd) { LIBC_FAULT("ucl_parser_add_fd", false); return (__real_ucl_parser_add_fd(p, fd)); }
xo_handle_t *__wrap_xo_create_to_file(FILE *f, xo_style_t s, xo_xof_flags_t x) { LIBC_FAULT("xo_create_to_file", NULL); return (__real_xo_create_to_file(f, s, x)); }

/* ----------------------------------------------------------- VM model */
#define LOWMEM (2UL << 20)
#define HIGHBASE (4UL << 30)
#define HIGHMEM (1UL << 20)

struct vmctx {
	char *base;
	const char *name;
	uint16_t vmid;
	uint64_t epoch;
	bool destroyed, suspended;
	int restore_time_calls;
	uint8_t kern[16][256];		/* last restored kernel record by req */
	size_t kern_len[16];
	uint64_t session_id;
	bool session_active;
	int sessions_committed, sessions_aborted;
};
static struct vmctx src_vm, dst_vm;

static void
vm_init(struct vmctx *vm, const char *name, uint8_t seed)
{
	if (vm->base == NULL) {
		vm->base = mmap(NULL, HIGHBASE + HIGHMEM, PROT_NONE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
		CHECK(vm->base != MAP_FAILED);
		CHECK(mprotect(vm->base, LOWMEM, PROT_READ | PROT_WRITE) == 0);
		CHECK(mprotect(vm->base + HIGHBASE, HIGHMEM, PROT_READ | PROT_WRITE) == 0);
	}
	for (size_t i = 0; i < LOWMEM; i++)
		vm->base[i] = (char)(seed + i * 3 + (i >> 12));
	for (size_t i = 0; i < HIGHMEM; i++)
		vm->base[HIGHBASE + i] = (char)(seed ^ (i * 7));
	vm->name = name;
	vm->vmid = 5;
	vm->epoch = 50;
	vm->destroyed = vm->suspended = false;
	memset(vm->kern, 0, sizeof(vm->kern));
	memset(vm->kern_len, 0, sizeof(vm->kern_len));
	vm->session_active = false;
	vm->restore_time_calls = 0;
	vm->sessions_committed = vm->sessions_aborted = 0;
}

static bool
ram_equal(const struct vmctx *a, const struct vmctx *b)
{
	return (memcmp(a->base, b->base, LOWMEM) == 0 &&
	    memcmp(a->base + HIGHBASE, b->base + HIGHBASE, HIGHMEM) == 0);
}

int
vm_get_guestmem_from_ctx(struct vmctx *ctx, char **base, size_t *low, size_t *high)
{
	int error = boundary("vm_get_guestmem_from_ctx");

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	*base = ctx->base;
	*low = LOWMEM;
	*high = HIGHMEM;
	return (0);
}

uint64_t vm_get_lowmem_size(struct vmctx *ctx) { (void)ctx; return (LOWMEM); }
uint64_t vm_get_highmem_size(struct vmctx *ctx) { (void)ctx; return (HIGHMEM); }
uint64_t vm_get_highmem_base(struct vmctx *ctx) { (void)ctx; return (HIGHBASE); }
int vm_get_memflags(struct vmctx *ctx) { (void)ctx; return (0); }
const char *vm_get_name(struct vmctx *ctx) { return (ctx->name); }

static int identity_error;		/* next identity read fails (errno, or FAULT_NOERRNO) */
static int identity_vmid_delta, identity_epoch_delta;
int
vm_get_identity(struct vmctx *ctx, uint16_t *vmid, uint64_t *epoch)
{
	if (identity_error != 0) {
		errno = identity_error == FAULT_NOERRNO ? 0 : identity_error;
		identity_error = 0;
		return (-1);
	}
	*vmid = ctx->vmid + identity_vmid_delta;
	*epoch = ctx->epoch + identity_epoch_delta;
	return (0);
}

/* Generic device memory: two named segments per VM when enabled. */
static bool devmem_enabled;
static uint8_t devmem_buf[2][2][8192];	/* [vm][segment] */

int
vm_get_devmem_info(struct vmctx *ctx, int segid, void **base, size_t *len,
    char *name, size_t namelen)
{
	int error = boundary("vm_get_devmem_info");
	int vm = ctx == &dst_vm;

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	if (devmem_enabled && (segid == VM_DEVMEM_START || segid == VM_DEVMEM_START + 2)) {
		int seg = segid == VM_DEVMEM_START ? 0 : 1;
		*base = devmem_buf[vm][seg];
		*len = seg == 0 ? 8192 : 4096;
		strlcpy(name, seg == 0 ? "fbuf" : "audio", namelen);
		return (0);
	}
	errno = ENOENT;
	return (-1);
}

static int suspend_error;	/* merged: the suspend ioctl result is checked */
int
vm_suspend_all_cpus(struct vmctx *ctx)
{
	if (suspend_error != 0) {
		errno = suspend_error == FAULT_NOERRNO ? 0 : suspend_error;
		return (-1);
	}
	ctx->suspended = true;
	return (0);
}

int
vm_resume_all_cpus(struct vmctx *ctx)
{
	int error = boundary("vm_resume_all_cpus");

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	CHECK(!ctx->destroyed);
	ctx->suspended = false;
	return (0);
}

int
vm_restore_time(struct vmctx *ctx)
{
	int error = boundary("vm_restore_time");

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	ctx->restore_time_calls++;
	return (0);
}

int
vm_destroy_checked(struct vmctx *ctx)
{
	int error = boundary("vm_destroy_checked");

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	ctx->destroyed = true;
	return (0);
}

/* Kernel records: SAVE emits a request-specific deterministic payload;
 * RESTORE consumes it and keeps a copy for comparison. */
static size_t
kern_length(int req)
{
	return (40 + (size_t)req * 13);
}

static bool kern_restore_short;
int
vm_snapshot_req(struct vmctx *ctx, struct vm_snapshot_meta *meta)
{
	int error = boundary("vm_snapshot_req");
	size_t n = kern_length(meta->dev_req);
	uint8_t *buf = (uint8_t *)meta->buffer.buf;

	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	if (kern_restore_short && meta->op == VM_SNAPSHOT_RESTORE &&
	    meta->buffer.buf_rem > 1) {
		meta->buffer.buf_rem = 1;	/* one byte left unconsumed */
		return (0);
	}
	CHECK(meta->dev_req >= 0 && meta->dev_req < 16);
	if (meta->op == VM_SNAPSHOT_SAVE) {
		CHECK(meta->buffer.buf_rem >= n);
		for (size_t i = 0; i < n; i++)
			buf[i] = (uint8_t)(ctx->epoch + meta->dev_req * 17 + i);
		meta->buffer.buf += n;
		meta->buffer.buf_rem -= n;
		return (0);
	}
	CHECK(meta->op == VM_SNAPSHOT_RESTORE);
	if (meta->buffer.buf_rem < n) {
		errno = EINVAL;
		return (-1);
	}
	memcpy(ctx->kern[meta->dev_req], buf, n);
	ctx->kern_len[meta->dev_req] = n;
	meta->buffer.buf += n;
	meta->buffer.buf_rem -= n;
	return (0);
}

/* Descriptor-owned session ABI. */
static int session_efault;	/* number of EFAULT replies to inject */
static const int *session_script;	/* scripted errno per call (0 = success) */
static int session_script_len, session_ops[8], session_nops;
int
vm_snapshot_session(struct vmctx *ctx, struct vm_snapshot_session *s)
{
	int error = boundary("vm_snapshot_session");

	CHECK(s->version == VM_SNAPSHOT_SESSION_VERSION);
	if (session_script != NULL) {
		/* Scripted replies: record the operation, return the result. */
		CHECK(session_script_len > 0);
		session_ops[session_nops++] = s->op;
		int r = session_script[0];
		session_script++;
		session_script_len--;
		if (r == 0) {
			/* A scripted success still models the session identity. */
			if (s->op == VM_SNAPSHOT_SESSION_BEGIN) {
				ctx->session_active = true;
				s->session_id = ++ctx->session_id;
			} else if (s->op == VM_SNAPSHOT_SESSION_COMMIT ||
			    s->op == VM_SNAPSHOT_SESSION_ABORT)
				ctx->session_active = false;
			return (0);
		}
		errno = r == FAULT_NOERRNO ? 0 : r;
		return (-1);
	}
	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	switch (s->op) {
	case VM_SNAPSHOT_SESSION_BEGIN:
		if (ctx->session_active) {
			errno = EBUSY;
			return (-1);
		}
		ctx->session_active = true;
		s->session_id = ++ctx->session_id;
		break;
	case VM_SNAPSHOT_SESSION_COMMIT:
	case VM_SNAPSHOT_SESSION_ABORT:
		if (!ctx->session_active || s->session_id != ctx->session_id) {
			errno = ESTALE;
			return (-1);
		}
		ctx->session_active = false;
		if (s->op == VM_SNAPSHOT_SESSION_COMMIT)
			ctx->sessions_committed++;
		else
			ctx->sessions_aborted++;
		break;
	case VM_SNAPSHOT_SESSION_ABORT_CURRENT:
		if (!ctx->session_active) {
			errno = ESTALE;
			return (-1);
		}
		ctx->session_active = false;
		ctx->sessions_aborted++;
		break;
	default:
		errno = EINVAL;
		return (-1);
	}
	if (session_efault > 0) {
		session_efault--;
		errno = EFAULT;
		return (-1);
	}
	return (0);
}

/* CPUID model: a small deterministic baseline (mode 0) or a rich
 * enumeration with cache, topology and XSAVE subleaves (mode 1). */
static int cpuid_mode, cpuid_errno, compat_mode;
int
vm_get_cpuid(struct vcpu *vcpu, uint32_t flags, uint32_t *eax, uint32_t *ebx,
    uint32_t *ecx, uint32_t *edx)
{
	uint32_t leaf = *eax;
	int error = boundary("vm_get_cpuid");

	(void)vcpu;
	(void)flags;
	if (error != 0) {
		errno = error == FAULT_NOERRNO ? 0 : error;
		return (-1);
	}
	uint32_t sub = *ecx;
	*ebx = *ecx = *edx = 0;
	if (cpuid_mode == 5) {
		errno = cpuid_errno;
		return (-1);
	}
	if (cpuid_mode == 0) {
		if (leaf == 0)
			*eax = 0x7;
		else if (leaf == 0x80000000U)
			*eax = 0x80000004U;
		else if (leaf == 0x40000000U)
			*eax = 0x40000001U;
		else
			*eax = leaf ^ 0x5a5a;
		if (leaf == 4 || leaf == 0xb)
			*eax &= ~0x1fU, *ebx = 0;
		return (0);
	}
	/* Rich enumeration (mode 1) and its failure variants. */
	if (leaf == 0)
		*eax = cpuid_mode == 4 ? 0x1000 : 0x1f;
	else if (leaf == 0x80000000U)
		*eax = cpuid_mode == 3 ? 0x7fffffffU : 0x8000001dU;
	else if (leaf == 0x40000000U)
		*eax = 0x40000001U;
	else if (leaf == 4 || leaf == 0x8000001dU)
		*eax = (cpuid_mode == 2 || sub < 3) ? 0x01 | (sub << 5) : 0x100;
	else if (leaf == 0xb || leaf == 0x1f)
		*ebx = sub < 2 ? 1 + sub : 0, *eax = sub;
	else if (leaf == 0xd && sub == 0)
		*eax = 0x2e7, *edx = 1;
	else
		*eax = leaf * 3 + sub;
	return (0);
}

int
vm_get_cpu_compat(struct vcpu *vcpu, struct vm_cpu_compat *compat)
{
	(void)vcpu;
	memset(compat, 0, sizeof(*compat));
	compat->version = VM_CPU_COMPAT_VERSION;
	compat->tsc_frequency = 2000000000ULL;
	compat->xcr0_allowed = 3;
	compat->xsave_max_size = 576;
	switch (compat_mode) {
	case 1: compat->version++; break;
	case 2: compat->flags = 0x80000000U; break;
	case 3: compat->x2apic_state = X2APIC_STATE_LAST; break;
	case 4: compat->tsc_frequency = 0; break;
	case 5: errno = 0; return (-1);
	}
	return (boundary("vm_get_cpu_compat") != 0 ? (errno = EIO, -1) : 0);
}

static int fake_vcpu;
struct vcpu *
fbsdrun_vcpu(int vcpuid)
{
	(void)vcpuid;
	return ((struct vcpu *)&fake_vcpu);
}

int
bhyve_numa_checkpoint_export(uint64_t *sizes, size_t capacity, uint16_t *domains,
    size_t ncpus, size_t *count)
{
	int error = boundary("bhyve_numa_checkpoint_export");

	if (error != 0)
		return (error);
	CHECK(capacity >= 1);
	sizes[0] = LOWMEM + HIGHMEM;
	for (size_t i = 0; i < ncpus; i++)
		domains[i] = 0;
	*count = 1;
	return (0);
}

void *
paddr_guest2host(struct vmctx *ctx, uintptr_t gpa, size_t len)
{
	if (gpa < LOWMEM && len <= LOWMEM - gpa)
		return (ctx->base + gpa);
	return (NULL);
}

uintptr_t
paddr_host2guest(struct vmctx *ctx, void *addr)
{
	/* Like vm_rev_map_gpa(): -1 outside guest RAM. */
	uintptr_t off = (uintptr_t)addr - (uintptr_t)ctx->base;

	if ((uintptr_t)addr < (uintptr_t)ctx->base ||
	    (off >= LOWMEM && (off < HIGHBASE || off >= HIGHBASE + HIGHMEM)))
		return ((uintptr_t)-1);
	return (off);
}

/*
 * TPM (merged): a checkpointable device named "tpm".  Its record is 32
 * bytes of per-side state; vm_pause_devices() opens a state read that
 * vm_resume_devices() ends; the migration gate is a separate knob.
 */
static bool tpm_present, tpm_reading_side[2];
static int tpm_migration_error, tpm_begin_error, tpm_end_error, tpm_validate_error;
static int tpm_begins, tpm_ends;
static uint8_t tpm_state[2][32];
static int side;
/* Each side models its own process: the source (0) or a destination (1). */
#define tpm_reading tpm_reading_side[side]
bool tpm_device_present(void) { return (tpm_present); }
int
tpm_device_migration_check(void)
{
	return (tpm_present ? tpm_migration_error : 0);
}
int
tpm_device_state_begin_read(void)
{
	CHECK(tpm_present);
	if (tpm_reading)
		return (EBUSY);	/* one state transaction at a time */
	if (tpm_begin_error != 0)
		return (tpm_begin_error);
	tpm_reading = true;
	tpm_begins++;
	return (0);
}
int
tpm_device_state_end_if_active(void)
{
	if (!tpm_present || !tpm_reading)
		return (0);
	if (tpm_end_error != 0)
		return (tpm_end_error);
	tpm_reading = false;
	tpm_ends++;
	return (0);
}
/* Configuration: the previous-ABI restore opt-in (merged). */
static bool config_restore_abi_v2;
bool
get_config_bool_default(const char *name, bool def)
{
	if (strcmp(name, "checkpoint.restore_abi_v2") == 0)
		return (config_restore_abi_v2);
	return (def);
}

void console_input_pause(void) {}
void console_input_resume(void) {}

/* ---------------------------------------------------------- devices */
static bool vtdtr_present;
static const void *captured_image;
static size_t captured_length;
static bool capturing;

struct fake_state {
	uint8_t bytes[96];
	uint32_t counter;
	bool paused;
	int pauses, resumes;
};
static struct fake_state src_state[2], dst_state[2];
static struct fake_state *state = src_state;	/* which VM's devices */
static uint8_t kbd_state[2][16], fwcfg_state[2][24];
static int side;	/* 0 source, 1 destination */

static bool restore_short, validate_short;
static int extra_capacity_error;
static size_t extra_capacity_value = 64;	/* the compat device always asks for room */
static int
fake_extra_capacity(struct pci_devinst *pdi, size_t *extra)
{
	(void)pdi;
	*extra = extra_capacity_value;
	return (extra_capacity_error);
}

static int
fake_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pdi = meta->dev_data;
	struct fake_state *s = &state[pdi->pi_slot];
	struct fake_state copy = *s;
	int ret = 0;

	if (boundary("device_snapshot") != 0)
		return (EIO);
	SNAPSHOT_BUF_OR_LEAVE(copy.bytes, sizeof(copy.bytes), meta, ret, done);
	if (restore_short && meta->op == VM_SNAPSHOT_RESTORE)
		goto done;	/* the counter is left unconsumed */
	SNAPSHOT_VAR_OR_LEAVE(copy.counter, meta, ret, done);
	if (meta->op == VM_SNAPSHOT_RESTORE) {
		memcpy(s->bytes, copy.bytes, sizeof(s->bytes));
		s->counter = copy.counter;
	}
done:
	return (ret);
}

static int
fake_validate(struct vm_snapshot_meta *meta)
{
	struct fake_state copy;
	int ret = 0;

	if (boundary("device_validate") != 0)
		return (EINVAL);
	if (capturing) {
		captured_image = meta->buffer.buf_start;
		captured_length = meta->buffer.buf_size;
	}
	SNAPSHOT_BUF_OR_LEAVE(copy.bytes, sizeof(copy.bytes), meta, ret, done);
	if (validate_short)
		goto done;	/* the counter is left unconsumed */
	SNAPSHOT_VAR_OR_LEAVE(copy.counter, meta, ret, done);
	if (copy.counter == 0xdeadbeef)
		ret = EINVAL;
	/* The private image is valid but the daemon state is not rebound: the
	 * production DTrace device answers EOPNOTSUPP here. */
	if (ret == 0 && capturing)
		ret = EOPNOTSUPP;
done:
	return (ret);
}
/* Capture-end shapes: 0 normal; 1 incomplete; 2 no image; 3 zero length;
 * 4 image outside the record; 5 image too long for the record. */
static int capture_shape;

static int compat_error, compat_variant;
static int
fake_compat(struct pci_devinst *pdi, struct pci_snapshot_compat *compat)
{
	(void)pdi;
	if (compat_error != 0)
		return (compat_error);
	memset(compat, 0, sizeof(*compat));
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = 2;
	compat->queue_count = 3 + compat_variant;
	compat->msix_table_count = 4;
	compat->config_size = 128;
	compat->offered_features = 0xf0f0;
	compat->negotiated_features = 0x00f0;
	strlcpy(compat->queue_sizes, "128,128,64", sizeof(compat->queue_sizes));
	return (0);
}

static struct pci_devemu emu_plain = {
	.pe_emu = "fake-plain", .pe_snapshot = fake_snapshot,
	.pe_snapshot_validate = fake_validate,
	.pe_restore_phase = PCI_RESTORE_NORMAL,
};
static struct pci_devemu emu_compat = {
	.pe_emu = "fake-compat", .pe_snapshot = fake_snapshot,
	.pe_snapshot_validate = fake_validate, .pe_snapshot_compat = fake_compat,
	.pe_snapshot_extra_capacity = fake_extra_capacity,
	.pe_restore_phase = PCI_RESTORE_NORMAL,
};
static struct pci_devinst pci_devices[2];

static void
devices_init(void)
{
	memset(pci_devices, 0, sizeof(pci_devices));
	pci_devices[0].pi_d = &emu_plain;
	pci_devices[0].pi_slot = 0;
	strlcpy(pci_devices[0].pi_name, "plain0", sizeof(pci_devices[0].pi_name));
	pci_devices[1].pi_d = &emu_compat;
	pci_devices[1].pi_slot = 1;
	strlcpy(pci_devices[1].pi_name, "compat1", sizeof(pci_devices[1].pi_name));
	for (int i = 0; i < 2; i++) {
		memset(&src_state[i], 0, sizeof(src_state[i]));
		memset(&dst_state[i], 0, sizeof(dst_state[i]));
		for (size_t j = 0; j < sizeof(src_state[i].bytes); j++)
			src_state[i].bytes[j] = (uint8_t)(i * 50 + j);
		src_state[i].counter = 1000 + (uint32_t)i;
	}
	for (int j = 0; j < 16; j++)
		kbd_state[0][j] = (uint8_t)(0x40 + j), kbd_state[1][j] = 0;
	for (int j = 0; j < 24; j++)
		fwcfg_state[0][j] = (uint8_t)(0x80 + j), fwcfg_state[1][j] = 0;
	for (int j = 0; j < 32; j++)
		tpm_state[0][j] = (uint8_t)(0xc0 ^ j), tpm_state[1][j] = 0;
	tpm_reading_side[0] = tpm_reading_side[1] = false;
}

struct pci_devinst *
pci_next(const struct pci_devinst *cursor)
{
	if (cursor == NULL)
		return (&pci_devices[0]);
	if (cursor == &pci_devices[0])
		return (&pci_devices[1]);
	return (NULL);
}

int
pci_snapshot(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pdi = meta->dev_data;

	return (pdi->pi_d->pe_snapshot(meta));
}

int
pci_snapshot_validate(struct vm_snapshot_meta *meta)
{
	struct pci_devinst *pdi = meta->dev_data;

	return (pdi->pi_d->pe_snapshot_validate(meta));
}

int
pci_snapshot_compat(struct pci_devinst *pdi, struct pci_snapshot_compat *compat)
{
	int error = boundary("pci_snapshot_compat");

	if (error != 0)
		return (error);
	if (pdi->pi_d->pe_snapshot_compat == NULL)
		return (ENOENT);
	return (pdi->pi_d->pe_snapshot_compat(pdi, compat));
}

static bool release_fence_on_pause;
static int release_fence_result = -1;
int
pci_pause(struct pci_devinst *pdi)
{
	int error = boundary("pci_pause");

	if (error != 0)
		return (error);
	if (release_fence_on_pause) {
		release_fence_on_pause = false;
		release_fence_result = checkpoint_restore_startup_release();
	}
	state[pdi->pi_slot].paused = true;
	state[pdi->pi_slot].pauses++;
	return (0);
}

static bool release_fence_on_resume;	/* the fence vanishes under the transaction */
int
pci_resume(struct pci_devinst *pdi)
{
	int error = boundary("pci_resume");

	if (error != 0)
		return (error);
	if (release_fence_on_resume) {
		release_fence_on_resume = false;
		(void)checkpoint_restore_startup_release();
	}
	state[pdi->pi_slot].paused = false;
	state[pdi->pi_slot].resumes++;
	return (0);
}

int
atkbdc_snapshot(struct vm_snapshot_meta *meta)
{
	uint8_t copy[16];
	int ret = 0;

	if (boundary("atkbdc_snapshot") != 0)
		return (EIO);
	memcpy(copy, kbd_state[side], sizeof(copy));
	SNAPSHOT_BUF_OR_LEAVE(copy, sizeof(copy), meta, ret, done);
	if (meta->op == VM_SNAPSHOT_RESTORE)
		memcpy(kbd_state[side], copy, sizeof(copy));
done:
	return (ret);
}

/*
 * VM generation device (vmgenc.c) per VM: the page the guest reads, the ACPI
 * PM event registers and the GPE notifications raised.  A destination's page
 * starts with its own random ID; a checkpoint restore's fixed-ROM copy is
 * modelled by the test writing the checkpoint's ID there first.
 */
static bool vmgenc_present[2] = { true, true };
static uint8_t vmgenc_page[2][CHECKPOINT_VMGENID_ID_SIZE];
static struct checkpoint_acpi_pm vmgenc_pm[2];
static int vmgenc_notifies[2], vmgenc_pm_writes[2];
static int entropy_repeat;	/* draws that repeat the destination's ID */
static const uint8_t *entropy_queue[4];	/* scripted draws, last first */
static int entropy_queued;

int
vmgenc_current_id(struct vmctx *ctx, uint8_t id[CHECKPOINT_VMGENID_ID_SIZE])
{
	int vm = ctx == &dst_vm;

	if (!vmgenc_present[vm])
		return (ENOENT);
	memcpy(id, vmgenc_page[vm], CHECKPOINT_VMGENID_ID_SIZE);
	return (0);
}

int
vmgenc_checkpoint_state(struct vmctx *ctx, struct checkpoint_vmgenid *record)
{
	int vm = ctx == &dst_vm;

	memset(record, 0, sizeof(*record));
	if (!vmgenc_present[vm])
		return (ENOENT);
	memcpy(record->id, vmgenc_page[vm], CHECKPOINT_VMGENID_ID_SIZE);
	record->pm = vmgenc_pm[vm];
	return (0);
}

int
vmgenc_restore_apply(struct vmctx *ctx,
    const uint8_t id[CHECKPOINT_VMGENID_ID_SIZE],
    const struct checkpoint_acpi_pm *pm, bool notify)
{
	int vm = ctx == &dst_vm, error = boundary("vmgenc_restore_apply");

	if (error != 0)
		return (error == FAULT_NOERRNO ? EIO : error);
	CHECK(vmgenc_present[vm]);
	memcpy(vmgenc_page[vm], id, CHECKPOINT_VMGENID_ID_SIZE);
	if (pm != NULL) {
		vmgenc_pm[vm] = *pm;
		vmgenc_pm_writes[vm]++;
	}
	if (notify)
		vmgenc_notifies[vm]++;
	return (0);
}

int __real_getentropy(void *, size_t);
int
__wrap_getentropy(void *buf, size_t len)
{
	LIBC_FAULT("getentropy", -1);
	if (entropy_queued > 0 && len == CHECKPOINT_VMGENID_ID_SIZE) {
		memcpy(buf, entropy_queue[--entropy_queued], len);
		return (0);
	}
	if (entropy_repeat > 0 && len == CHECKPOINT_VMGENID_ID_SIZE) {
		entropy_repeat--;
		memcpy(buf, vmgenc_page[1], len);
		return (0);
	}
	return (__real_getentropy(buf, len));
}

static bool fwcfg_on = true;
bool qemu_fwcfg_enabled(void) { return (fwcfg_on); }

static void
fwcfg_compat(struct pci_snapshot_compat *compat)
{
	memset(compat, 0, sizeof(*compat));
	compat->schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	compat->transport = 9;
	compat->config_size = 24;
}

int
qemu_fwcfg_snapshot(struct vm_snapshot_meta *meta)
{
	uint8_t copy[24];
	int ret = 0;

	if (boundary("qemu_fwcfg_snapshot") != 0)
		return (EIO);
	memcpy(copy, fwcfg_state[side], sizeof(copy));
	SNAPSHOT_BUF_OR_LEAVE(copy, sizeof(copy), meta, ret, done);
	if (meta->op == VM_SNAPSHOT_RESTORE)
		memcpy(fwcfg_state[side], copy, sizeof(copy));
done:
	return (ret);
}

int
tpm_device_snapshot(struct vm_snapshot_meta *meta)
{
	uint8_t copy[32];
	int ret = 0;

	CHECK(tpm_present);
	if (meta->op == VM_SNAPSHOT_SAVE)
		CHECK(tpm_reading);	/* writes drained before the copy */
	if (meta->op == VM_SNAPSHOT_VALIDATE && tpm_validate_error != 0)
		return (tpm_validate_error);
	memcpy(copy, tpm_state[side], sizeof(copy));
	SNAPSHOT_BUF_OR_LEAVE(copy, sizeof(copy), meta, ret, done);
	if (meta->op == VM_SNAPSHOT_RESTORE)
		memcpy(tpm_state[side], copy, sizeof(copy));
done:
	return (ret);
}

int
qemu_fwcfg_snapshot_compat(struct pci_snapshot_compat *compat)
{
	fwcfg_compat(compat);
	return (boundary("qemu_fwcfg_snapshot_compat"));
}

int
qemu_fwcfg_snapshot_compat_record(const void *record, size_t size,
    struct pci_snapshot_compat *compat)
{
	(void)record;
	if (size != 24)
		return (EINVAL);
	fwcfg_compat(compat);
	return (0);
}

/* ------------------------------------------- HyperTrace boundaries */
static bool tracing;
int hypertrace_initialized(void) { return (tracing); }
static uint8_t trace_record[HYPERTRACE_SESSION_RECORD_SIZE];
static int stop_status_busy;

static int clock_count_at_begin;
int pci_vtdtr_session_checkpoint_begin(struct vmctx *ctx)
{
	(void)ctx;
	if (clock_track) {
		clock_calls_after_begin = 0;
		clock_deadline_base = clock_last;	/* the deadline reading */
		clock_count_at_begin = clock_calls;
	}
	return (boundary("pci_vtdtr_session_checkpoint_begin"));
}
int pci_vtdtr_session_stop_status(struct vmctx *ctx)
{
	(void)ctx;
	if (stop_status_busy > 0) {
		stop_status_busy--;
		return (EBUSY);
	}
	return (boundary("pci_vtdtr_session_stop_status"));
}
static int collectors_remaining;
int pci_vtdtr_session_collectors_stop_step(struct vmctx *ctx, bool *complete)
{
	(void)ctx;
	*complete = collectors_remaining-- <= 0;
	return (boundary("pci_vtdtr_session_collectors_stop_step"));
}
int
pci_vtdtr_session_checkpoint_export(struct vmctx *ctx, void *record, size_t len)
{
	struct hypertrace_session_record r = { .vmid = ctx->vmid, .epoch = ctx->epoch,
	    .stop_token = 0x77, .features = HYPERTRACE_SESSION_FEATURES };
	int error = boundary("pci_vtdtr_session_checkpoint_export");

	CHECK(len == HYPERTRACE_SESSION_RECORD_SIZE);
	if (error != 0)
		return (error);
	CHECK(hypertrace_session_record_encode(record, len, &r) == 0);
	memcpy(trace_record, record, len);
	return (0);
}
int pci_vtdtr_checkpoint_stop(void) { return (boundary("pci_vtdtr_checkpoint_stop")); }
/* The compat device doubles as the virtio-dtrace device when present: its
 * validated record is the private image the coordinator captures. */
static bool vtdtr_both;		/* both fake devices claim to be the DTrace device */
bool pci_vtdtr_checkpoint_is_device(const struct pci_devinst *pdi)
{
	return (vtdtr_present && (pdi == &pci_devices[1] || vtdtr_both));
}
int pci_vtdtr_checkpoint_features_validate(uint64_t f) { (void)f; return (boundary("pci_vtdtr_checkpoint_features_validate")); }
int pci_vtdtr_checkpoint_capture_begin(struct pci_devinst *p)
{
	int error = boundary("pci_vtdtr_checkpoint_capture_begin");

	(void)p;
	/* A refused begin leaves no capture open (no end call follows). */
	capturing = error == 0;
	captured_image = NULL;
	return (error);
}
int pci_vtdtr_checkpoint_capture_end(struct pci_devinst *p, const void **i, size_t *l, bool *c)
{
	(void)p;
	capturing = false;
	*i = captured_image;
	*l = captured_length;
	*c = captured_image != NULL;
	switch (capture_shape) {
	case 1: *c = false; break;
	case 2: *i = NULL; break;
	case 3: *l = 0; break;
	case 4: *i = (const uint8_t *)captured_image - 1; break;
	case 5: *l = captured_length + 1; break;
	case 6: *i = (const uint8_t *)captured_image + captured_length + 1; break;
	}
	return (boundary("pci_vtdtr_checkpoint_capture_end"));
}

/* The retained continuity handoff and the remaining device hooks are never
 * reached in these configurations; they abort if they ever are. */
#define UNREACHED(sig) sig { abort(); }
UNREACHED(int hypertrace_handoff_destination_ensure(struct vmctx *c, uint8_t o, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_destination_import_prestart(struct vmctx *c, const uint8_t t[16], const uint8_t d[32], const void *b, size_t l))
UNREACHED(int hypertrace_handoff_destination_prestart(struct vmctx *c, uint8_t o, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_destination_promote_prestart(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_destination_stage_release_prestart(struct vmctx *c, const uint8_t t[16], const uint8_t d[32], const uint8_t r[CHECKPOINT_RELEASE_WIRE_SIZE]))
UNREACHED(int hypertrace_handoff_execution_start(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_rebind_begin_optional(struct vmctx *c, const uint8_t t[16], const uint8_t d[32], bool *r))
UNREACHED(int hypertrace_handoff_rebind_commit_empty(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_rebind_empty_ready(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_rebind_nonempty_preflight(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_rebind_pending(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_rebind_stage(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_handoff_replay_drain(struct vmctx *c, const uint8_t t[16], const uint8_t d[32], int ms))
UNREACHED(int hypertrace_release_attestation_inspect(const uint8_t r[CHECKPOINT_RELEASE_WIRE_SIZE], const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int hypertrace_release_recover(const uint8_t t[16], const uint8_t d[32], uint8_t r[CHECKPOINT_RELEASE_WIRE_SIZE]))
UNREACHED(int hypertrace_release_transfer_inspect(const uint8_t r[CHECKPOINT_RELEASE_WIRE_SIZE], const uint8_t t[16], const uint8_t d[32], const void *b, size_t l))
UNREACHED(int hypertrace_transfer_inspect(const void *w, size_t l, const uint8_t t[16], bool *s))
UNREACHED(int hypertrace_transfer_replay_controls(const void *w, size_t l, const uint8_t t[16], size_t *c))
UNREACHED(int pci_vtdtr_checkpoint_private_image_bind(void *i, size_t l, struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int pci_vtdtr_checkpoint_private_image_query(void *i, size_t l, struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int pci_vtdtr_checkpoint_private_image_replay_room(void *i, size_t l, size_t c))
UNREACHED(int pci_vtdtr_checkpoint_publish_paused(struct pci_devinst *p))
UNREACHED(int pci_vtdtr_handoff_ticket_attach_paused(struct pci_devinst *p, const uint8_t t[16], const uint8_t d[32], const dtraced_replay_kill_t *k, size_t n))
UNREACHED(void pci_vtdtr_handoff_ticket_clear(struct pci_devinst *p))
UNREACHED(int hypertrace_handoff_source_release_open(struct vmctx *c))
UNREACHED(int hypertrace_handoff_source_release_finish(int f, const uint8_t t[16], const uint8_t d[32], uint8_t r[DTRACED_RELEASE_ATTESTED_SIZE], bool *s))
UNREACHED(int hypertrace_handoff_source_bundle_fresh(struct vmctx *c, const uint8_t t[16], void **b, size_t *l))
UNREACHED(int hypertrace_handoff_source_ensure(struct vmctx *c, uint8_t o, const uint8_t t[16], const uint8_t d[32], bool *a))
UNREACHED(int hypertrace_handoff_source_gate_ensure(struct vmctx *c, uint8_t o, const uint8_t t[16]))
UNREACHED(int hypertrace_handoff_source_drain(struct vmctx *c, const uint8_t t[16], const uint8_t d[32]))
UNREACHED(int pci_vtdtr_checkpoint_source_replay_room(struct pci_devinst *p, size_t n))

static int start_ready_error;
int hypertrace_start_ready(struct vmctx *c, int ms)
{
	(void)c; (void)ms;
	if (start_ready_error) {
		errno = start_ready_error == FAULT_NOERRNO ? 0 : start_ready_error;
		return (-1);
	}
	return (0);
}
static size_t replay_fake_count;	/* admission replay KILLs the daemon reports */
int hypertrace_take_replay_kills(struct vmctx *c, dtraced_replay_kill_t **k, size_t *n)
{
	int error = boundary("hypertrace_take_replay_kills");

	(void)c;
	*k = NULL;
	*n = 0;
	if (error == 0 && replay_fake_count != 0) {
		*k = __real_calloc(replay_fake_count, sizeof(**k));
		*n = replay_fake_count;
	}
	return (error);
}
int pci_vtdtr_session_attach_begin(struct vmctx *c) { (void)c; return (boundary("pci_vtdtr_session_attach_begin")); }
int pci_vtdtr_session_discard_paused(struct pci_devinst *p) { (void)p; return (boundary("pci_vtdtr_session_discard_paused")); }
int pci_vtdtr_session_restore_stage_paused(struct pci_devinst *p, const void *r, size_t rl, void *i, size_t il)
{ (void)p; (void)r; (void)rl; (void)i; (void)il; return (boundary("pci_vtdtr_session_restore_stage_paused")); }
int pci_vtdtr_session_migration_stage_paused(struct pci_devinst *p, const void *r, size_t rl, void *i, size_t il)
{ (void)p; (void)r; (void)rl; (void)i; (void)il; return (boundary("pci_vtdtr_session_migration_stage_paused")); }
int pci_vtdtr_session_migration_release_paused(struct pci_devinst *p, const void *r, size_t rl)
{ (void)p; (void)r; (void)rl; return (boundary("pci_vtdtr_session_migration_release_paused")); }

/* ------------------------------------------------------------ helpers */
SET_DECLARE(ipc_cmd_set, struct ipc_command);

static nvlist_t *(*ipc_lookup(const char *name))(struct vmctx *, const nvlist_t *)
{
	struct ipc_command **cmd;

	SET_FOREACH(cmd, ipc_cmd_set)
		if (strcmp((*cmd)->name, name) == 0)
			return ((*cmd)->handler);
	abort();
}

static char dir[256];
static int dirfd_;

static int
list_dir(char names[][128], int max)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	int n = 0;

	CHECK(d != NULL);
	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] == '.')
			continue;
		CHECK(n < max);
		strlcpy(names[n++], e->d_name, 128);
	}
	closedir(d);
	/* sort */
	for (int i = 0; i < n; i++)
		for (int j = i + 1; j < n; j++)
			if (strcmp(names[i], names[j]) > 0) {
				char t[128];
				strlcpy(t, names[i], 128);
				strlcpy(names[i], names[j], 128);
				strlcpy(names[j], t, 128);
			}
	return (n);
}

static void
fresh_dir(void)
{
	char path[300];

	snprintf(path, sizeof(path), "%s", "ckpt.XXXXXX");
	CHECK(mkdtemp(path) != NULL);
	CHECK(realpath(path, dir) != NULL);
	dirfd_ = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(dirfd_ >= 0);
}

/* Restore the named checkpoint into dst_vm and compare everything. */
static int
restore_into_destination(const char *name, bool compare)
{
	struct restore_state rstate;
	char path[400];
	int error;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (load_restore_file(path, &rstate) != 0)
		return (-1);
	vm_init(&dst_vm, "dst", 0x99);
	side = 1;
	state = dst_state;
	tpm_reading_side[1] = false;	/* a new destination process */
	checkpoint_restore_startup_hold();
	error = vm_restore_transaction(&dst_vm, &rstate);
	if (error == 0) {
		CHECK(!checkpoint_restore_startup_held());
		CHECK(!dst_vm.session_active && dst_vm.sessions_committed >= 1);
		if (compare) {
			CHECK(ram_equal(&src_vm, &dst_vm));
			for (int req = 0; req < 16; req++)
				if (dst_vm.kern_len[req] != 0)
					for (size_t i = 0; i < dst_vm.kern_len[req]; i++)
						CHECK(dst_vm.kern[req][i] ==
						    (uint8_t)(src_vm.epoch + req * 17 + i));
			for (int i = 0; i < 2; i++) {
				CHECK(memcmp(dst_state[i].bytes, src_state[i].bytes, 96) == 0);
				CHECK(dst_state[i].counter == src_state[i].counter);
				CHECK(!dst_state[i].paused);
			}
			CHECK(memcmp(kbd_state[1], kbd_state[0], 16) == 0);
			CHECK(memcmp(fwcfg_state[1], fwcfg_state[0], 24) == 0);
			if (devmem_enabled)
				CHECK(memcmp(devmem_buf[1][0], devmem_buf[0][0], 8192) == 0 &&
				    memcmp(devmem_buf[1][1], devmem_buf[0][1], 4096) == 0);
		}
	} else {
		/* A failed restore never lets the destination execute. */
		CHECK(checkpoint_restore_startup_held());
		CHECK(!dst_vm.session_active);
		(void)checkpoint_restore_startup_release();
	}
	destroy_restore_state(&rstate);
	side = 0;
	state = src_state;
	return (error);
}

/* ------------------------------------------------------------- tests */
static void
test_round_trip(void)
{
	char before[32][128], after[32][128];
	int n;

	fresh_dir();
	vm_init(&src_vm, "src", 0x11);
	devices_init();
	reset_points();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	CHECK(!src_vm.suspended && !src_vm.session_active && src_vm.sessions_committed == 1);
	CHECK(!src_state[0].paused && !src_state[1].paused);
	n = list_dir(before, 32);
	CHECK(n >= 4);	/* manifest, lock, data, kern, meta */
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	/* A second checkpoint replaces the generation and removes the old one. */
	src_vm.base[100] ^= 1;
	src_state[0].counter++;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	CHECK(list_dir(after, 32) == n);
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	printf("snapshot round trip: two generations restored exactly, old members removed\n");
}

/* A stopped checkpoint publishes, stops the device workers, destroys the
 * source and exits with BHYVE_EXIT_SUSPEND; the checkpoint restores. */
static void
test_stop_vm(bool fresh)
{
	pid_t child;
	int status;

	fresh_dir();
	vm_init(&src_vm, "src", 0x22);
	devices_init();
	tracing = fresh;
	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		stop_status_busy = 2;		/* the stop poll retries */
		collectors_remaining = 1;	/* one collector step remains */
		(void)vm_checkpoint(&src_vm, dirfd_, "vm.ckp", true);
		_exit(99);	/* not reached on success */
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == BHYVE_EXIT_SUSPEND);
	/* The parent's model still describes the source at checkpoint time. */
	{
		char names[16][128];
		int n = list_dir(names, 16);
		CHECK(n == (fresh ? 6 : 5));
	}
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	tracing = false;
	printf("snapshot stop_vm (fresh %d): source exits suspended, checkpoint restores\n", fresh);
}

/*
 * Trace continuity is a disabled future feature (fresh-session contract):
 * restore refuses a format-4 transfer-ticket checkpoint at load, and the
 * restore transaction refuses format 4 or handoff metadata version 1 before
 * any mutation.  Regression: both used to enter the destination handoff.
 * Oracle: the refusal (ENOTSUP / load failure), the startup fence still held,
 * no kernel session begun and no device paused; the unmodified fresh image
 * still restores.
 */
static void
test_continuity_refusal(void)
{
	struct restore_state rstate;
	char path[400];
	pid_t child;
	int status;

	fresh_dir();
	vm_init(&src_vm, "src", 0x23);
	devices_init();
	tracing = true;
	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		(void)vm_checkpoint(&src_vm, dirfd_, "vm.ckp", true);
		_exit(99);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == BHYVE_EXIT_SUSPEND);
	snprintf(path, sizeof(path), "%s/vm.ckp", dir);
	for (int variant = 0; variant < 2; variant++) {
		CHECK(load_restore_file(path, &rstate) == 0);
		CHECK(rstate.checkpoint_format_version == 5);
		if (variant == 0)
			rstate.checkpoint_format_version = 4;
		else {
			/* Handoff metadata version 1 in a legacy (format 3)
			 * image requests the transfer-ticket handoff. */
			rstate.checkpoint_format_version = 3;
			ucl_object_t *basic = __DECONST(ucl_object_t *,
			    lookup_basic_metadata_object(&rstate));
			CHECK(basic != NULL && ucl_object_replace_key(basic,
			    ucl_object_fromint(1), JSON_HYPERTRACE_HANDOFF_VERSION_KEY,
			    0, true));
		}
		vm_init(&dst_vm, "dst", 0x99);
		checkpoint_restore_startup_hold();
		CHECK(vm_restore_transaction(&dst_vm, &rstate) == ENOTSUP);
		CHECK(checkpoint_restore_startup_held() && !dst_vm.session_active &&
		    dst_vm.sessions_committed == 0 && dst_vm.sessions_aborted == 0 &&
		    !dst_state[0].paused && !dst_state[1].paused);
		(void)checkpoint_restore_startup_release();
		destroy_restore_state(&rstate);
	}
	/* The same generation published as format 4 is refused at load, by
	 * name, before any member is opened (stderr names the format).  The
	 * two manifest encodings differ only in the magic line. */
	{
		struct checkpoint_manifest m;
		char original[4096], changed[4096], err[4096];
		ssize_t olen, n;
		bool exists, is_manifest;
		int fd, saved, errfd;

		fd = openat(dirfd_, "vm.ckp", O_RDONLY);
		CHECK(fd >= 0);
		olen = read(fd, original, sizeof(original));
		close(fd);
		CHECK(olen > (ssize_t)sizeof(CHECKPOINT_MANIFEST_MAGIC_V5) &&
		    memcmp(original, CHECKPOINT_MANIFEST_MAGIC_V5,
		    sizeof(CHECKPOINT_MANIFEST_MAGIC_V5) - 1) == 0);
		memcpy(changed, original, olen);
		memcpy(changed, CHECKPOINT_MANIFEST_MAGIC_V4,
		    sizeof(CHECKPOINT_MANIFEST_MAGIC_V4) - 1);
		fd = openat(dirfd_, "vm.ckp", O_WRONLY | O_TRUNC);
		CHECK(fd >= 0 && write(fd, changed, olen) == olen);
		close(fd);
		CHECK(checkpoint_manifest_read_at(dirfd_, "vm.ckp", &m, &exists,
		    &is_manifest) == 0 && exists && is_manifest && m.format_version == 4);
		errfd = openat(dirfd_, "stderr.txt", O_RDWR | O_CREAT | O_TRUNC, 0600);
		fflush(stderr);
		saved = dup(STDERR_FILENO);
		CHECK(errfd >= 0 && dup2(errfd, STDERR_FILENO) == STDERR_FILENO);
		CHECK(load_restore_file(path, &rstate) == -1);
		fflush(stderr);
		dup2(saved, STDERR_FILENO);
		close(saved);
		n = pread(errfd, err, sizeof(err) - 1, 0);
		close(errfd);
		err[n < 0 ? 0 : n] = '\0';
		CHECK(strstr(err, "trace-continuity format (manifest format 4)") != NULL);
		fd = openat(dirfd_, "vm.ckp", O_WRONLY | O_TRUNC);
		CHECK(fd >= 0 && write(fd, original, olen) == olen);
		close(fd);
	}
	/* The unmodified fresh image still restores. */
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	tracing = false;
	printf("snapshot continuity refusal: format 4 and handoff v1 refused before mutation\n");
}

static void
test_refusals(void)
{
	fresh_dir();
	vm_init(&src_vm, "src", 0x33);
	devices_init();
	/* Fresh tracing requires a stopped checkpoint. */
	tracing = true;
	BOTH_PARITIES(CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == ENOTSUP));
	tracing = false;
	/* Names that cannot carry the generation suffixes. */
	{
		char longname[NAME_MAX + 2];
		memset(longname, 'n', sizeof(longname) - 1);
		longname[sizeof(longname) - 1] = '\0';
		CHECK(vm_checkpoint(&src_vm, dirfd_, longname, false) == ENAMETOOLONG);
	}
	/* Merged TPM: a guest whose TPM cannot migrate is refused before
	 * anything is created; otherwise its state is checkpointed under the
	 * device pause (begin_read .. end) and restored exactly. */
	tpm_present = true;
	tpm_migration_error = ENOTSUP;
	BOTH_PARITIES(CHECK(vm_checkpoint(&src_vm, dirfd_, "tpm.ckp", false) == ENOTSUP));
	CHECK(faccessat(dirfd_, "tpm.ckp.lock", F_OK, 0) != 0);
	tpm_migration_error = 0;
	tpm_begins = tpm_ends = 0;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tpm.ckp", false) == 0);
	CHECK(tpm_begins == 1 && tpm_ends == 1 && !tpm_reading_side[0]);
	CHECK(restore_into_destination("tpm.ckp", true) == 0);
	CHECK(memcmp(tpm_state[1], tpm_state[0], 32) == 0);
	/* A destination TPM that cannot migrate refuses before mutation; an
	 * invalid TPM record is refused in preflight. */
	tpm_migration_error = EOPNOTSUPP;
	CHECK(restore_into_destination("tpm.ckp", false) == EOPNOTSUPP);
	tpm_migration_error = 0;
	tpm_validate_error = EINVAL;
	CHECK(restore_into_destination("tpm.ckp", false) != 0);
	tpm_validate_error = 0;
	/* A TPM that cannot drain its writes fails the pause; the devices
	 * paused before it are resumed again. */
	tpm_begin_error = EBUSY;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tpmbusy.ckp", false) == EBUSY);
	CHECK(!src_state[0].paused && !src_state[1].paused && !tpm_reading_side[0]);
	tpm_begin_error = 0;
	/* A TPM that cannot restart keeps every device paused. */
	side = 0;
	state = src_state;
	CHECK(vm_pause_devices() == 0 && tpm_reading);
	tpm_end_error = EIO;
	CHECK(vm_resume_devices() == EIO && src_state[0].paused && tpm_reading);
	tpm_end_error = 0;
	CHECK(vm_resume_devices() == 0 && !src_state[0].paused && !tpm_reading);
	tpm_present = false;
	/* A destination with a TPM the image lacks has another topology. */
	tpm_present = true;
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	tpm_present = false;
	/* A restore path whose member name is longer than NAME_MAX. */
	{
		struct restore_state rstate;
		char path[NAME_MAX + 400];
		size_t n = strlen(dir);
		memcpy(path, dir, n);
		path[n++] = '/';
		memset(path + n, 'n', NAME_MAX + 1);
		path[n + NAME_MAX + 1] = '\0';
		CHECK(load_restore_file(path, &rstate) == -1);
	}
	/* The lock name exists as a directory. */
	CHECK(mkdirat(dirfd_, "dir.ckp.lock", 0700) == 0);
	CHECK(vm_checkpoint(&src_vm, dirfd_, "dir.ckp", false) != 0);
	/* Restore of something that is not a manifest. */
	{
		int fd = openat(dirfd_, "plain.ckp", O_WRONLY | O_CREAT, 0600);
		CHECK(fd >= 0 && write(fd, "x", 1) == 1);
		close(fd);
		CHECK(restore_into_destination("plain.ckp", false) == -1);
		CHECK(restore_into_destination("absent.ckp", false) == -1);
	}
	/* The restore transaction refuses a caller without the startup fence. */
	{
		struct restore_state rstate;
		char path[400];
		CHECK(vm_checkpoint(&src_vm, dirfd_, "ok.ckp", false) == 0);
		snprintf(path, sizeof(path), "%s/ok.ckp", dir);
		CHECK(load_restore_file(path, &rstate) == 0);
		BOTH_PARITIES(CHECK(vm_restore_transaction(&dst_vm, &rstate) == EBUSY));
		BOTH_PARITIES(CHECK(vm_restore_transaction(NULL, &rstate) == EINVAL));
		BOTH_PARITIES(CHECK(vm_restore_transaction(&dst_vm, NULL) == EINVAL));
		destroy_restore_state(&rstate);
		destroy_restore_state(NULL);
	}
	/* IPC entry. */
	{
		nvlist_t *request = nvlist_create(0), *reply;
		reply = ipc_lookup("checkpoint")(&src_vm, request);
		CHECK(nvlist_exists_string(reply, "error"));
		nvlist_destroy(reply);
		nvlist_add_string(request, "filename", "ipc.ckp");
		nvlist_add_bool(request, "suspend", false);
		nvlist_add_descriptor(request, "fddir", dirfd_);
		reply = ipc_lookup("checkpoint")(&src_vm, request);
		CHECK(!nvlist_exists_string(reply, "error"));
		nvlist_destroy(reply);
		nvlist_destroy(request);
	}
	printf("snapshot refusals: tracing without stop, long name, lock, non-manifest, fence, IPC\n");
}

static void
test_migration_blob(bool fresh)
{
	uint8_t *blob = NULL, record[HYPERTRACE_SESSION_RECORD_SIZE];
	size_t len = 0;
	struct pci_devinst *device = NULL;
	struct vm_snapshot_capture cap = {0};
	int committed, aborted;

	vm_init(&src_vm, "src", 0x44);
	devices_init();
	tracing = fresh;
	vtdtr_present = fresh;
	if (fresh) {
		CHECK(vm_migrate_stop_tracing(&src_vm, record) == 0);
		CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == 0);
		{
			uint8_t *none = (uint8_t *)1;
			size_t zero = 1;
			struct vm_snapshot_capture other = {0};
			/* Fresh tracing is never silently stripped. */
			CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &none, &zero, &other) == EOPNOTSUPP);
			CHECK(none == NULL && zero == 0 && !other.active);
			/* A capture that already holds the fence is not reused. */
			CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &none, &zero, &cap) == EBUSY);
		}
	} else {
		CHECK(vm_migrate_stop_tracing(&src_vm, record) == ENXIO);
		CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == 0);
	}
	CHECK(blob != NULL && len > MIGRATE_BLOB_HDR);
	/* Merged: the event fence stays held through the handoff; retirement
	 * commits it (fresh here), a rollback aborts it (ordinary here). */
	CHECK(src_vm.session_active && cap.active && !cap.unresolved);
	committed = src_vm.sessions_committed;
	aborted = src_vm.sessions_aborted;
	CHECK(vm_snapshot_dev_state_finish(NULL, &cap, fresh) == EINVAL);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, NULL, fresh) == EINVAL);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, fresh) == 0);
	CHECK(!src_vm.session_active && !cap.active);
	CHECK(src_vm.sessions_committed == committed + (fresh ? 1 : 0) &&
	    src_vm.sessions_aborted == aborted + (fresh ? 0 : 1));
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, fresh) == 0);	/* idle */
	/* Destination: guest RAM was streamed separately. */
	vm_init(&dst_vm, "dst", 0x44);
	side = 1;
	state = dst_state;
	CHECK((fresh ? vm_migrate_fresh_commit_state(&dst_vm, blob, len, &device) :
	    vm_migrate_commit_state(&dst_vm, blob, len)) == EBUSY);	/* no fence */
	checkpoint_restore_startup_hold();
	if (fresh) {
		CHECK(vm_migrate_commit_state(&dst_vm, blob, len) == EOPNOTSUPP);
		CHECK(vm_migrate_fresh_commit_state(&dst_vm, blob, len, NULL) == EINVAL);
		CHECK(vm_migrate_fresh_commit_state(&dst_vm, blob, len, &device) == 0);
	} else {
		CHECK(vm_migrate_commit_state(&dst_vm, blob, MIGRATE_BLOB_HDR - 1) == EINVAL);
		CHECK(vm_migrate_commit_state(&dst_vm, blob, len) == 0);
	}
	CHECK(dst_state[0].paused && dst_state[1].paused);	/* still paused */
	CHECK(checkpoint_restore_startup_held());
	for (int i = 0; i < 2; i++)
		CHECK(memcmp(dst_state[i].bytes, src_state[i].bytes, 96) == 0 &&
		    dst_state[i].counter == src_state[i].counter);
	CHECK(memcmp(kbd_state[1], kbd_state[0], 16) == 0);
	if (fresh) {
		CHECK(vm_migrate_resume(&dst_vm) == EOPNOTSUPP);
		CHECK(vm_migrate_fresh_resume(&dst_vm, NULL, record) == EINVAL);
		CHECK(vm_migrate_fresh_resume(&dst_vm, (void *)&dst_vm, record) == 0);
	} else {
		CHECK(vm_migrate_fresh_resume(&dst_vm, (void *)&dst_vm, record) == EBUSY);
		CHECK(vm_migrate_resume(&dst_vm) == 0);
	}
	CHECK(!checkpoint_restore_startup_held() && dst_vm.restore_time_calls == 1);
	CHECK(!dst_state[0].paused && !dst_state[1].paused);
	CHECK(vm_migrate_resume(&dst_vm) == (fresh ? EOPNOTSUPP : EBUSY));
	free(blob);
	side = 0;
	state = src_state;
	tracing = false;
	vtdtr_present = false;
	printf("snapshot migration blob (fresh %d): %zu bytes, device and kernel state equal\n",
	    fresh, len);
}

/* ------------------------------------------------- VM generation ID */
static void
vmgenid_seed(int vm, uint8_t seed)
{
	for (int i = 0; i < CHECKPOINT_VMGENID_ID_SIZE; i++)
		vmgenc_page[vm][i] = (uint8_t)(seed + i * 3);
}

static bool
pm_equal(const struct checkpoint_acpi_pm *a, const struct checkpoint_acpi_pm *b)
{
	return (a->pm1_enable == b->pm1_enable && a->pm1_status == b->pm1_status &&
	    a->pm1_control == b->pm1_control && a->gpe0_enable == b->gpe0_enable &&
	    a->gpe0_status == b->gpe0_status && a->sci_active == b->sci_active);
}

static void
vmgenid_dest_reset(const uint8_t *page)
{
	memcpy(vmgenc_page[1], page, CHECKPOINT_VMGENID_ID_SIZE);
	memset(&vmgenc_pm[1], 0, sizeof(vmgenc_pm[1]));
	vmgenc_notifies[1] = vmgenc_pm_writes[1] = 0;
}

/* Capture a migration blob from src_vm and commit it into dst_vm. */
static int
vmgenid_migrate(bool corrupt)
{
	struct vm_snapshot_capture cap = {0};
	uint8_t *blob = NULL, *p;
	size_t len = 0;
	int error;

	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == 0);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, false) == 0);
	p = memmem(blob, len, "\"" JSON_VMGENID_STATE_KEY "\"", sizeof(JSON_VMGENID_STATE_KEY) + 1);
	CHECK((p != NULL) == vmgenc_present[0]);
	if (corrupt) {
		p = memmem(p, len - (size_t)(p - blob), "\"1:", 3);
		CHECK(p != NULL);
		p[1] = '2';	/* an unknown record version */
	}
	vm_init(&dst_vm, "dst", 0x45);
	side = 1;
	state = dst_state;
	checkpoint_restore_startup_hold();
	error = vm_migrate_commit_state(&dst_vm, blob, len);
	if (error == 0)
		CHECK(vm_migrate_resume(&dst_vm) == 0);
	else
		(void)checkpoint_restore_startup_release();
	free(blob);
	side = 0;
	state = src_state;
	return (error);
}

static void
test_vmgenid(void)
{
	const struct checkpoint_acpi_pm pm = { .pm1_enable = 0x0120,
	    .pm1_status = 0x0100, .pm1_control = 0x0001, .gpe0_enable = 1,
	    .gpe0_status = 0, .sci_active = true };
	uint8_t ckpt[CHECKPOINT_VMGENID_ID_SIZE], first[CHECKPOINT_VMGENID_ID_SIZE];
	uint8_t own[CHECKPOINT_VMGENID_ID_SIZE];

	fresh_dir();
	vm_init(&src_vm, "src", 0x21);
	devices_init();
	vmgenid_seed(0, 0x40);
	vmgenc_pm[0] = pm;
	vmgenc_notifies[0] = 0;
	memcpy(ckpt, vmgenc_page[0], sizeof(ckpt));

	/* A checkpoint of a running VM leaves its generation unchanged. */
	CHECK(vm_checkpoint(&src_vm, dirfd_, "gen.ckp", false) == 0);
	CHECK(memcmp(vmgenc_page[0], ckpt, sizeof(ckpt)) == 0);
	CHECK(vmgenc_notifies[0] == 0);

	/* Each restore of the same checkpoint is a new generation, notified. */
	for (int round = 0; round < 2; round++) {
		vmgenid_dest_reset(ckpt);	/* the fixed-ROM restore result */
		CHECK(restore_into_destination("gen.ckp", true) == 0);
		CHECK(memcmp(vmgenc_page[1], ckpt, sizeof(ckpt)) != 0);
		CHECK(vmgenc_notifies[1] == 1 && vmgenc_pm_writes[1] == 1);
		CHECK(pm_equal(&vmgenc_pm[1], &pm));
		if (round == 0)
			memcpy(first, vmgenc_page[1], sizeof(first));
		else
			CHECK(memcmp(first, vmgenc_page[1], sizeof(first)) != 0);
	}
	/* A draw equal to the ID being replaced is drawn again ... */
	vmgenid_dest_reset(ckpt);
	entropy_repeat = 2;
	CHECK(restore_into_destination("gen.ckp", true) == 0);
	CHECK(entropy_repeat == 0 && memcmp(vmgenc_page[1], ckpt, sizeof(ckpt)) != 0);
	CHECK(vmgenc_notifies[1] == 1);
	/* ... and a source that never yields a new ID fails the restore. */
	vmgenid_dest_reset(ckpt);
	entropy_repeat = 8;
	CHECK(restore_into_destination("gen.ckp", false) == EAGAIN);
	CHECK(vmgenc_notifies[1] == 0);
	entropy_repeat = 0;
	/* Neither an all-zero ID nor the checkpoint's own ID is accepted, also
	 * when the destination page differs from the checkpoint's. */
	{
		static const uint8_t zero[CHECKPOINT_VMGENID_ID_SIZE];
		uint8_t other[CHECKPOINT_VMGENID_ID_SIZE];

		memset(other, 0x5a, sizeof(other));
		vmgenid_dest_reset(other);
		entropy_queue[1] = zero;
		entropy_queue[0] = ckpt;
		entropy_queued = 2;
		CHECK(restore_into_destination("gen.ckp", true) == 0);
		CHECK(entropy_queued == 0 && vmgenc_notifies[1] == 1);
		CHECK(memcmp(vmgenc_page[1], ckpt, sizeof(ckpt)) != 0 &&
		    memcmp(vmgenc_page[1], zero, sizeof(zero)) != 0 &&
		    memcmp(vmgenc_page[1], other, sizeof(other)) != 0);
	}
	{
		struct restore_state blank;

		memset(&blank, 0, sizeof(blank));
		CHECK(lookup_vmgenid_state(&blank) == EINVAL && !blank.vmgenid_present);
	}
	/* A destination without a generation device ignores the record. */
	vmgenc_present[1] = false;
	vmgenid_dest_reset(ckpt);
	CHECK(restore_into_destination("gen.ckp", true) == 0);
	CHECK(vmgenc_notifies[1] == 0 && memcmp(vmgenc_page[1], ckpt, sizeof(ckpt)) == 0);
	vmgenc_present[1] = true;

	/* Live migration presents the source's ID, without a notification. */
	vm_init(&src_vm, "src", 0x22);
	devices_init();
	vmgenid_seed(0, 0x80);
	vmgenid_seed(1, 0x10);
	vmgenid_dest_reset(vmgenc_page[1]);
	CHECK(vmgenid_migrate(false) == 0);
	CHECK(memcmp(vmgenc_page[1], vmgenc_page[0], CHECKPOINT_VMGENID_ID_SIZE) == 0);
	CHECK(vmgenc_notifies[1] == 0 && vmgenc_pm_writes[1] == 1);
	CHECK(pm_equal(&vmgenc_pm[1], &vmgenc_pm[0]));
	/* A malformed record is refused before the destination changes. */
	vmgenid_seed(1, 0x10);
	memcpy(own, vmgenc_page[1], sizeof(own));
	vmgenid_dest_reset(own);
	CHECK(vmgenid_migrate(true) == EINVAL);
	CHECK(memcmp(vmgenc_page[1], own, sizeof(own)) == 0 && vmgenc_pm_writes[1] == 0);

	/* An older source sends no record: the destination keeps its own ID. */
	vmgenc_present[0] = false;
	vmgenid_dest_reset(own);
	CHECK(vmgenid_migrate(false) == 0);
	CHECK(memcmp(vmgenc_page[1], own, sizeof(own)) == 0);
	CHECK(vmgenc_notifies[1] == 0 && vmgenc_pm_writes[1] == 0);
	/* An older checkpoint without the record still restores as a new
	 * generation; the PM registers keep their reset values. */
	CHECK(vm_checkpoint(&src_vm, dirfd_, "old.ckp", false) == 0);
	vmgenid_dest_reset(ckpt);
	CHECK(restore_into_destination("old.ckp", true) == 0);
	CHECK(memcmp(vmgenc_page[1], ckpt, sizeof(ckpt)) != 0);
	CHECK(vmgenc_notifies[1] == 1 && vmgenc_pm_writes[1] == 0);
	vmgenc_present[0] = true;
	/* A PM image the record cannot carry fails the checkpoint. */
	vmgenc_pm[0].gpe0_enable = 2;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "bad.ckp", false) != 0);
	vmgenc_pm[0] = pm;
	printf("vmgenid: restore renews and notifies, migration keeps the source ID\n");
}

static void
test_vmgenid_codec(void)
{
	struct checkpoint_vmgenid r = {0}, d;
	char text[CHECKPOINT_VMGENID_TEXT_SIZE], bad[CHECKPOINT_VMGENID_TEXT_SIZE + 1];
	uint8_t cur[CHECKPOINT_VMGENID_ID_SIZE] = {1}, next[CHECKPOINT_VMGENID_ID_SIZE];
	bool notify;
	static const struct { size_t at; char c; } edits[] = {
		{ 0, '2' }, { 1, '-' }, { 2, 'G' }, { 3, 'A' }, { 34, '-' },
		{ 35, 'x' }, { 39, '-' }, { 35, 'f' }, { 40, 'f' }, { 45, 'f' },
		{ 50, '2' }, { 53, '2' }, { 56, '2' }, { 56, 'z' },
	};

	for (int i = 0; i < CHECKPOINT_VMGENID_ID_SIZE; i++)
		r.id[i] = (uint8_t)(0xa0 + i);
	r.pm = (struct checkpoint_acpi_pm){ 0x0520, 0x8731, 0x1ffd, 1, 1, true };
	CHECK(checkpoint_vmgenid_encode(&r, text, sizeof(text)) == 0);
	CHECK(strcmp(text, "1:a0a1a2a3a4a5a6a7a8a9aaabacadaeaf:0520:8731:1ffd:01:01:1") == 0);
	CHECK(checkpoint_vmgenid_decode(text, &d) == 0);
	CHECK(memcmp(d.id, r.id, sizeof(r.id)) == 0 && pm_equal(&d.pm, &r.pm));
	CHECK(checkpoint_vmgenid_encode(NULL, text, sizeof(text)) == EINVAL);
	CHECK(checkpoint_vmgenid_encode(&r, NULL, sizeof(text)) == EINVAL);
	CHECK(checkpoint_vmgenid_encode(&r, text, sizeof(text) - 1) == EINVAL);
	for (int f = 0; f < 5; f++) {
		struct checkpoint_vmgenid m = r;

		switch (f) {
		case 0: m.pm.pm1_enable |= 0x0001; break;
		case 1: m.pm.pm1_status |= 0x0002; break;
		case 2: m.pm.pm1_control |= 0x0002; break;
		case 3: m.pm.gpe0_enable |= 0x02; break;
		case 4: m.pm.gpe0_status |= 0x02; break;
		}
		CHECK(checkpoint_vmgenid_encode(&m, bad, sizeof(bad)) == EINVAL);
	}
	CHECK(checkpoint_vmgenid_decode(NULL, &d) == EINVAL);
	CHECK(checkpoint_vmgenid_decode(text, NULL) == EINVAL);
	CHECK(checkpoint_vmgenid_decode("1:00", &d) == EINVAL);
	for (size_t i = 0; i < nitems(edits); i++) {
		strlcpy(bad, text, sizeof(bad));
		bad[edits[i].at] = edits[i].c;
		CHECK(checkpoint_vmgenid_decode(bad, &d) == EINVAL);
	}
	/* Plan guards. */
	CHECK(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_MIGRATE, NULL, NULL, NULL,
	    next, &notify) == EINVAL);
	CHECK(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_MIGRATE, NULL, cur, NULL,
	    NULL, &notify) == EINVAL);
	CHECK(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_MIGRATE, NULL, cur, NULL,
	    next, NULL) == EINVAL);
	CHECK(checkpoint_vmgenid_plan(CHECKPOINT_VMGENID_RESTORE, NULL, cur, NULL,
	    next, &notify) == EINVAL);
	CHECK(checkpoint_vmgenid_plan((enum checkpoint_vmgenid_restore)7, NULL,
	    cur, NULL, next, &notify) == EINVAL);
	printf("vmgenid codec: canonical text, %zu malformed forms refused\n",
	    nitems(edits) + 1);
}

/* ------------------------------------------- generic device memory */
static int checks_devmem;

static void
devmem_regions(struct bhyve_devmem_region *r, uint8_t *a, uint8_t *b, uint8_t *c)
{
	memset(r, 0, 3 * sizeof(*r));
	strlcpy(r[0].name, "zeta", sizeof(r[0].name));
	r[0].host_base = a;
	r[0].length = 300;
	strlcpy(r[1].name, "alpha", sizeof(r[1].name));
	r[1].host_base = b;
	r[1].length = 5000;
	strlcpy(r[2].name, "mid", sizeof(r[2].name));
	r[2].host_base = c;
	r[2].length = 1;
}

static int
devmem_file(off_t normal)
{
	char path[] = "devmem.XXXXXX";
	int fd = mkstemp(path);
	uint8_t zero[4096] = { 0 };

	CHECK(fd >= 0 && unlink(path) == 0);
	for (off_t o = 0; o < normal; o += 4096)
		CHECK(__real_write(fd, zero, 4096) == 4096);
	return (fd);
}

/* Generic device memory extension: all-or-nothing restore of exactly the
 * saved bytes; every corruption of the extension is refused by both the
 * validator and the restorer with destination memory untouched. */
static void
test_devmem_extension(void)
{
	static uint8_t src[3][5000], dst[3][5000], ext[8192];
	struct bhyve_devmem_region sr[3], dr[3], shuffled[3];
	off_t normal = 8192;
	size_t extsize;
	int fd = devmem_file(normal), n = 0, refused = 0;

	for (int r = 0; r < 3; r++)
		for (int i = 0; i < 5000; i++)
			src[r][i] = (uint8_t)(r * 77 + i * 13);
	devmem_regions(sr, src[0], src[1], src[2]);
	CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &extsize) == 0);
	CHECK(extsize == 32 + 3 * 40 + 300 + 5000 + 1);
	/* The destination lists the regions in another order. */
	memset(dst, 0xee, sizeof(dst));
	devmem_regions(dr, dst[0], dst[1], dst[2]);
	shuffled[0] = dr[2]; shuffled[1] = dr[0]; shuffled[2] = dr[1];
	CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, shuffled, 3) == 0);
	CHECK(bhyve_devmem_snapshot_restore(fd, normal, normal + (off_t)extsize, shuffled, 3) == 0);
	CHECK(memcmp(dst[0], src[0], 300) == 0 && memcmp(dst[1], src[1], 5000) == 0 &&
	    dst[2][0] == src[2][0]);
	checks_devmem += 2;
	CHECK(pread(fd, ext, extsize, normal) == (ssize_t)extsize);
	/* Every byte of the extension, two substitutions each. */
	for (size_t off = 0; off < extsize; off++) {
		for (int v = 0; v < 2; v++) {
			uint8_t saved = ext[off], value = v == 0 ? (uint8_t)(saved ^ 1) : 0xff;
			int rv, rr;
			if (value == saved)
				continue;
			CHECK(pwrite(fd, &value, 1, normal + (off_t)off) == 1);
			memset(dst, 0xee, sizeof(dst));
			rv = bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, dr, 3);
			rr = bhyve_devmem_snapshot_restore(fd, normal, normal + (off_t)extsize, dr, 3);
			CHECK((rv == 0) == (rr == 0));
			if (rr != 0) {
				refused++;
				for (int r = 0; r < 3; r++)
					for (int i = 0; i < 5000; i++)
						CHECK(dst[r][i] == 0xee);
			} else {
				/* Only bytes no rule covers may change. */
				CHECK(memcmp(dst[0], src[0], 300) == 0 &&
				    memcmp(dst[1], src[1], 5000) == 0 && dst[2][0] == src[2][0]);
			}
			CHECK(pwrite(fd, &saved, 1, normal + (off_t)off) == 1);
			n++;
		}
	}
	/* Truncations and extensions of the file. */
	for (size_t cut = 0; cut < extsize; cut += 7) {
		int r = bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)cut, dr, 3);
		CHECK(r == (cut == 0 ? ENOENT : EPROTO));
		checks_devmem++;
	}
	/* Every single-byte corruption of the extension is refused. */
	CHECK(refused == n);
	CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize + 1, dr, 3) != 0);
	/* Region sets that do not match the image. */
	{
		struct bhyve_devmem_region two[2] = { dr[0], dr[1] }, four[4] = { dr[0], dr[1], dr[2] };
		static uint8_t extra[16];
		strlcpy(four[3].name, "omega", sizeof(four[3].name));
		four[3].host_base = extra;
		four[3].length = 16;
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, two, 2) == EPROTO);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, four, 4) == EPROTO);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, NULL, 0) == EPROTO);
		struct bhyve_devmem_region renamed[3] = { dr[0], dr[1], dr[2] };
		strlcpy(renamed[2].name, "mud", sizeof(renamed[2].name));
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, renamed, 3) == EPROTO);
		struct bhyve_devmem_region resized[3] = { dr[0], dr[1], dr[2] };
		resized[0].length = 299;
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, resized, 3) == EPROTO);
		/* No extension: only an empty region set matches. */
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal, NULL, 0) == 0);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal, dr, 3) == ENOENT);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + 16, dr, 3) == EPROTO);
		CHECK(bhyve_devmem_snapshot_validate(-1, normal, normal, NULL, 0) == EINVAL);
		CHECK(bhyve_devmem_snapshot_validate(fd, -1, normal, NULL, 0) == EINVAL);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal - 1, NULL, 0) == EINVAL);
		checks_devmem += 12;
	}
	/* Region descriptions are validated before any I/O. */
	{
		struct bhyve_devmem_region bad[3];
		size_t sz;
		static uint8_t overlap[64];
		for (int k = 0; k < 8; k++) {
			devmem_regions(bad, src[0], src[1], src[2]);
			int want = EINVAL;
			switch (k) {
			case 0: bad[1].host_base = NULL; break;
			case 1: bad[1].length = 0; break;
			case 2: bad[1].name[0] = '\0'; break;
			case 3: memset(bad[1].name, 'x', sizeof(bad[1].name)); break;
			case 4: strlcpy(bad[2].name, "zeta", sizeof(bad[2].name)); want = EEXIST; break;
			case 5: bad[2].host_base = src[1] + 10; break;	/* overlaps alpha */
			case 6: bad[0].host_base = (void *)bad; bad[0].length = 8; break;
			case 7: bad[0].host_base = overlap; bad[1].host_base = overlap + 63;
				bad[1].length = 2; break;
			}
			CHECK(bhyve_devmem_snapshot_save(fd, normal, bad, 3, &sz) == want && sz == 0);
			CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, bad, 3) ==
			    want);
			checks_devmem += 2;
		}
		CHECK(bhyve_devmem_snapshot_save(fd, normal, NULL, 2, &sz) == EINVAL);
		CHECK(bhyve_devmem_snapshot_save(-1, normal, sr, 3, &sz) == EINVAL);
		CHECK(bhyve_devmem_snapshot_save(fd, -1, sr, 3, &sz) == EINVAL);
		CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, NULL) == EINVAL);
		CHECK(bhyve_devmem_snapshot_save(fd, normal, NULL, 0, &sz) == 0 && sz == 0);
		CHECK(bhyve_devmem_snapshot_save(fd, INT64_MAX, sr, 3, &sz) == EOVERFLOW);
		checks_devmem += 6;
	}
	/* I/O and allocation failures. */
	{
		static const char *names[] = { "pwrite", "pread", "malloc", "calloc" };
		for (size_t f = 0; f < nitems(names); f++) {
			for (int occ = 1; occ <= 8; occ++) {
				size_t sz = 0;
				int r1, r2, r3;
				reset_points();
				strlcpy(fault_name, names[f], sizeof(fault_name));
				fault_occurrence = occ;
				fault_error = EIO;
				armed = true;
				r1 = bhyve_devmem_snapshot_save(fd, normal, sr, 3, &sz);
				armed = false;
				/* Repair the image for the load checks. */
				CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &sz) == 0);
				memset(dst, 0xee, sizeof(dst));
				reset_points();
				armed = true;
				r2 = bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, dr, 3);
				reset_points();
				r3 = bhyve_devmem_snapshot_restore(fd, normal, normal + (off_t)extsize, dr, 3);
				armed = false;
				if (r3 != 0)
					CHECK(dst[1][0] == 0xee);
				else
					CHECK(memcmp(dst[1], src[1], 5000) == 0);
				(void)r1;
				(void)r2;
				checks_devmem++;
			}
		}
	}
	close(fd);
	printf("snapshot devmem extension: %d mutations (%d refused), %d other checks\n",
	    n, refused, checks_devmem);
}

/* Device-state buffer helpers used by every device codec. */
static void
test_buffer_helpers(void)
{
	uint8_t buf[64];
	struct vm_snapshot_meta save = {
		.buffer = { .buf_start = buf, .buf_size = sizeof(buf), .buf = buf, .buf_rem = sizeof(buf) },
		.op = VM_SNAPSHOT_SAVE,
	};
	uint16_t v16 = 0xbeef, r16 = 0;
	uint32_t v32 = 0xcafef00d, r32 = 0;
	uint64_t v64 = 0x0123456789abcdefULL, r64 = 0;
	uint8_t v8 = 0x5a, r8 = 0;
	int nonneg = 12345, rn = 0, negative = -1;
	void *gptr;

	vm_init(&src_vm, "src", 1);
	CHECK(vm_snapshot_le16(&v16, &save) == 0 && buf[0] == 0xef && buf[1] == 0xbe);
	CHECK(vm_snapshot_le32(&v32, &save) == 0 && buf[2] == 0x0d && buf[5] == 0xca);
	CHECK(vm_snapshot_le64(&v64, &save) == 0 && buf[6] == 0xef && buf[13] == 0x01);
	CHECK(vm_snapshot_u8(&v8, &save) == 0 && buf[14] == 0x5a);
	CHECK(vm_snapshot_nonnegative_int(&nonneg, &save) == 0);
	CHECK(vm_snapshot_nonnegative_int(&negative, &save) == EINVAL);
	gptr = src_vm.base + 0x1000;
	CHECK(vm_snapshot_guest2host_addr(&src_vm, &gptr, 16, false, &save) == 0);
	gptr = NULL;
	CHECK(vm_snapshot_guest2host_addr(&src_vm, &gptr, 16, true, &save) == 0);
	{
		void *outside = (void *)&save;
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &outside, 16, false, &save) == EFAULT);
		outside = (void *)&save;
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &outside, 16, true, &save) == EFAULT);
	}
	CHECK(vm_snapshot_buf_cmp(&v32, 4, &save) == 0);
	CHECK(vm_get_snapshot_size(&save) == 15 + 4 + 8 + 8 + 4);
	{
		size_t used = vm_get_snapshot_size(&save);
		struct vm_snapshot_meta load = {
			.buffer = { .buf_start = buf, .buf_size = used, .buf = buf, .buf_rem = used },
			.op = VM_SNAPSHOT_RESTORE,
		};
		void *restored = NULL, *null_restored = (void *)1;
		CHECK(vm_snapshot_le16(&r16, &load) == 0 && r16 == v16);
		CHECK(vm_snapshot_le32(&r32, &load) == 0 && r32 == v32);
		CHECK(vm_snapshot_le64(&r64, &load) == 0 && r64 == v64);
		CHECK(vm_snapshot_u8(&r8, &load) == 0 && r8 == v8);
		CHECK(vm_snapshot_nonnegative_int(&rn, &load) == 0 && rn == nonneg);
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &restored, 16, false, &load) == 0 &&
		    restored == src_vm.base + 0x1000);
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &null_restored, 16, true, &load) == 0 &&
		    null_restored == NULL);
		CHECK(vm_snapshot_buf_cmp(&v32, 4, &load) == 0);
		CHECK(vm_snapshot_buf_cmp(&v32, 4, &load) == E2BIG);	/* exhausted */
		CHECK(vm_get_snapshot_size(&load) == used);
		CHECK(vm_snapshot_le16(&r16, &load) == E2BIG);
	}
	{
		/* Loaded values outside the int range, unmapped guest addresses
		 * and NULL where not permitted are refused. */
		uint8_t raw[8];
		struct vm_snapshot_meta load = {
			.buffer = { .buf_start = raw, .buf_size = 8, .buf = raw, .buf_rem = 8 },
			.op = VM_SNAPSHOT_VALIDATE,
		};
		memset(raw, 0xff, 8);
		CHECK(vm_snapshot_nonnegative_int(&rn, &load) == EINVAL);
		struct vm_snapshot_meta g = {
			.buffer = { .buf_start = raw, .buf_size = 8, .buf = raw, .buf_rem = 8 },
			.op = VM_SNAPSHOT_RESTORE,
		};
		void *p = NULL;
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &p, 16, false, &g) == EFAULT);
		uint64_t far = 0x7fffffff;
		memcpy(raw, &far, 8);
		struct vm_snapshot_meta h = {
			.buffer = { .buf_start = raw, .buf_size = 8, .buf = raw, .buf_rem = 8 },
			.op = VM_SNAPSHOT_RESTORE,
		};
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &p, 16, false, &h) == EFAULT);
		struct vm_snapshot_meta bad = {
			.buffer = { .buf_start = raw, .buf_size = 8, .buf = raw, .buf_rem = 8 },
			.op = 7,
		};
		CHECK(vm_snapshot_buf(raw, 1, &bad) == EINVAL);
		CHECK(vm_snapshot_buf_cmp(raw, 1, &bad) == EINVAL);
		CHECK(vm_snapshot_guest2host_addr(&src_vm, &p, 16, false, &bad) == EINVAL);
		vm_snapshot_buf_err("x", VM_SNAPSHOT_SAVE);
		vm_snapshot_buf_err("x", VM_SNAPSHOT_RESTORE);
		vm_snapshot_buf_err("x", VM_SNAPSHOT_VALIDATE);
		vm_snapshot_buf_err("x", 7);
		struct vm_snapshot_meta broken = {
			.buffer = { .buf_start = raw, .buf_size = 4, .buf = raw, .buf_rem = 8 },
			.op = VM_SNAPSHOT_SAVE,
		};
		CHECK(vm_get_snapshot_size(&broken) == 0);
	}
	printf("snapshot buffer helpers: all checks\n");
}

/* --------------------------------------------- progress and vCPU fence */
#include <termios.h>
#include <stdatomic.h>
#include <libutil.h>

static char progress_out[1 << 16];

/* Run print_progress with stdout redirected to a pipe. */
static const char *
progress(size_t done, size_t total, unsigned short cols)
{
	int pfd[2], saved;
	ssize_t n;

	CHECK(pipe(pfd) == 0);
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	CHECK(dup2(pfd[1], STDOUT_FILENO) == STDOUT_FILENO);
	winsize.ws_col = cols;
	CHECK(print_progress(done, total) == 0);
	fflush(stdout);
	CHECK(dup2(saved, STDOUT_FILENO) == STDOUT_FILENO);
	close(saved);
	close(pfd[1]);
	n = __real_read(pfd[0], progress_out, sizeof(progress_out) - 1);
	close(pfd[0]);
	progress_out[n < 0 ? 0 : n] = '\0';
	return (progress_out);
}

static int
count_char(const char *s, char c)
{
	int n = 0;

	for (; *s != '\0'; s++)
		n += *s == c;
	return (n);
}

static void
test_progress(void)
{
	const char *out;

	out = progress(0, 0, 80);
	CHECK(strcmp(out, "[0B / 0B]\r\n") == 0);
	/* Units by total size; the bar spans the window: done fraction as '#',
	 * a progress mark, '_' for the rest, '|' at the last column. */
	out = progress(5UL << 20, 20UL << 20, 60);
	CHECK(strncmp(out, "\r[ 5.000MiB / 20.000MiB] |", 26) == 0 && out[58] == '|' &&
	    count_char(out, '#') == (60 - 26 - 2) / 4 && strchr(out, '_') != NULL);
	out = progress(30UL << 30, 30UL << 30, 60);
	CHECK(strncmp(out, "\r[30.000GiB / 30.000GiB] |", 26) == 0 && out[58] == '|' &&
	    strchr(out, '_') == NULL && count_char(out, '#') == 60 - 26 - 2);
	out = progress(50UL << 30, 30UL << 30, 60);	/* clamped */
	CHECK(strncmp(out, "\r[30.000GiB / 30.000GiB] |", 26) == 0);
	out = progress(1024, 4096, 60);
	CHECK(strncmp(out, "\r[1.000KiB / 4.000KiB] |", 24) == 0);
	/* The progress mark advances through / - \\ |. */
	{
		char marks[4];
		for (int i = 0; i < 4; i++) {
			out = progress(1, 4096, 40);
			marks[i] = out[24];
		}
		CHECK(marks[0] != marks[1] && marks[1] != marks[2] && marks[2] != marks[3]);
	}
	/* Regression: after a wider window the bar ends at the new last
	 * column; the static buffer's older, longer bar used to leave its next
	 * character in the output. */
	out = progress(4096, 4096, 70);
	CHECK(strlen(out) == 69 && out[68] == '|');
	out = progress(1024, 4096, 40);
	/* 14 bar columns at 1/4: 3 '#', the mark, 10 '_'. */
	CHECK(strlen(out) == 39 && out[38] == '|' && count_char(out, '#') == 3 &&
	    strchr("/-\\|", out[27]) != NULL && count_char(out, '_') == 10);
	/* Too narrow for a bar: only the counters. */
	out = progress(1024, 4096, 2);
	CHECK(strncmp(out, "\r[", 2) == 0 && strchr(out, '#') == NULL);
	/* A failing write disables the indicator. */
	{
		int saved = dup(STDOUT_FILENO), devnull = __real_open("/dev/null", O_RDONLY);
		fflush(stdout);
		dup2(devnull, STDOUT_FILENO);
		winsize.ws_col = 60;
		int r = print_progress(1, 2);
		dup2(saved, STDOUT_FILENO);
		close(saved);
		close(devnull);
		CHECK(r == -1);
	}
	/* Window-size changes are read on SIGWINCH. */
	winch_handler(SIGWINCH);
	/* A checkpoint and restore on a terminal draw the bar. */
	{
		int master, slave, status;
		pid_t child;
		struct winsize ws = { .ws_col = 70, .ws_row = 24 };
		CHECK(openpty(&master, &slave, NULL, NULL, &ws) == 0);
		fflush(stdout);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			close(master);
			dup2(slave, STDOUT_FILENO);
			fresh_dir();
			vm_init(&src_vm, "src", 0x2a);
			devices_init();
			CHECK(vm_checkpoint(&src_vm, dirfd_, "tty.ckp", false) == 0);
			CHECK(restore_into_destination("tty.ckp", true) == 0);
			fflush(stdout);
			exit(0);
		}
		close(slave);
		{
			char buf[4096];
			size_t got = 0;
			ssize_t n;
			while ((n = __real_read(master, buf + got, sizeof(buf) - 1 - got)) > 0 &&
			    got + (size_t)n < sizeof(buf) - 1)
				got += (size_t)n;
			buf[got] = '\0';
			CHECK(strstr(buf, "[3072.000KiB / 3072.000KiB] |") != NULL);
		}
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 0);
		close(master);
	}
	printf("snapshot progress indicator: all checks\n");
}

/* The vCPU checkpoint fence: pause waits until every active vCPU reports
 * idle; a vCPU added during a checkpoint is held; resume releases all. */
static atomic_int fence_progress[4];
static atomic_bool fence_stop;

static void *
fence_vcpu(void *arg)
{
	int id = (int)(intptr_t)arg;

	checkpoint_cpu_add(id);
	while (!atomic_load(&fence_stop)) {
		atomic_fetch_add(&fence_progress[id], 1);
		usleep(200);
		/* A debug exit: report idle, wait for resume. */
		if (src_vm.suspended) {
			checkpoint_cpu_suspend(id);
			checkpoint_cpu_resume(id);
		}
	}
	return (NULL);
}

static void
test_vcpu_fence(void)
{
	pthread_t threads[3];
	int frozen[3];

	vm_init(&src_vm, "src", 3);
	checkpoint_active = false;
	CPU_ZERO(&vcpus_active);
	CPU_ZERO(&vcpus_suspended);
	for (int i = 0; i < 2; i++)
		CHECK(pthread_create(&threads[i], NULL, fence_vcpu, (void *)(intptr_t)i) == 0);
	usleep(20000);
	{
		bool runnable = true, owned = false;
		CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, &owned) == 0);
		CHECK(owned && !runnable);
	}
	CHECK(checkpoint_active && CPU_CMP(&vcpus_active, &vcpus_suspended) == 0);
	/* A vCPU created during the checkpoint is held before it runs. */
	CHECK(pthread_create(&threads[2], NULL, fence_vcpu, (void *)(intptr_t)2) == 0);
	usleep(20000);
	for (int i = 0; i < 3; i++)
		frozen[i] = atomic_load(&fence_progress[i]);
	usleep(20000);
	for (int i = 0; i < 3; i++)
		CHECK(atomic_load(&fence_progress[i]) == frozen[i]);
	CHECK(frozen[2] == 0);
	src_vm.suspended = false;
	CHECK(checkpoint_vcpu_resume(&src_vm) == 0 && !checkpoint_active);
	/* Every vCPU runs again (bounded wait: the host may be loaded). */
	for (int i = 0; i < 3; i++) {
		for (int t = 0; t < 5000 && atomic_load(&fence_progress[i]) <= frozen[i]; t++)
			usleep(1000);
		CHECK(atomic_load(&fence_progress[i]) > frozen[i]);
	}
	atomic_store(&fence_stop, true);
	for (int i = 0; i < 3; i++)
		CHECK(pthread_join(threads[i], NULL) == 0);
	/* The restore startup fence holds a vCPU added before release. */
	atomic_store(&fence_stop, false);
	memset(fence_progress, 0, sizeof(fence_progress));
	CPU_ZERO(&vcpus_active);
	CPU_ZERO(&vcpus_suspended);
	checkpoint_restore_startup_hold();
	CHECK(checkpoint_restore_startup_held());
	CHECK(pthread_create(&threads[0], NULL, fence_vcpu, (void *)(intptr_t)0) == 0);
	usleep(20000);
	CHECK(atomic_load(&fence_progress[0]) == 0);
	CHECK(checkpoint_restore_startup_release() == 0);
	CHECK(checkpoint_restore_startup_release() == EINVAL);
	for (int t = 0; t < 5000 && atomic_load(&fence_progress[0]) == 0; t++)
		usleep(1000);
	CHECK(atomic_load(&fence_progress[0]) > 0);
	atomic_store(&fence_stop, true);
	CHECK(pthread_join(threads[0], NULL) == 0);
	CPU_ZERO(&vcpus_active);
	CPU_ZERO(&vcpus_suspended);
	printf("snapshot vCPU checkpoint fence: all checks\n");
}

/* ------------------------------------- checkpoint codecs and validators */
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static uint64_t
rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return (rng_state);
}

/* NUMA text codec: random round trips; any accepted text is exactly the
 * canonical encoding of what it decodes to; refused input leaves outputs
 * untouched. */
static void
test_numa_codec(void)
{
	int trips = 0, mutated = 0, accepted = 0;

	for (int t = 0; t < 300; t++) {
		size_t domains = 1 + rnd() % CHECKPOINT_NUMA_MAX_DOMAINS;
		size_t vcpus = domains + rnd() % 40;
		uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS], total = 0, out_sizes[8];
		uint16_t map[64], out_map[64];
		size_t out_count;
		char *st, *mt;

		for (size_t d = 0; d < domains; d++) {
			sizes[d] = 1 + ((rnd() >> 8) >> (rnd() % 50));
			total += sizes[d];
		}
		for (size_t v = 0; v < vcpus; v++)
			map[v] = (uint16_t)(v < domains ? v : rnd() % domains);
		CHECK(checkpoint_numa_encode(sizes, domains, map, vcpus, &st, &mt) == 0);
		CHECK(checkpoint_numa_decode(st, mt, vcpus, total, out_sizes, &out_count,
		    out_map) == 0 && out_count == domains &&
		    memcmp(out_sizes, sizes, domains * 8) == 0 &&
		    memcmp(out_map, map, vcpus * 2) == 0);
		trips++;
		if (t < 30) {
			static const char subst[] = { '0', 'f', 'g', 'A', ',', '\0' };
			char *texts[2] = { st, mt };
			for (int which = 0; which < 2; which++) {
				size_t len = strlen(texts[which]);
				for (size_t i = 0; i < len; i++) {
					for (size_t k = 0; k < sizeof(subst); k++) {
						char saved = texts[which][i];
						if (saved == subst[k])
							continue;
						texts[which][i] = subst[k];
						memset(out_sizes, 0xa5, sizeof(out_sizes));
						memset(out_map, 0xa5, sizeof(out_map));
						out_count = 777;
						int r = checkpoint_numa_decode(st, mt, vcpus, total,
						    out_sizes, &out_count, out_map);
						if (r == 0) {
							char *s2, *m2;
							accepted++;
							CHECK(checkpoint_numa_encode(out_sizes, out_count,
							    out_map, vcpus, &s2, &m2) == 0 &&
							    strcmp(s2, st) == 0 && strcmp(m2, mt) == 0);
							free(s2);
							free(m2);
						} else {
							CHECK(out_count == 777 && out_map[0] == 0xa5a5);
						}
						texts[which][i] = saved;
						mutated++;
					}
				}
			}
		}
		free(st);
		free(mt);
	}
	/* Argument and rule refusals. */
	{
		uint64_t sizes[2] = { 4096, 4096 }, os[8];
		uint16_t map[3] = { 0, 1, 1 }, om[3];
		size_t oc;
		char *st, *mt;
		CHECK(checkpoint_numa_encode(NULL, 2, map, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 0, map, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 9, map, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, NULL, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, map, 0, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, map, 70000, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, map, 3, NULL, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, map, 3, &st, NULL) == EINVAL);
		uint64_t zero[2] = { 4096, 0 }, big[2] = { UINT64_MAX, 1 };
		CHECK(checkpoint_numa_encode(zero, 2, map, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(big, 2, map, 3, &st, &mt) == EINVAL);
		uint16_t unpopulated[3] = { 0, 0, 0 };
		CHECK(checkpoint_numa_encode(sizes, 2, unpopulated, 3, &st, &mt) == EINVAL);
		CHECK(checkpoint_numa_encode(sizes, 2, map, 3, &st, &mt) == 0);
		CHECK(checkpoint_numa_decode(st, mt, 3, 8192, NULL, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 3, 8192, os, NULL, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 3, 8192, os, &oc, NULL) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 0, 8192, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 70000, 8192, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 3, 0, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 2, 8192, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 4, 8192, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode(st, mt, 3, 8193, os, &oc, om) == ERANGE);
		CHECK(checkpoint_numa_decode(NULL, mt, 3, 8192, os, &oc, om) == EINVAL);
		CHECK(checkpoint_numa_decode("", mt, 3, 8192, os, &oc, om) == EINVAL);
		free(st);
		free(mt);
		/* A ninth domain does not fit the table. */
		char nine[9 * 17];
		for (int i = 0; i < 9; i++)
			snprintf(nine + i * 17, sizeof(nine) - i * 17, "%016x%s", 1, i == 8 ? "" : ",");
		CHECK(checkpoint_numa_decode(nine, "0000", 1, 9, os, &oc, om) == EINVAL);
		/* Mapping domain values above 16 bits cannot be expressed in 4
		 * digits; an out-of-range domain index is refused. */
		CHECK(checkpoint_numa_decode("0000000000001000", "0001", 1, 4096, os, &oc, om) == EINVAL);
	}
	printf("snapshot NUMA codec: %d round trips, %d mutations (%d canonical accepts)\n",
	    trips, mutated, accepted);
}

static void
random_contract(struct checkpoint_cpu_contract *c, size_t records)
{
	memset(c, 0, sizeof(*c));
	c->version = CHECKPOINT_CPU_CONTRACT_VERSION;
	c->architecture = CHECKPOINT_CPU_ARCH_AMD64 + (uint32_t)(rnd() % 3);
	c->record_count = records;
	uint32_t selector = (uint32_t)(rnd() % 4);
	for (size_t i = 0; i < records; i++) {
		if (i != 0 && rnd() % 2 == 0)
			selector += 1 + (uint32_t)(rnd() % 3);
		c->records[i].selector = selector;
		c->records[i].parameter = (i != 0 && c->records[i - 1].selector == selector) ?
		    c->records[i - 1].parameter + 1 : 0;
		for (int v = 0; v < 4; v++)
			c->records[i].values[v] = (uint32_t)rnd();
	}
}

static void
test_cpu_contract_codec(void)
{
	struct checkpoint_cpu_contract c, d, e;
	char *text;
	int mutated = 0, accepted = 0;

	for (int t = 0; t < 200; t++) {
		random_contract(&c, 1 + rnd() % CHECKPOINT_CPU_MAX_RECORDS);
		CHECK(checkpoint_cpu_contract_encode(&c, &text) == 0);
		CHECK(checkpoint_cpu_contract_decode(text, &d) == 0 &&
		    checkpoint_cpu_contract_match(&c, &d) == 0);
		if (t < 6) {
			size_t len = strlen(text);
			for (size_t i = 0; i < len && i < 200; i++) {
				static const char subst[] = { '0', '1', 'f', 'g', 'F', '\0' };
				for (size_t k = 0; k < sizeof(subst); k++) {
					char saved = text[i];
					if (saved == subst[k])
						continue;
					text[i] = subst[k];
					memset(&e, 0xa5, sizeof(e));
					if (checkpoint_cpu_contract_decode(text, &e) == 0) {
						char *again;
						accepted++;
						CHECK(checkpoint_cpu_contract_encode(&e, &again) == 0 &&
						    strcmp(again, text) == 0);
						free(again);
					} else {
						CHECK(e.version == 0xa5a5a5a5U);
					}
					text[i] = saved;
					mutated++;
				}
			}
		}
		free(text);
	}
	/* Validation and matching rules. */
	random_contract(&c, 4);
	CHECK(checkpoint_cpu_contract_validate(NULL) == EINVAL);
	d = c; d.version++;
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.record_count = 0;
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.record_count = CHECKPOINT_CPU_MAX_RECORDS + 1;
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.architecture = 77;
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.records[2] = d.records[1];		/* duplicate */
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.records[2].selector = d.records[1].selector - 1 + 0 * (d.records[1].selector = 5);
	d.records[2].selector = 4;
	CHECK(checkpoint_cpu_contract_validate(&d) == EINVAL);
	d = c; d.architecture = c.architecture == CHECKPOINT_CPU_ARCH_AMD64 ?
	    CHECKPOINT_CPU_ARCH_ARM64 : CHECKPOINT_CPU_ARCH_AMD64;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EXDEV);
	d = c; d.record_count = 3;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EXDEV);
	d = c; d.records[3].values[2] ^= 1;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EXDEV);
	d = c; d.records[3].parameter += 1;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EXDEV);
	d = c; d.records[3].selector += 1;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EXDEV);
	d = c; d.version++;
	CHECK(checkpoint_cpu_contract_match(&c, &d) == EINVAL);
	CHECK(checkpoint_cpu_contract_match(&d, &c) == EINVAL);
	CHECK(checkpoint_cpu_contract_encode(&c, NULL) == EINVAL);
	CHECK(checkpoint_cpu_contract_encode(&d, &text) == EINVAL);
	CHECK(checkpoint_cpu_contract_decode(NULL, &e) == EINVAL);
	CHECK(checkpoint_cpu_contract_decode("00", NULL) == EINVAL);
	CHECK(checkpoint_cpu_contract_decode("000", &e) == EINVAL);
	CHECK(checkpoint_cpu_contract_decode("00000000", &e) == EINVAL);
	{
		size_t huge = 2 * (16 + 24 * CHECKPOINT_CPU_MAX_RECORDS) + 2;
		char *long_text = malloc(huge + 1);
		memset(long_text, '0', huge);
		long_text[huge] = '\0';
		CHECK(checkpoint_cpu_contract_decode(long_text, &e) == E2BIG);
		free(long_text);
	}
	printf("snapshot CPU contract codec: 200 round trips, %d mutations (%d canonical accepts)\n",
	    mutated, accepted);
}

static void
test_compat_and_machine(void)
{
	struct pci_snapshot_compat a, b;
	uint8_t record[CHECKPOINT_COMPAT_ENVELOPE_SIZE + 8];
	int mutated = 0, accepted = 0;

	fake_compat(NULL, &a);
	a.payload_crc32 = 0x12345678;
	CHECK(checkpoint_compat_encode(&a, record, sizeof(record)) == 0);
	CHECK(checkpoint_compat_decode(record, CHECKPOINT_COMPAT_ENVELOPE_SIZE, &b) == 0 &&
	    checkpoint_compat_equal(&a, &b));
	for (size_t i = 0; i < CHECKPOINT_COMPAT_ENVELOPE_SIZE; i++) {
		static const uint8_t subst[] = { 0x00, 0x01, 0x2c, 0xff };
		for (size_t k = 0; k < sizeof(subst); k++) {
			uint8_t saved = record[i];
			if (saved == subst[k])
				continue;
			record[i] = subst[k];
			memset(&b, 0xa5, sizeof(b));
			if (checkpoint_compat_decode(record, CHECKPOINT_COMPAT_ENVELOPE_SIZE, &b) == 0) {
				uint8_t again[CHECKPOINT_COMPAT_ENVELOPE_SIZE];
				accepted++;
				CHECK(checkpoint_compat_encode(&b, again, sizeof(again)) == 0 &&
				    memcmp(again, record, sizeof(again)) == 0);
			} else {
				CHECK(b.schema == 0xa5a5a5a5U);
			}
			record[i] = saved;
			mutated++;
		}
	}
	CHECK(checkpoint_compat_encode(NULL, record, sizeof(record)) == EINVAL);
	CHECK(checkpoint_compat_encode(&a, NULL, sizeof(record)) == EINVAL);
	CHECK(checkpoint_compat_encode(&a, record, 10) == EINVAL);
	b = a; b.schema++;
	CHECK(checkpoint_compat_encode(&b, record, sizeof(record)) == EINVAL && !checkpoint_compat_equal(&a, &b));
	b = a; b.negotiated_features |= 1ULL << 63;
	CHECK(checkpoint_compat_encode(&b, record, sizeof(record)) == EINVAL);
	b = a; memset(b.queue_sizes, 'x', sizeof(b.queue_sizes));
	CHECK(checkpoint_compat_encode(&b, record, sizeof(record)) == EINVAL && !checkpoint_compat_equal(&a, &b) &&
	    !checkpoint_compat_equal(&b, &a));
	b = a; b.queue_sizes[sizeof(b.queue_sizes) - 1] = 'x';
	CHECK(checkpoint_compat_encode(&b, record, sizeof(record)) == EINVAL);
	b = a; b.shared_memory[sizeof(b.shared_memory) - 1] = 'x';
	CHECK(checkpoint_compat_encode(&b, record, sizeof(record)) == EINVAL &&
	    !checkpoint_compat_equal(&a, &b) && !checkpoint_compat_equal(&b, &a));
	CHECK(checkpoint_compat_decode(NULL, sizeof(record), &b) == EINVAL);
	CHECK(checkpoint_compat_decode(record, 10, &b) == EINVAL);
	CHECK(checkpoint_compat_decode(record, sizeof(record), NULL) == EINVAL);
	CHECK(!checkpoint_compat_equal(NULL, &a) && !checkpoint_compat_equal(&a, NULL));
	/* Each scalar participates in equality. */
	for (int f = 0; f < 9; f++) {
		b = a;
		switch (f) {
		case 0: b.transport++; break;
		case 1: b.queue_count++; break;
		case 2: b.msix_table_count++; break;
		case 3: b.config_size++; break;
		case 4: b.offered_features ^= 1ULL << 40; break;
		case 5: b.negotiated_features ^= 0x10; break;
		case 6: b.payload_crc32++; break;
		case 7: b.queue_sizes[0] ^= 1; break;
		case 8: b.shared_memory[0] = 'x'; break;
		}
		CHECK(!checkpoint_compat_equal(&a, &b));
	}
	CHECK(checkpoint_compat_payload_crc32(NULL, 0) == 0 &&
	    checkpoint_compat_payload_crc32(NULL, 5) == 0 &&
	    checkpoint_compat_payload_crc32("123456789", 9) == 0xcbf43926U);
	/* Machine topology digest: canonical hex, independent of device
	 * order, sensitive to every hashed field, insensitive to negotiated
	 * features and payload checksums. */
	{
		struct pci_snapshot_compat c1 = a, c2 = a;
		struct checkpoint_machine_device devs[3] = {
			{ "virtio-net", &c1 }, { "ahci", NULL }, { "virtio-blk", &c2 } };
		struct checkpoint_machine_device perm[3] = { devs[2], devs[0], devs[1] };
		char d1[CHECKPOINT_MACHINE_DIGEST_LENGTH], d2[CHECKPOINT_MACHINE_DIGEST_LENGTH];
		CHECK(checkpoint_machine_topology_digest(devs, 3, d1, sizeof(d1)) == 0 &&
		    checkpoint_machine_digest_canonical(d1));
		CHECK(checkpoint_machine_topology_digest(perm, 3, d2, sizeof(d2)) == 0 &&
		    strcmp(d1, d2) == 0);
		c2.negotiated_features = 0;
		c2.payload_crc32 = 1;
		c2.offered_features = 0;
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == 0 &&
		    strcmp(d1, d2) == 0);
		for (int f = 0; f < 8; f++) {
			c2 = a;
			const char *saved = devs[1].name;
			switch (f) {
			case 0: c2.transport++; break;
			case 1: c2.queue_count++; break;
			case 2: c2.msix_table_count++; break;
			case 3: c2.config_size++; break;
			case 4: c2.queue_sizes[0] ^= 1; break;
			case 5: strlcpy(c2.shared_memory, "shm", sizeof(c2.shared_memory)); break;
			case 6: devs[1].name = "ahci2"; break;
			case 7: devs[1].compat = &c1; break;
			}
			CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == 0 &&
			    strcmp(d1, d2) != 0);
			devs[1].name = saved;
			devs[1].compat = NULL;
		}
		c2 = a;
		CHECK(checkpoint_machine_topology_digest(NULL, 0, d2, sizeof(d2)) == 0 &&
		    checkpoint_machine_digest_canonical(d2) && strcmp(d1, d2) != 0);
		CHECK(checkpoint_machine_topology_digest(NULL, 1, d2, sizeof(d2)) == EINVAL);
		CHECK(checkpoint_machine_topology_digest(devs, 3, NULL, sizeof(d2)) == EINVAL);
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, 10) == EINVAL);
		devs[1].name = "virtio-net";
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EEXIST);
		devs[1].name = "";
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
		devs[1].name = NULL;
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
		{
			char *long_name = malloc(CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 2);
			memset(long_name, 'n', CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 1);
			long_name[CHECKPOINT_MACHINE_DEVICE_NAME_MAX + 1] = '\0';
			devs[1].name = long_name;
			CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
			free(long_name);
		}
		devs[1].name = "ahci";
		c2.schema++;
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
		c2 = a;
		memset(c2.queue_sizes, 'q', sizeof(c2.queue_sizes));
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
		c2 = a;
		c2.shared_memory[sizeof(c2.shared_memory) - 1] = 'z';
		CHECK(checkpoint_machine_topology_digest(devs, 3, d2, sizeof(d2)) == EINVAL);
		CHECK(!checkpoint_machine_digest_canonical(NULL));
		CHECK(!checkpoint_machine_digest_canonical("abc"));
		strlcpy(d2, d1, sizeof(d2));
		d2[5] = 'G';
		CHECK(!checkpoint_machine_digest_canonical(d2));
		d2[5] = 'A';
		CHECK(!checkpoint_machine_digest_canonical(d2));
	}
	printf("snapshot compat envelope and machine digest: %d mutations (%d canonical accepts)\n",
	    mutated, accepted);
}

static void
test_topology_rules(void)
{
	const char *src[] = { "a", "b", "c" }, *perm[] = { "c", "a", "b" };
	const char *dup[] = { "a", "a", "c" }, *empty[] = { "a", "", "c" }, *other[] = { "a", "b", "d" };
	const char *nul[] = { "a", NULL, "c" };

	CHECK(checkpoint_topology_validate(src, 3, perm, 3) == 0);
	CHECK(checkpoint_topology_validate(NULL, 0, NULL, 0) == 0);
	CHECK(checkpoint_topology_validate(NULL, 3, perm, 3) == EINVAL);
	CHECK(checkpoint_topology_validate(src, 3, NULL, 3) == EINVAL);
	CHECK(checkpoint_topology_validate(dup, 3, perm, 3) == EEXIST);
	CHECK(checkpoint_topology_validate(src, 3, dup, 3) == EEXIST);
	CHECK(checkpoint_topology_validate(empty, 3, perm, 3) == EINVAL);
	CHECK(checkpoint_topology_validate(nul, 3, perm, 3) == EINVAL);
	CHECK(checkpoint_topology_validate(src, 3, perm, 2) == ENODEV);
	CHECK(checkpoint_topology_validate(src, 3, other, 3) == ENODEV);
	CHECK(checkpoint_record_consumption_validate(10, 0) == 0);
	CHECK(checkpoint_record_consumption_validate(10, 1) == EINVAL);
	CHECK(checkpoint_record_consumption_validate(10, 11) == EINVAL);
	/* CPU topology: product rule and 16-bit bounds. */
	CHECK(checkpoint_cpu_topology_validate(8, 2, 2, 2) == 0);
	CHECK(checkpoint_cpu_topology_validate(7, 2, 2, 2) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(0, 1, 1, 1) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(65536, 65536, 1, 1) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(1, 0, 1, 1) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(1, 1, 0, 1) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(1, 1, 1, 0) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(1, 1, 65536, 1) == EINVAL);
	CHECK(checkpoint_cpu_topology_validate(1, 1, 1, 65536) == EINVAL);
	/* NUMA mapping rules. */
	{
		uint64_t s[2] = { 4096, 4096 }, z[2] = { 4096, 0 }, o[2] = { UINT64_MAX, 2 };
		uint16_t m[2] = { 0, 1 }, u[2] = { 0, 0 }, x[2] = { 0, 2 };
		CHECK(checkpoint_numa_mapping_validate(s, 2, m, 2, 8192) == 0);
		CHECK(checkpoint_numa_mapping_validate(s, 2, m, 2, 8191) == ERANGE);
		CHECK(checkpoint_numa_mapping_validate(NULL, 2, m, 2, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 0, m, 2, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 9, m, 2, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, NULL, 2, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, m, 0, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, m, 70000, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, m, 2, 0) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(z, 2, m, 2, 4096) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(o, 2, m, 2, 1) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, u, 2, 8192) == EINVAL);
		CHECK(checkpoint_numa_mapping_validate(s, 2, x, 2, 8192) == EINVAL);
	}
	/* Memory geometry rules. */
	{
		struct checkpoint_memory_geometry g = { 4096, 3UL << 30, 4UL << 30, 1UL << 30 }, h;
		uint64_t total = 4UL << 30;
		CHECK(checkpoint_memory_geometry_validate(&g, total) == 0);
		CHECK(checkpoint_memory_geometry_validate(NULL, total) == EINVAL);
		CHECK(checkpoint_memory_geometry_validate(&g, 0) == EINVAL);
		h = g; h.page_size = 0; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.page_size = 3000; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.lowmem_size += 1; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.highmem_base += 1; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.highmem_size += 1; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.lowmem_size = total + 4096; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.highmem_size = 2UL << 30; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.highmem_size = 0; CHECK(checkpoint_memory_geometry_validate(&h, total) == ERANGE);
		h = g; h.highmem_base = 2UL << 30; CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.highmem_base = UINT64_MAX - 4095;
		CHECK(checkpoint_memory_geometry_validate(&h, total) == EINVAL);
		h = g; h.lowmem_size = total; h.highmem_size = 0;
		CHECK(checkpoint_memory_geometry_validate(&h, total) == 0);
		CHECK(checkpoint_memory_geometry_match(&g, &g, total) == 0);
		CHECK(checkpoint_memory_geometry_match(&g, &h, total) == EXDEV);
		h = g; h.page_size = 8192; h.lowmem_size = 3UL << 30;
		CHECK(checkpoint_memory_geometry_match(&g, &h, total) == EXDEV);
		h = g; h.page_size = 0;
		CHECK(checkpoint_memory_geometry_match(&h, &g, total) == EINVAL);
		CHECK(checkpoint_memory_geometry_match(&g, &h, total) == EINVAL);
	}
	/* Record layout: ranges tile [0, total) exactly in any order. */
	{
		struct checkpoint_record_range r[3] = { { 30, 10 }, { 0, 10 }, { 10, 20 } }, q[3];
		CHECK(checkpoint_record_layout_validate(r, 3, 40) == 0);
		CHECK(checkpoint_record_layout_validate(NULL, 0, 0) == 0);
		CHECK(checkpoint_record_layout_validate(NULL, 0, 1) == EINVAL);
		CHECK(checkpoint_record_layout_validate(NULL, 3, 40) == EINVAL);
		CHECK(checkpoint_record_layout_validate(r, 3, 0) == EINVAL);
		CHECK(checkpoint_record_layout_validate(r, 3, 41) == EINVAL);
		memcpy(q, r, sizeof(r)); q[0].length = 0;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);
		memcpy(q, r, sizeof(r)); q[0].offset = 50;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);
		memcpy(q, r, sizeof(r)); q[0].length = 11;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);
		memcpy(q, r, sizeof(r)); q[2].offset = 12; q[2].length = 18;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);	/* gap */
		memcpy(q, r, sizeof(r)); q[2].offset = 5; q[2].length = 25;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);	/* overlap */
		memcpy(q, r, sizeof(r)); q[1].offset = 10;
		CHECK(checkpoint_record_layout_validate(q, 3, 40) == EINVAL);	/* duplicate start */
	}
	printf("snapshot topology, geometry and layout rules: all checks\n");
}

/* CPU contract capture per the CPUID enumeration rules: leaf 4 and
 * 0x8000001d subleaves until a null cache type (inclusive), leaves 0xb and
 * 0x1f until a null level (inclusive), leaf 0xd subleaf 1 plus each XCR0 bit
 * from 2 up, hypervisor leaves, then three platform records. */
static void
test_cpu_capture(void)
{
	struct checkpoint_cpu_contract c;
	size_t i = 0;

	cpuid_mode = 1;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == 0);
#define EXPECT(sel, par) do { CHECK(i < c.record_count && c.records[i].selector == (sel) && \
	c.records[i].parameter == (par)); i++; } while (0)
	EXPECT(0, 0);
	for (uint32_t leaf = 1; leaf <= 0x1f; leaf++) {
		EXPECT(leaf, 0);
		if (leaf == 4)
			for (uint32_t sub = 1; sub <= 3; sub++)
				EXPECT(4, sub);
		if (leaf == 0xb || leaf == 0x1f)
			for (uint32_t sub = 1; sub <= 2; sub++)
				EXPECT(leaf, sub);
		if (leaf == 0xd) {
			static const uint32_t bits[] = { 1, 2, 5, 6, 7, 9, 32 };
			for (size_t b = 0; b < nitems(bits); b++)
				EXPECT(0xd, bits[b]);
		}
	}
	EXPECT(0x40000000U, 0);
	EXPECT(0x40000001U, 0);
	for (uint32_t leaf = 0x80000000U; leaf <= 0x8000001dU; leaf++) {
		EXPECT(leaf, 0);
		if (leaf == 0x8000001dU)
			for (uint32_t sub = 1; sub <= 3; sub++)
				EXPECT(leaf, sub);
	}
	EXPECT(0xfffffffdU, 0);
	EXPECT(0xfffffffeU, 0);
	EXPECT(0xffffffffU, 0);
	CHECK(i == c.record_count);
#undef EXPECT
	/* Failure modes. */
	cpuid_mode = 2;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == E2BIG);
	cpuid_mode = 3;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == EPROTO);
	cpuid_mode = 4;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == E2BIG);
	cpuid_mode = 5;
	cpuid_errno = 0;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == EIO);
	cpuid_errno = ENXIO;
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) == ENXIO);
	cpuid_mode = 0;
	for (compat_mode = 1; compat_mode <= 5; compat_mode++)
		CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c) ==
		    (compat_mode == 5 ? EIO : EPROTO));
	compat_mode = 0;
	CHECK(checkpoint_cpu_contract_capture(NULL, &c) == EINVAL);
	CHECK(checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), NULL) == EINVAL);
	/* A rich capture round-trips through a checkpoint. */
	cpuid_mode = 1;
	fresh_dir();
	vm_init(&src_vm, "src", 0x3c);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "cpu.ckp", false) == 0);
	CHECK(restore_into_destination("cpu.ckp", true) == 0);
	cpuid_mode = 0;
	printf("snapshot CPU contract capture: enumeration and failure checks\n");
}

/* The kernel session ownership protocol under ambiguous copyouts: the
 * request sequence and the resolved/released verdict for every outcome. */
static void
script(const int *replies, int n)
{
	session_script = replies;
	session_script_len = n;
	session_nops = 0;
}

static void
test_session_protocol(void)
{
	struct vm_snapshot_session sess;
	bool resolved, released;
	static const struct {
		int replies[4], n;
		int error;
		bool resolved;
		int ops[4], nops;
	} begin[] = {
		{ { 0 }, 1, 0, false, { VM_SNAPSHOT_SESSION_BEGIN }, 1 },
		{ { EBUSY }, 1, EBUSY, true, { VM_SNAPSHOT_SESSION_BEGIN }, 1 },
		{ { EFAULT, 0 }, 2, EFAULT, true,
		  { VM_SNAPSHOT_SESSION_BEGIN, VM_SNAPSHOT_SESSION_ABORT_CURRENT }, 2 },
		{ { EFAULT, ESTALE }, 2, EFAULT, true,
		  { VM_SNAPSHOT_SESSION_BEGIN, VM_SNAPSHOT_SESSION_ABORT_CURRENT }, 2 },
		{ { EFAULT, EFAULT, 0 }, 3, EFAULT, true,
		  { VM_SNAPSHOT_SESSION_BEGIN, VM_SNAPSHOT_SESSION_ABORT_CURRENT,
		    VM_SNAPSHOT_SESSION_ABORT_CURRENT }, 3 },
		{ { EFAULT, EFAULT, ESTALE }, 3, EFAULT, true,
		  { VM_SNAPSHOT_SESSION_BEGIN, VM_SNAPSHOT_SESSION_ABORT_CURRENT,
		    VM_SNAPSHOT_SESSION_ABORT_CURRENT }, 3 },
		{ { EFAULT, EFAULT, EFAULT }, 3, EFAULT, false,
		  { VM_SNAPSHOT_SESSION_BEGIN, VM_SNAPSHOT_SESSION_ABORT_CURRENT,
		    VM_SNAPSHOT_SESSION_ABORT_CURRENT }, 3 },
	};
	static const struct {
		bool committing;
		int replies[4], n;
		int error;
		bool released;
		int nops;
	} release[] = {
		{ true, { 0 }, 1, 0, true, 1 },
		{ false, { 0 }, 1, 0, true, 1 },
		{ true, { EFAULT, 0 }, 2, EFAULT, true, 2 },
		{ true, { EIO, ESTALE }, 2, EIO, true, 2 },
		{ true, { EFAULT, EFAULT, 0 }, 3, EFAULT, true, 3 },
		{ true, { EFAULT, EFAULT, ESTALE }, 3, EFAULT, true, 3 },
		{ true, { EFAULT, EFAULT, EFAULT }, 3, EFAULT, false, 3 },
	};

	for (size_t i = 0; i < nitems(begin); i++) {
		script(begin[i].replies, begin[i].n);
		CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, &resolved) == begin[i].error &&
		    resolved == begin[i].resolved && session_nops == begin[i].nops);
		for (int k = 0; k < session_nops; k++)
			CHECK(session_ops[k] == begin[i].ops[k]);
	}
	for (size_t i = 0; i < nitems(release); i++) {
		memset(&sess, 0, sizeof(sess));
		sess.version = VM_SNAPSHOT_SESSION_VERSION;
		sess.session_id = 9;
		script(release[i].replies, release[i].n);
		CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, release[i].committing,
		    &released) == release[i].error && released == release[i].released &&
		    session_nops == release[i].nops);
		CHECK(session_ops[0] == (release[i].committing ? VM_SNAPSHOT_SESSION_COMMIT :
		    VM_SNAPSHOT_SESSION_ABORT));
		for (int k = 1; k < session_nops; k++)
			CHECK(session_ops[k] == VM_SNAPSHOT_SESSION_ABORT);
	}
	session_script = NULL;
	CHECK(vm_snapshot_session_begin_exact(NULL, &sess, &resolved) == EINVAL && resolved);
	CHECK(vm_snapshot_session_begin_exact(&src_vm, NULL, &resolved) == EINVAL);
	CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, NULL) == EINVAL);
	memset(&sess, 0, sizeof(sess));
	sess.version = VM_SNAPSHOT_SESSION_VERSION;
	CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, true, &released) == EINVAL &&
	    !released);
	sess.session_id = 1;
	sess.version = 0;
	CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, true, &released) == EINVAL);
	sess.version = VM_SNAPSHOT_SESSION_VERSION;
	CHECK(vm_snapshot_session_release_exact(NULL, &sess, true, &released) == EINVAL);
	CHECK(vm_snapshot_session_release_exact(&src_vm, NULL, true, &released) == EINVAL);
	CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, true, NULL) == EINVAL);
	/* A checkpoint whose BEGIN ownership stays unresolved keeps the VM
	 * stopped and publishes nothing. */
	{
		static const int unresolved[] = { EFAULT, EFAULT, EFAULT };
		fresh_dir();
		vm_init(&src_vm, "src", 0x4a);
		devices_init();
		script(unresolved, 3);
		CHECK(vm_checkpoint(&src_vm, dirfd_, "u.ckp", false) == EFAULT);
		CHECK(src_vm.suspended && src_state[0].paused);
		session_script = NULL;
		checkpoint_active = false;
		static const int busy[] = { EBUSY };
		vm_init(&src_vm, "src", 0x4b);
		devices_init();
		script(busy, 1);
		CHECK(vm_checkpoint(&src_vm, dirfd_, "u.ckp", false) == EBUSY);
		CHECK(src_vm.suspended);	/* another owner: stays stopped */
		session_script = NULL;
		checkpoint_active = false;
	}
	printf("snapshot kernel session protocol: %zu begin and %zu release outcomes\n",
	    nitems(begin), nitems(release));
}

/* ------------------------------------------------ checkpoint mutation */
#include <sha256.h>

static char *
slurp(const char *name, size_t *len)
{
	char path[400];
	struct stat st;
	char *buf;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = __real_open(path, O_RDONLY);
	if (fd < 0)
		fprintf(stderr, "slurp: cannot open %s\n", path);
	CHECK(fd >= 0 && __real_fstat(fd, &st) == 0);
	buf = __real_malloc((size_t)st.st_size + 1);
	CHECK(buf != NULL && __real_read(fd, buf, (size_t)st.st_size) == st.st_size);
	buf[st.st_size] = '\0';
	close(fd);
	*len = (size_t)st.st_size;
	return (buf);
}

static void
spill(const char *name, const char *buf, size_t len)
{
	char path[400];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = __real_open(path, O_WRONLY | O_TRUNC | O_CREAT, 0600);
	if (fd < 0)
		fprintf(stderr, "spill: cannot open %s\n", path);
	CHECK(fd >= 0 && __real_write(fd, buf, len) == (ssize_t)len);
	close(fd);
}

/* Replace "<kind>_sha256=..." in the manifest with the digest of member. */
static void
rehash_named(const char *manifest_name, const char *kind, const char *member)
{
	char key[32], digest[65], *manifest, *line;
	size_t len, mlen;
	char *data = slurp(member, &mlen);

	SHA256_Data(data, mlen, digest);
	free(data);
	manifest = slurp(manifest_name, &len);
	snprintf(key, sizeof(key), "\n%s_sha256=", kind);
	line = strstr(manifest, key);
	CHECK(line != NULL);
	memcpy(line + strlen(key), digest, 64);
	spill(manifest_name, manifest, len);
	free(manifest);
}

static void
rehash(const char *kind, const char *member)
{
	rehash_named("vm.ckp", kind, member);
}

static struct checkpoint_manifest good_manifest;

/* Lookups bhyverun performs on a loaded checkpoint before creating the VM. */
static void
startup_lookups(struct restore_state *r, bool expect_valid)
{
	struct checkpoint_cpu_contract contract;
	struct checkpoint_memory_geometry geometry;
	uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t domains[2], sockets, cores, threads;
	size_t count;
	int ncpus, memflags;
	int e[8];

	e[0] = lookup_vmname(r) == NULL;
	e[1] = lookup_memflags(r, &memflags);
	e[2] = lookup_memsize(r) == 0;
	e[3] = lookup_guest_ncpus(r) == 0;
	e[4] = lookup_cpu_topology(r, &ncpus, &sockets, &cores, &threads);
	e[5] = lookup_cpu_contract(r, &contract);
	e[6] = lookup_numa_topology(r, 2, LOWMEM + HIGHMEM, sizes, &count, domains);
	e[7] = lookup_memory_geometry(r, &geometry);
	if (!expect_valid)
		return;
	for (int i = 0; i < 8; i++)
		CHECK(e[i] == 0);
	CHECK(strcmp(lookup_vmname(r), "src") == 0 && memflags == 0);
	CHECK(lookup_memsize(r) == LOWMEM + HIGHMEM && lookup_guest_ncpus(r) == 2);
	CHECK(ncpus == 2 && sockets == 1 && cores == 2 && threads == 1);
	CHECK(count == 1 && sizes[0] == LOWMEM + HIGHMEM && domains[0] == 0 && domains[1] == 0);
	CHECK(geometry.page_size == PAGE_SIZE && geometry.lowmem_size == LOWMEM &&
	    geometry.highmem_base == HIGHBASE && geometry.highmem_size == HIGHMEM);
	CHECK(lookup_memflags(NULL, &memflags) == EINVAL);
	CHECK(lookup_cpu_topology(r, NULL, &sockets, &cores, &threads) == EINVAL);
	CHECK(lookup_cpu_contract(NULL, &contract) == EINVAL);
	CHECK(lookup_numa_topology(r, 2, LOWMEM + HIGHMEM, NULL, &count, domains) == EINVAL);
	CHECK(lookup_memory_geometry(r, NULL) == EINVAL);
}

/*
 * bhyverun's destination admission (bhyverun.c, restore_file != NULL): the
 * CPU topology, memory flags and size, NUMA map, memory geometry and CPU
 * contract come from the checkpoint and must match what this destination
 * would create.  Returns 0 when bhyverun would create the VM.
 */
static int
destination_admits(struct restore_state *r)
{
	struct checkpoint_cpu_contract source_cpu, destination_cpu;
	struct checkpoint_memory_geometry source, destination;
	uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	uint16_t domains[64], sockets, cores, threads;
	size_t count, memsize;
	int ncpus, memflags, error;

	(void)lookup_vmname(r);
	if ((error = lookup_cpu_topology(r, &ncpus, &sockets, &cores, &threads)) != 0)
		return (error);
	if (lookup_memflags(r, &memflags) != 0 || (memsize = lookup_memsize(r)) == 0)
		return (EINVAL);
	if (ncpus > 64)
		return (E2BIG);
	if ((error = lookup_numa_topology(r, (size_t)ncpus, memsize, sizes,
	    &count, domains)) != 0)
		return (error);
	/* This destination creates exactly the fake VM's memory layout. */
	if (memsize != LOWMEM + HIGHMEM || count != 1)
		return (EINVAL);
	destination = (struct checkpoint_memory_geometry){ .page_size = PAGE_SIZE,
	    .lowmem_size = LOWMEM, .highmem_base = HIGHBASE, .highmem_size = HIGHMEM };
	if ((error = lookup_memory_geometry(r, &source)) != 0 ||
	    (error = checkpoint_memory_geometry_match(&source, &destination, memsize)) != 0)
		return (error);
	if ((error = lookup_cpu_contract(r, &source_cpu)) != 0 ||
	    (error = checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &destination_cpu)) != 0 ||
	    (error = checkpoint_cpu_contract_match(&source_cpu, &destination_cpu)) != 0)
		return (error);
	/* bhyverun configures the destination from the checkpoint. */
	guest_ncpus = ncpus;
	cpu_sockets = sockets;
	cpu_cores = cores;
	cpu_threads = threads;
	return (0);
}

static int startup_refusals;

static int
restore_mutated(bool *lookups_ok)
{
	struct restore_state r;
	char path[400];
	int error;

	(void)lookups_ok;
	snprintf(path, sizeof(path), "%s/vm.ckp", dir);
	if (load_restore_file(path, &r) != 0)
		return (-1);
	error = destination_admits(&r);
	destroy_restore_state(&r);
	if (error == 0)
		error = restore_into_destination("vm.ckp", true);
	else
		startup_refusals++;
	guest_ncpus = 2;
	cpu_sockets = 1;
	cpu_cores = 2;
	cpu_threads = 1;
	return (error);
}

static const char *must_refuse_keys[] = {
	"\"ncpus\"", "\"cpu_sockets\"", "\"cpu_cores\"", "\"cpu_threads\"",
	"\"cpu_contract\"", "\"numa_topology_version\"", "\"numa_domain_sizes\"",
	"\"numa_vcpu_domains\"", "\"memory_", "\"memsize\"",
	"\"compatibility_version\"", "\"machine_topology_", "\"size\"",
	"\"file_offset\"", "\"device\"", "\"compat_", "\"hypertrace_handoff_version\"",
};

static bool
must_refuse(const char *line)
{
	for (size_t i = 0; i < nitems(must_refuse_keys); i++)
		if (strstr(line, must_refuse_keys[i]) != NULL)
			return (true);
	return (false);
}

static void
test_metadata_mutations(void)
{
	static const char *values[] = { "-1", "0", "99999999999999999999", "\"x\"",
	    "7", "[]", "4294967297" };
	char *meta, *line, *next, *colon, *mutated;
	size_t len;
	int refused = 0, accepted = 0, total = 0, accepted_must_refuse = 0, arrays = 0;

	fresh_dir();
	vm_init(&src_vm, "src", 0x5c);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	{
		bool exists, is_manifest;
		CHECK(checkpoint_manifest_read_at(dirfd_, "vm.ckp", &good_manifest,
		    &exists, &is_manifest) == 0);
	}
	{
		struct restore_state r;
		char path[400];
		snprintf(path, sizeof(path), "%s/vm.ckp", dir);
		CHECK(load_restore_file(path, &r) == 0);
		startup_lookups(&r, true);
		destroy_restore_state(&r);
	}
	meta = slurp(good_manifest.meta, &len);
	mutated = __real_malloc(len + 256);
	for (line = meta; (next = strchr(line, '\n')) != NULL; line = next + 1) {
		size_t prefix, vlen;
		char linebuf[2048];

		colon = memchr(line, ':', (size_t)(next - line));
		if (colon == NULL || colon[1] != ' ')
			continue;
		prefix = (size_t)(colon + 2 - meta);
		if (colon[2] == '{' || colon[2] == '[') {
			/* A structured value: its extent is found by bracket depth. */
			int depth = 0;
			const char *q = colon + 2, *stop = meta + len;
			for (; q < stop; q++) {
				if (*q == '{' || *q == '[')
					depth++;
				else if (*q == '}' || *q == ']') {
					if (--depth == 0) {
						q++;
						break;
					}
				}
			}
			vlen = (size_t)(q - (colon + 2));
			arrays++;
		} else {
			vlen = (size_t)(next - (colon + 2));
			if (vlen > 0 && colon[2 + vlen - 1] == ',')
				vlen--;
		}
		snprintf(linebuf, sizeof(linebuf), "%.*s", (int)(next - line), line);
		for (size_t v = 0; v <= nitems(values); v++) {
			size_t mlen;
			int error;

			/* A structured value takes the scalar 7, the empty array and
			 * the rename. */
			if ((colon[2] == '{' || colon[2] == '[') && v < nitems(values) &&
			    strcmp(values[v], "7") != 0 && strcmp(values[v], "[]") != 0)
				continue;
			if (v < nitems(values)) {
				/* Replace the value. */
				memcpy(mutated, meta, prefix);
				mlen = prefix;
				memcpy(mutated + mlen, values[v], strlen(values[v]));
				mlen += strlen(values[v]);
				memcpy(mutated + mlen, colon + 2 + vlen,
				    len - prefix - vlen);
				mlen += len - prefix - vlen;
			} else {
				/* Rename the key: equivalent to removing it. */
				memcpy(mutated, meta, len);
				mlen = len;
				mutated[(size_t)(colon - meta) - 2] ^= 0x20;
			}
			if (mlen == len && memcmp(mutated, meta, len) == 0)
				continue;
			spill(good_manifest.meta, mutated, mlen);
			rehash("meta", good_manifest.meta);
			error = restore_mutated(NULL);
			total++;
			if (error != 0)
				refused++;
			else {
				accepted++;
				/* An absent handoff version is the legacy
				 * value 0 for a format-3 manifest. */
				bool legacy = v == nitems(values) &&
				    strstr(linebuf, "hypertrace_handoff_version") != NULL;
				if (must_refuse(linebuf) && !legacy) {
					accepted_must_refuse++;
					fprintf(stderr, "ACCEPTED %s -> %s\n", linebuf,
					    v < nitems(values) ? values[v] : "(renamed)");
				}
			}
		}
	}
	spill(good_manifest.meta, meta, len);
	rehash("meta", good_manifest.meta);
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	free(meta);
	free(mutated);
	printf("snapshot metadata mutations: %d (%d refused, %d by bhyverun admission; "
	    "%d accepted with exact state; %d structured values)\n", total, refused,
	    startup_refusals, accepted, arrays);
	CHECK(accepted_must_refuse == 0);
}

/* Every manifest line mutation is refused; member truncation and payload
 * corruption covered by a compatibility CRC are refused. */
static void
test_member_mutations(void)
{
	char *manifest, *data;
	size_t len, dlen;
	int total = 0;

	fresh_dir();
	vm_init(&src_vm, "src", 0x5d);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	{
		bool exists, is_manifest;
		CHECK(checkpoint_manifest_read_at(dirfd_, "vm.ckp", &good_manifest,
		    &exists, &is_manifest) == 0);
	}
	manifest = slurp("vm.ckp", &len);
	for (size_t i = 0; i < len; i++) {
		static const char subst[] = { 'A', '0', '\n', '=', '.', '/', '\0' };
		if (i > 40 && manifest[i - 1] != '\n' && manifest[i - 1] != '=' &&
		    i % 13 != 0)
			continue;
		for (size_t k = 0; k < sizeof(subst); k++) {
			char saved = manifest[i];
			if (saved == subst[k])
				continue;
			manifest[i] = subst[k];
			spill("vm.ckp", manifest, len);
			CHECK(restore_into_destination("vm.ckp", false) != 0);
			manifest[i] = saved;
			total++;
		}
	}
	/* Truncated and extended manifests. */
	for (size_t cut = 0; cut < len; cut += 37) {
		spill("vm.ckp", manifest, cut);
		CHECK(restore_into_destination("vm.ckp", false) != 0);
		total++;
	}
	{
		char *longer = __real_malloc(len + 16);
		memcpy(longer, manifest, len);
		memcpy(longer + len, "extra=1\n", 8);
		spill("vm.ckp", longer, len + 8);
		CHECK(restore_into_destination("vm.ckp", false) != 0);
		free(longer);
		total++;
	}
	spill("vm.ckp", manifest, len);
	/* Members without the manifest digest update. */
	{
		const char *members[] = { good_manifest.data, good_manifest.kern,
		    good_manifest.meta };
		for (size_t m = 0; m < nitems(members); m++) {
			data = slurp(members[m], &dlen);
			data[dlen / 2] ^= 1;
			spill(members[m], data, dlen);
			CHECK(restore_into_destination("vm.ckp", false) != 0);
			data[dlen / 2] ^= 1;
			spill(members[m], data, dlen);
			free(data);
			total++;
		}
	}
	/* A truncated data member with a matching digest is refused. */
	data = slurp(good_manifest.data, &dlen);
	spill(good_manifest.data, data, dlen - PAGE_SIZE);
	rehash("data", good_manifest.data);
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	spill(good_manifest.data, data, dlen);
	rehash("data", good_manifest.data);
	free(data);
	total++;
	/* Kernel-member corruption inside the compatibility device's payload
	 * (protected by compat_payload_crc32) is refused even with a matching
	 * member digest; truncation of the kernel member is refused. */
	data = slurp(good_manifest.kern, &dlen);
	data[1123 + 5] ^= 0x10;
	spill(good_manifest.kern, data, dlen);
	rehash("kern", good_manifest.kern);
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	data[1123 + 5] ^= 0x10;
	spill(good_manifest.kern, data, dlen - 1);
	rehash("kern", good_manifest.kern);
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	spill(good_manifest.kern, data, dlen);
	rehash("kern", good_manifest.kern);
	free(data);
	total += 2;
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	free(manifest);
	printf("snapshot member mutations: %d refused\n", total);
}

/*
 * A guest under the restore startup fence (a restored or retained inbound
 * destination whose vCPUs never ran) cannot be checkpointed: vm_checkpoint()
 * refuses with EBUSY before creating any file, for both --checkpoint and
 * --suspend, and leaves the fence held and the parked vCPU parked.
 * Regression: the plain checkpoint used to complete, and its vCPU resume
 * released the parked vCPU while the fence was still reported held, which
 * would have started a retained guest.  Once the fence is released (as a
 * resolved resume releases it) the checkpoint works again.
 */
static volatile int parked_released;

static void *
parked_vcpu(void *arg)
{
	(void)arg;
	checkpoint_cpu_add(0);	/* parks while the startup fence is active */
	parked_released = 1;
	return (NULL);
}

static void
test_fenced_checkpoint(void)
{
	pid_t child;
	int status;

	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		char names[16][128];
		pthread_t t;
		int before;

		fresh_dir();
		vm_init(&src_vm, "src", 0x25);
		devices_init();
		tracing = false;
		checkpoint_restore_startup_hold();
		CHECK(pthread_create(&t, NULL, parked_vcpu, NULL) == 0);
		usleep(100000);
		CHECK(!parked_released);
		alarm(20);	/* a hang fails the test */
		before = list_dir(names, 16);
		BOTH_PARITIES(CHECK(vm_checkpoint(&src_vm, dirfd_, "held.ckp", false) == EBUSY));
		CHECK(vm_checkpoint(&src_vm, dirfd_, "held.ckp", true) == EBUSY);
		usleep(100000);
		CHECK(list_dir(names, 16) == before);	/* nothing created */
		CHECK(!parked_released && checkpoint_restore_startup_held() &&
		    !src_vm.destroyed);
		/* The fence released (resume of the retained copy): the vCPU
		 * runs and a checkpoint works again. */
		CHECK(checkpoint_restore_startup_release() == 0);
		CHECK(pthread_join(t, NULL) == 0 && parked_released);
		/* vCPU 0 now reports itself idle, as a running vCPU does when the
		 * checkpoint suspends it, and resumes after the checkpoint. */
		checkpoint_cpu_suspend(0);
		CHECK(vm_checkpoint(&src_vm, dirfd_, "held.ckp", false) == 0);
		checkpoint_cpu_resume(0);
		printf("snapshot fenced guest: checkpoint and suspend refused (EBUSY), "
		    "nothing created, vCPU parked; works after release\n");
		fflush(stdout);
		exit(0);	/* exit (not _exit): the child's coverage profile is written */
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == 0);
}

/* --------------------------------------------------- fault enumeration */
typedef void scenario_fn(void);
struct scenario {
	const char *name;
	void (*prepare)(void);	/* unarmed setup, in the child */
	int (*operate)(void);	/* armed operation */
	void (*verify)(int result);	/* unarmed invariants */
};
static const char *relaxed;	/* fault name whose effect the oracle allows */

static int
pick_occurrences(int last, int *out)
{
	int n = 0;

	for (int k = 1; k <= last; k++)
		if (k <= 16 || k > last - 4 || k % 17 == 0)
			out[n++] = k;
	return (n);
}

static int
fault_errno(const char *name)
{
	if (strcmp(name, "malloc") == 0 || strcmp(name, "calloc") == 0 ||
	    strcmp(name, "strdup") == 0 || strcmp(name, "mmap") == 0)
		return (ENOMEM);
	if (strcmp(name, "write") == 0 || strcmp(name, "pwrite") == 0 ||
	    strcmp(name, "fwrite") == 0 || strcmp(name, "fsync") == 0)
		return (ENOSPC);
	if (strcmp(name, "vm_snapshot_session") == 0)
		return (ESTALE);
	return (EIO);
}

static int enumerated_faults, enumerated_failures, enumerated_benign, enumerated_noerrno;
static int noerrno_mismatches;

static bool
libc_boundary(const char *name)
{
	static const char *const names[] = { "malloc", "calloc", "strdup", "open",
	    "openat", "fstat", "fsync", "unlinkat", "linkat", "renameat", "write",
	    "pwrite", "pread", "read", "lseek", "flock", "mmap", "memfd_create",
	    "fdopen", "fwrite", "fread", "fseek", "ftell", "close", "fclose", "fflush",
	    "xo_finish_h", "asprintf", "clock_gettime", "nanosleep",
	    /* ioctl-style boundaries whose fakes can fail without an errno */
	    "vm_destroy_checked", "vm_get_cpuid", "vm_get_devmem_info",
	    "vm_get_guestmem_from_ctx", "vm_restore_time", "vm_resume_all_cpus",
	    "vm_snapshot_req" };
	for (size_t i = 0; i < nitems(names); i++)
		if (strcmp(name, names[i]) == 0)
			return (true);
	return (false);
}

static void
enumerate(const struct scenario *sc)
{
	struct { char name[64]; int last; } list[MAX_POINTS];
	int nlist, status;
	pid_t child;

	/* Record the boundaries of an unfaulted run in a child. */
	{
		int pfd[2];
		CHECK(pipe(pfd) == 0);
		fflush(stdout);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			close(pfd[0]);
			sc->prepare();
			reset_points();
			nseen = 0;
			recording = true;
			fault_name[0] = '\0';
			armed = true;
			CHECK(sc->operate() == 0);
			armed = false;
			recording = false;
			sc->verify(0);
			CHECK(__real_write(pfd[1], &nseen, sizeof(nseen)) == sizeof(nseen));
			CHECK(__real_write(pfd[1], seen, sizeof(seen[0]) * nseen) ==
			    (ssize_t)(sizeof(seen[0]) * nseen));
			exit(0);
		}
		close(pfd[1]);
		CHECK(__real_read(pfd[0], &nlist, sizeof(nlist)) == sizeof(nlist));
		CHECK(__real_read(pfd[0], list, sizeof(list[0]) * nlist) ==
		    (ssize_t)(sizeof(list[0]) * nlist));
		close(pfd[0]);
		CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
		    WEXITSTATUS(status) == 0);
	}
	struct { int i, occ, status; } refused[512];
	int nrefused = 0;
	for (int i = 0; i < nlist; i++) {
		int occ[4096], nocc = pick_occurrences(list[i].last, occ);

		for (int j = 0; j < nocc; j++) {
			int result = 0;

			fflush(stdout);
			fflush(stderr);
			child = fork();
			CHECK(child >= 0);
			if (child == 0) {
				int devnull = __real_open("fault.err",
				    O_WRONLY | O_CREAT | O_TRUNC, 0600);
				dup2(devnull, STDERR_FILENO);
				sc->prepare();
				reset_points();
				ht_probe_queries = (unsigned long)occ[j];
				raw_stdio = occ[j] & 1;		/* both console modes */
				strlcpy(fault_name, list[i].name, sizeof(fault_name));
				fault_occurrence = occ[j];
				fault_error = fault_errno(fault_name);
				relaxed = fault_name;
				armed = true;
				result = sc->operate();
				armed = false;
				sc->verify(result);
				exit(result == 0 ? 0 : 1);
			}
			CHECK(waitpid(child, &status, 0) == child);
			if (WIFEXITED(status) && WEXITSTATUS(status) == 2) {
				printf("snapshot faults %s: %s:%d published with an error result\n",
				    sc->name, list[i].name, occ[j]);
				enumerated_faults++;
				enumerated_failures++;
				if (libc_boundary(list[i].name) && nrefused < 512) {
					refused[nrefused].i = i;
					refused[nrefused].occ = occ[j];
					refused[nrefused++].status = 2;
				}
				continue;
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status) > 1) {
				fprintf(stderr, "%s: fault %s:%d: status 0x%x\n",
				    sc->name, list[i].name, occ[j], status);
				system("tail -5 fault.err >&2");
				abort();
			}
			enumerated_faults++;
			if (WEXITSTATUS(status) == 0)
				enumerated_benign++;
			else
				enumerated_failures++;
			if (WEXITSTATUS(status) != 0 && libc_boundary(list[i].name) &&
			    nrefused < 512) {
				refused[nrefused].i = i;
				refused[nrefused].occ = occ[j];
				refused[nrefused++].status = WEXITSTATUS(status);
			}
		}
	}
	/*
	 * Errno-less libc failures.  Each libc fault that refused the operation
	 * is repeated with errno left at 0.  Oracle: the same outcome class
	 * (refused, or published with an error result) and the scenario's
	 * invariants; above all a failure that reports no errno never becomes
	 * a success.
	 */
	for (int r = 0; r < nrefused; r++) {
		int i = refused[r].i;

		fflush(stdout);
		fflush(stderr);
		child = fork();
		CHECK(child >= 0);
		if (child == 0) {
			int devnull = __real_open("fault.err",
			    O_WRONLY | O_CREAT | O_TRUNC, 0600);
			int result;
			dup2(devnull, STDERR_FILENO);
			sc->prepare();
			reset_points();
			ht_probe_queries = (unsigned long)refused[r].occ + 1;
			raw_stdio = (refused[r].occ + 1) & 1;
			strlcpy(fault_name, list[i].name, sizeof(fault_name));
			fault_occurrence = refused[r].occ;
			fault_error = FAULT_NOERRNO;
			relaxed = fault_name;
			armed = true;
			result = sc->operate();
			armed = false;
			sc->verify(result);
			exit(result == 0 ? 0 : 1);
		}
		CHECK(waitpid(child, &status, 0) == child);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != refused[r].status) {
			fprintf(stderr, "%s: errno-less fault %s:%d: status 0x%x, with errno %d\n",
			    sc->name, list[i].name, refused[r].occ, status, refused[r].status);
			system("tail -3 fault.err >&2");
			noerrno_mismatches++;
			continue;
		}
		enumerated_noerrno++;
	}
	CHECK(noerrno_mismatches == 0);
	printf("snapshot faults %s: %d boundaries, %d faults (%d refused, %d benign); "
	    "%d errno-less repeats matched\n", sc->name, nlist, enumerated_faults,
	    enumerated_failures, enumerated_benign, enumerated_noerrno);
	enumerated_faults = enumerated_failures = enumerated_benign = 0;
	enumerated_noerrno = 0;
}

static char generation_before[128];
static int published_with_error;
static void manifest_generation(char *, size_t);

/* Checkpoint: a good generation exists; the source changes; a faulted
 * checkpoint either publishes the new state exactly or leaves the previous
 * generation intact and the source running. */
static void
ckpt_prepare(void)
{
	fresh_dir();
	vm_init(&src_vm, "src", 0x55);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	manifest_generation(generation_before, sizeof(generation_before));
	src_vm.base[100] ^= 1;
	src_vm.base[HIGHBASE + 7] ^= 2;
	src_state[1].counter++;
	kbd_state[0][3]++;
}

static int
ckpt_operate(void)
{
	return (vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false));
}

static bool
relaxed_is(const char *name)
{
	return (relaxed != NULL && strcmp(relaxed, name) == 0);
}


static void
manifest_generation(char *out, size_t len)
{
	char names[32][128];
	int n = list_dir(names, 32);

	out[0] = '\0';
	for (int i = 0; i < n; i++)
		if (strncmp(names[i], "vm.ckp.data.", 12) == 0 &&
		    out[0] == '\0')
			strlcpy(out, names[i] + 12, len);
}

static bool
manifest_names(const char *generation)
{
	struct checkpoint_manifest m;
	bool exists, is_manifest;

	CHECK(checkpoint_manifest_read_at(dirfd_, "vm.ckp", &m, &exists,
	    &is_manifest) == 0 && exists && is_manifest);
	return (strstr(m.data, generation) != NULL);
}

static void
ckpt_verify(int result)
{
	char names[32][128];
	bool published;
	int n;

	/* Never run the guest while the kernel session is outstanding. */
	if (src_vm.session_active)
		CHECK(src_vm.suspended && src_state[0].paused && src_state[1].paused);
	else if (!relaxed_is("vm_resume_all_cpus") && !relaxed_is("pci_resume"))
		CHECK(!src_vm.suspended && !src_state[0].paused && !src_state[1].paused);
	if (src_vm.session_active)
		CHECK(result != 0 && relaxed_is("vm_snapshot_session"));
	/* A device which failed to resume keeps the guest stopped. */
	if (relaxed_is("pci_resume") && result != 0)
		CHECK(src_vm.suspended && checkpoint_active);
	published = !manifest_names(generation_before);
	/* The destination is a new process: no inherited execution fence. */
	checkpoint_active = false;
	restore_startup_hold = false;
	n = list_dir(names, 32);
	if (!published) {
		CHECK(result != 0);
		/* Previous generation: undo the changes and compare. */
		src_vm.base[100] ^= 1;
		src_vm.base[HIGHBASE + 7] ^= 2;
		src_state[1].counter--;
		kbd_state[0][3]--;
		/* Orphaned members are allowed only when removal was faulted. */
		if (!relaxed_is("unlinkat"))
			CHECK(n == 5);
	} else {
		if (result != 0) {
			published_with_error++;
			fprintf(stderr, "PUBLISHED-WITH-ERROR %s:%d -> %d\n",
			    relaxed, fault_occurrence, result);
		}
		/* The old generation is removed only after a clean publish;
		 * the kernel session is released after that removal. */
		CHECK(n == (result == 0 || relaxed_is("vm_snapshot_session") ||
		    relaxed_is("pci_resume") || relaxed_is("vm_resume_all_cpus") ? 5 : 8) ||
		    relaxed_is("unlinkat"));
	}
	CHECK(restore_into_destination("vm.ckp", true) == 0);
	if (published && result != 0)
		exit(2);
}

/* Restore: a faulted restore either restores exactly or fails holding the
 * startup fence (checked by restore_into_destination). */
static int restore_result;
static void
restore_prepare(void)
{
	fresh_dir();
	vm_init(&src_vm, "src", 0x66);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
}

static int
restore_operate(void)
{
	restore_result = restore_into_destination("vm.ckp", true);
	return (restore_result);
}

static void
restore_verify(int result)
{
	(void)result;
	/* The checkpoint is unchanged and still restores. */
	CHECK(restore_into_destination("vm.ckp", true) == 0);
}

/* Migration blob: faulted capture returns no blob and no session; faulted
 * commit keeps the startup fence. */
static uint8_t *mblob;
static size_t mlen;
static struct vm_snapshot_capture mcapture;
static void
blob_prepare(void)
{
	vm_init(&src_vm, "src", 0x77);
	devices_init();
	mblob = NULL;
	mlen = 0;
}

static int
blob_operate(void)
{
	memset(&mcapture, 0, sizeof(mcapture));
	return (vm_snapshot_dev_state_to_mem(&src_vm, &mblob, &mlen, &mcapture));
}

static void
blob_verify(int result)
{
	/* A failed capture holds no fence (or an unresolved one only when its
	 * release was faulted); a successful one holds it until finished. */
	CHECK(!src_vm.session_active || result == 0 || relaxed_is("vm_snapshot_session"));
	if (result != 0) {
		CHECK(mblob == NULL && mlen == 0);
		CHECK(!mcapture.active || mcapture.unresolved);
		return;
	}
	CHECK(src_vm.session_active && mcapture.active);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &mcapture, false) == 0);
	CHECK(!src_vm.session_active && !mcapture.active);
	vm_init(&dst_vm, "dst", 0x77);
	side = 1;
	state = dst_state;
	checkpoint_restore_startup_hold();
	CHECK(vm_migrate_commit_state(&dst_vm, mblob, mlen) == 0);
	CHECK(vm_migrate_resume(&dst_vm) == 0);
	for (int i = 0; i < 2; i++)
		CHECK(memcmp(dst_state[i].bytes, src_state[i].bytes, 96) == 0 &&
		    dst_state[i].counter == src_state[i].counter);
}

static void
commit_prepare(void)
{
	blob_prepare();
	memset(&mcapture, 0, sizeof(mcapture));
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &mblob, &mlen, &mcapture) == 0);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &mcapture, false) == 0);
	vm_init(&dst_vm, "dst", 0x77);
	side = 1;
	state = dst_state;
	checkpoint_restore_startup_hold();
}

static int
commit_operate(void)
{
	int error = vm_migrate_commit_state(&dst_vm, mblob, mlen);

	if (error == 0)
		error = vm_migrate_resume(&dst_vm);
	return (error);
}

static void
commit_verify(int result)
{
	if (result != 0) {
		CHECK(checkpoint_restore_startup_held() || relaxed_is("pci_resume") ||
		    relaxed_is("vm_restore_time"));
		return;
	}
	CHECK(!checkpoint_restore_startup_held());
	for (int i = 0; i < 2; i++)
		CHECK(memcmp(dst_state[i].bytes, src_state[i].bytes, 96) == 0 &&
		    dst_state[i].counter == src_state[i].counter && !dst_state[i].paused);
}

/*
 * Fresh-session variants.  A fresh checkpoint is written by a stop-VM
 * checkpoint in a child (it exits on success); its restore is then faulted.
 * Fresh capture and commit/resume use the session record of a stopped
 * source.  Oracles: a faulted fresh restore or commit never releases the
 * destination's startup fence and the checkpoint still restores; a faulted
 * capture returns no blob and leaves no kernel session.
 */
static uint8_t fresh_record[HYPERTRACE_SESSION_RECORD_SIZE];
static struct pci_devinst *fresh_device;

static void
fresh_restore_prepare(void)
{
	pid_t child;
	int status;

	fresh_dir();
	vm_init(&src_vm, "src", 0x67);
	devices_init();
	tracing = true;
	vtdtr_present = true;
	fflush(stdout);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		(void)vm_checkpoint(&src_vm, dirfd_, "vm.ckp", true);
		_exit(99);
	}
	CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	    WEXITSTATUS(status) == BHYVE_EXIT_SUSPEND);
}

static void
fresh_restore_verify(int result)
{
	(void)result;
	CHECK(restore_into_destination("vm.ckp", true) == 0);
}

static void
fresh_blob_prepare(void)
{
	vm_init(&src_vm, "src", 0x78);
	devices_init();
	tracing = true;
	vtdtr_present = true;
	mblob = NULL;
	mlen = 0;
	CHECK(vm_migrate_stop_tracing(&src_vm, fresh_record) == 0);
}

static int
fresh_blob_operate(void)
{
	memset(&mcapture, 0, sizeof(mcapture));
	return (vm_snapshot_fresh_dev_state_to_mem(&src_vm, fresh_record, &mblob, &mlen,
	    &mcapture));
}

static void
fresh_blob_verify(int result)
{
	CHECK(!src_vm.session_active || result == 0 || relaxed_is("vm_snapshot_session"));
	if (result != 0) {
		CHECK(mblob == NULL && mlen == 0);
		CHECK(!mcapture.active || mcapture.unresolved);
	} else {
		CHECK(mblob != NULL && mlen > MIGRATE_BLOB_HDR);
		/* Retirement commits the fence the capture still holds. */
		CHECK(src_vm.session_active && mcapture.active);
		CHECK(vm_snapshot_dev_state_finish(&src_vm, &mcapture, true) == 0);
		CHECK(!src_vm.session_active);
	}
}

static void
fresh_commit_prepare(void)
{
	fresh_blob_prepare();
	CHECK(fresh_blob_operate() == 0);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &mcapture, true) == 0);
	vm_init(&dst_vm, "dst", 0x78);
	side = 1;
	state = dst_state;
	fresh_device = NULL;
	checkpoint_restore_startup_hold();
}

static int
fresh_commit_operate(void)
{
	int error = vm_migrate_fresh_commit_state(&dst_vm, mblob, mlen, &fresh_device);

	if (error == 0)
		error = vm_migrate_fresh_resume(&dst_vm, fresh_device, fresh_record);
	return (error);
}

static void
fresh_commit_verify(int result)
{
	if (result != 0) {
		CHECK(checkpoint_restore_startup_held() || relaxed_is("pci_resume") ||
		    relaxed_is("vm_restore_time") || relaxed_is("vm_resume_all_cpus"));
		return;
	}
	CHECK(!checkpoint_restore_startup_held());
	for (int i = 0; i < 2; i++)
		CHECK(memcmp(dst_state[i].bytes, src_state[i].bytes, 96) == 0 &&
		    dst_state[i].counter == src_state[i].counter);
}

/* A fresh (tracing) stopped checkpoint, run in-process: the process exit
 * on success is caught.  Oracles: a result of 0 means the manifest was
 * published and the source destroyed, and the checkpoint restores; any
 * error leaves the source undestroyed, and (unless the fault came after
 * publication) no manifest. */
static void mutate_meta(const char *, const char *, bool);
static void rehash_named(const char *, const char *, const char *);
static int fault_once(const char *, int, int);
static void fault_clear(void);
static char *slurp(const char *, size_t *);
static void spill(const char *, const char *, size_t);

static int
checkpoint_stop_vm(const char *name)
{
	int r, jumped;

	if ((jumped = setjmp(suspend_jmp)) != 0) {
		/* The exit path skipped the lock release; a later shared lock in
		 * this process (a restore) would otherwise block on it. */
		if (held_exclusive_fd >= 0) {
			__real_close(held_exclusive_fd);
			held_exclusive_fd = -1;
		}
		/* The exiting source never resumes; this process goes on to act
		 * as a new destination with no inherited execution fence. */
		checkpoint_active = false;
		return (jumped == 1 ? 0 : CHECKPOINT_EXITED_ERROR);
	}
	suspend_catch = true;
	r = vm_checkpoint(&src_vm, dirfd_, name, true);
	suspend_catch = false;
	return (r);
}

static bool
manifest_published(const char *name)
{
	struct checkpoint_manifest m;
	bool exists = false, is_manifest = false;

	if (checkpoint_manifest_read_at(dirfd_, name, &m, &exists, &is_manifest) != 0)
		return (false);
	return (exists && is_manifest);
}

static void
fresh_ckpt_prepare(void)
{
	fresh_dir();
	vm_init(&src_vm, "src", 0x69);
	devices_init();
	tracing = true;
	stop_status_busy = 1;		/* the stop poll retries once */
	collectors_remaining = 1;	/* the collector loop steps twice */
}

static int
fresh_ckpt_operate(void)
{
	return (checkpoint_stop_vm("vm.ckp"));
}

static void
fresh_ckpt_verify(int result)
{
	bool published = manifest_published("vm.ckp");

	if (result == 0) {
		CHECK(published && src_vm.destroyed);
		CHECK(restore_into_destination("vm.ckp", true) == 0);
		return;
	}
	if (result == CHECKPOINT_EXITED_ERROR) {
		/* Published, but the source could not be stopped cleanly: bhyve
		 * ends without resuming it; the checkpoint is the surviving copy. */
		CHECK(published && !src_vm.destroyed);
		CHECK(src_vm.suspended && src_state[0].paused && src_state[1].paused);
		CHECK(restore_into_destination("vm.ckp", true) == 0);
		return;
	}
	CHECK(!src_vm.destroyed);
	/* A stop_vm checkpoint never returns an error once published: the
	 * process exits instead (above).  A failure before publication resumes
	 * the source and publishes nothing new. */
	if (published)
		fprintf(stderr, "PUBLISHED-AND-RESUMED %s:%d -> %d\n", relaxed, fault_occurrence, result);
	CHECK(!published);
	CHECK(!src_vm.suspended && !src_state[0].paused && !src_state[1].paused);
}

/* The HyperTrace stop protocol inside a fresh stopped checkpoint: each step's
 * failure, the deadline readings (failing, errno-less, past, exactly at and
 * just before the 600 s deadline) and the sleeps (EINTR continues; other
 * failures, with or without errno, refuse). */
static void
test_stop_protocol(void)
{
	struct row { const char *name; int occ, error; int fail_call, fail_after, jump_after,
	    jump_mode, clock_error, expect; };
	static const struct row rows[] = {
		{ "pci_vtdtr_session_checkpoint_begin", 1, EIO, 0, 0, 0, 0, 0, EIO },
		{ "pci_vtdtr_session_stop_status", 1, EIO, 0, 0, 0, 0, 0, EIO },
		{ "pci_vtdtr_session_collectors_stop_step", 1, EIO, 0, 0, 0, 0, 0, EIO },
		{ "pci_vtdtr_session_checkpoint_export", 1, EIO, 0, 0, 0, 0, 0, EIO },
		{ NULL, 0, 0, -1, 0, 0, 0, EIO, EIO },		/* the deadline reading */
		{ NULL, 0, 0, -1, 0, 0, 0, FAULT_NOERRNO, EIO },
		{ NULL, 0, 0, 0, 1, 0, 0, EIO, EIO },		/* the first poll reading */
		{ NULL, 0, 0, 0, 1, 0, 0, FAULT_NOERRNO, EIO },
		{ NULL, 0, 0, 0, 0, 1, 1, 0, ETIMEDOUT },
		{ NULL, 0, 0, 0, 0, 1, 2, 0, ETIMEDOUT },
		{ NULL, 0, 0, 0, 0, 1, 3, 0, 0 },
		{ NULL, 0, 0, 0, 3, 0, 0, EIO, EIO },		/* the first collector reading */
		{ NULL, 0, 0, 0, 3, 0, 0, FAULT_NOERRNO, EIO },
		{ NULL, 0, 0, 0, 0, 3, 1, 0, ETIMEDOUT },
		{ NULL, 0, 0, 0, 0, 3, 2, 0, ETIMEDOUT },
		{ NULL, 0, 0, 0, 0, 3, 3, 0, 0 },
		{ "nanosleep", 1, EINTR, 0, 0, 0, 0, 0, 0 },	/* the poll delay */
		{ "nanosleep", 1, EIO, 0, 0, 0, 0, 0, EIO },
		{ "nanosleep", 1, FAULT_NOERRNO, 0, 0, 0, 0, 0, EIO },
		{ "nanosleep", 3, EINTR, 0, 0, 0, 0, 0, 0 },	/* the collector delay */
		{ "nanosleep", 3, EIO, 0, 0, 0, 0, 0, EIO },
		{ "nanosleep", 3, FAULT_NOERRNO, 0, 0, 0, 0, 0, EIO },
	};
	int deadline_call = 0;

	for (int i = -1; i < (int)nitems(rows); i++) {
		const struct row *r = i < 0 ? NULL : &rows[i];
		int result;

		fresh_dir();
		vm_init(&src_vm, "src", 0x70);
		devices_init();
		tracing = true;
		stop_status_busy = 2;
		collectors_remaining = 1;
		clock_calls = 0;
		clock_calls_after_begin = -1;
		clock_fail_call = r != NULL && r->fail_call < 0 ? deadline_call : 0;
		clock_fail_after_begin = r != NULL ? r->fail_after : 0;
		clock_jump_after_begin = r != NULL ? r->jump_after : 0;
		clock_jump_mode = r != NULL ? r->jump_mode : 0;
		clock_fail_error = r != NULL ? r->clock_error : 0;
		clock_track = true;
		reset_points();
		fault_name[0] = '\0';
		if (r != NULL && r->name != NULL) {
			strlcpy(fault_name, r->name, sizeof(fault_name));
			fault_occurrence = r->occ;
			fault_error = r->error;
		}
		armed = true;
		result = checkpoint_stop_vm("stop.ckp");
		armed = false;
		clock_track = false;
		if (r == NULL) {
			/* Calibration: the deadline reading is the last before begin. */
			CHECK(result == 0 && clock_count_at_begin >= 1);
			deadline_call = clock_count_at_begin;
			continue;
		}
		if (result != r->expect)
			fprintf(stderr, "stop protocol row %d: got %d want %d\n", i, result, r->expect);
		CHECK(result == r->expect);
		if (result == 0)
			CHECK(src_vm.destroyed && manifest_published("stop.ckp"));
		else
			CHECK(!src_vm.destroyed && !manifest_published("stop.ckp"));
	}
	fault_name[0] = '\0';
	clock_fail_call = clock_fail_after_begin = clock_jump_after_begin = 0;
	tracing = false;
	printf("snapshot stop protocol: %zu rows\n", nitems(rows));
}

/* Restore-transaction refusals of a fresh-session image and failures of
 * the admission steps.  Oracle: the documented error, the destination still
 * fenced and no kernel session left active (unless the kernel itself refused
 * to release it). */
static void
test_restore_refusals(void)
{
	struct restore_state rstate;
	char path[400], legacy[400];
	int saved_fd, r;

	fresh_dir();
	vm_init(&src_vm, "src", 0x71);
	devices_init();
	tracing = false;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "legacy.ckp", false) == 0);
	snprintf(legacy, sizeof(legacy), "%s/legacy.ckp", dir);
	tracing = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(checkpoint_stop_vm("fresh.ckp") == 0);
	snprintf(path, sizeof(path), "%s/fresh.ckp", dir);
#define LOAD(p) do {								\
	CHECK(load_restore_file((p), &rstate) == 0);				\
	vm_init(&dst_vm, "dst", 0x99);						\
	side = 1;								\
	state = dst_state;							\
	checkpoint_restore_startup_hold();					\
} while (0)
#define DONE(session_check) do {						\
	CHECK(checkpoint_restore_startup_held());				\
	if (session_check)							\
		CHECK(!dst_vm.session_active);					\
	(void)checkpoint_restore_startup_release();				\
	destroy_restore_state(&rstate);						\
	side = 0;								\
	state = src_state;							\
} while (0)
	LOAD(path);
	CHECK(rstate.checkpoint_format_version == 5 && rstate.hypertrace_session_present);
	tracing = false;		/* a fresh image needs tracing on this host */
	BOTH_PARITIES(CHECK(vm_restore_transaction(&dst_vm, &rstate) == ENOTSUP));
	tracing = true;
	DONE(true);
	LOAD(path);
	rstate.handoff_identity_valid = false;
	CHECK(vm_restore_transaction(&dst_vm, &rstate) == ENOTSUP);
	DONE(true);
	LOAD(path);
	saved_fd = rstate.checkpoint_lock_fd;
	rstate.checkpoint_lock_fd = -1;
	CHECK(vm_restore_transaction(&dst_vm, &rstate) == ENOTSUP);
	rstate.checkpoint_lock_fd = saved_fd;
	DONE(true);
	LOAD(path);
	saved_fd = rstate.checkpoint_lock_fd;
	rstate.checkpoint_lock_fd = dup(dirfd_);	/* a directory is not a lock */
	CHECK(vm_restore_transaction(&dst_vm, &rstate) == ENOTSUP);
	close(rstate.checkpoint_lock_fd);
	rstate.checkpoint_lock_fd = saved_fd;
	DONE(true);
	LOAD(path);
	rstate.hypertrace_session_present = false;
	CHECK(vm_restore_transaction(&dst_vm, &rstate) == EPROTO);
	DONE(true);
	LOAD(path);
	rstate.hypertrace_transfer = __real_malloc(16);
	rstate.hypertrace_transfer_length = 16;
	CHECK(vm_restore_transaction(&dst_vm, &rstate) == EPROTO);
	DONE(true);
	LOAD(path);
	rstate.hypertrace_release_present = true;
	BOTH_PARITIES(CHECK(vm_restore_transaction(&dst_vm, &rstate) == EPROTO));
	DONE(true);
	/* A fresh image whose metadata lost its handoff version. */
	{
		struct checkpoint_manifest saved = good_manifest;
		bool exists, is_manifest;
		char *meta;
		size_t mlen;
		CHECK(checkpoint_manifest_read_at(dirfd_, "fresh.ckp", &good_manifest, &exists,
		    &is_manifest) == 0 && is_manifest);
		meta = slurp(good_manifest.meta, &mlen);
		mutate_meta("hypertrace_handoff_version", NULL, true);
		rehash_named("fresh.ckp", "meta", good_manifest.meta);
		LOAD(path);
		CHECK(vm_restore_transaction(&dst_vm, &rstate) == EPROTO);
		DONE(true);
		spill(good_manifest.meta, meta, mlen);
		rehash_named("fresh.ckp", "meta", good_manifest.meta);
		free(meta);
		good_manifest = saved;
	}
	/* The daemon refuses admission, with and without an errno. */
	LOAD(path);
	start_ready_error = EACCES;
	r = vm_restore_transaction(&dst_vm, &rstate);
	start_ready_error = 0;
	CHECK(r == EACCES);
	DONE(true);
	LOAD(path);
	start_ready_error = FAULT_NOERRNO;
	r = vm_restore_transaction(&dst_vm, &rstate);
	start_ready_error = 0;
	CHECK(r == EIO);
	DONE(true);
	/* Admission replay KILLs cannot target a fresh destination, nor a
	 * legacy one without a DTrace device. */
	LOAD(path);
	replay_fake_count = 2;
	r = vm_restore_transaction(&dst_vm, &rstate);
	replay_fake_count = 0;
	CHECK(r == EPROTO);
	DONE(true);
	LOAD(legacy);
	CHECK(rstate.checkpoint_format_version != 5);
	replay_fake_count = 1;
	r = vm_restore_transaction(&dst_vm, &rstate);
	replay_fake_count = 0;
	CHECK(r == EPROTO);
	DONE(true);
	/* Kernel session ownership unresolved at BEGIN. */
	{
		static const int unresolved[] = { EFAULT, EFAULT, EFAULT };
		LOAD(path);
		script(unresolved, 3);
		r = vm_restore_transaction(&dst_vm, &rstate);
		session_script = NULL;
		CHECK(r == EFAULT);
		DONE(false);
	}
	/* COMMIT fails and no retry proves release: the error is the commit's,
	 * the session stays live, and the abort on the failure path fails too. */
	{
		static const int stuck[] = { 0, EIO, EIO, EIO, EIO, EIO, EIO };
		LOAD(path);
		script(stuck, 7);
		r = vm_restore_transaction(&dst_vm, &rstate);
		session_script = NULL;
		CHECK(r == EIO);
		DONE(false);
	}
	/* The startup fence vanishes underneath the transaction (released while
	 * devices resume): the final release reports it. */
	LOAD(path);
	release_fence_on_resume = true;
	r = vm_restore_transaction(&dst_vm, &rstate);
	release_fence_on_resume = false;
	CHECK(r == EINVAL && !checkpoint_restore_startup_held());
	destroy_restore_state(&rstate);
	side = 0;
	state = src_state;
#undef LOAD
#undef DONE
	tracing = false;
	printf("snapshot restore refusals: fresh-image contracts, admission, replay, session ownership\n");
}

/* The manifest module's public contracts, called directly: argument guards,
 * member-name and generation rules, format-3/5 trace rules, name
 * construction limits, verified opens over crafted member files, and
 * publication guards.  Oracles: the documented boolean or errno. */
static void
hexcase(char *name, bool upper)
{
	size_t n = strlen(name);

	for (size_t i = n - CHECKPOINT_GENERATION_HEX_LEN; i < n; i++)
		name[i] = upper ? (char)toupper((unsigned char)name[i]) :
		    (char)tolower((unsigned char)name[i]);
}

static void
test_manifest_api(void)
{
	struct checkpoint_manifest m3, m5, bad;
	bool exists, is_manifest, published;
	char *tmp = NULL, big[NAME_MAX + 300], path[400];
	uint8_t token[16], digest[32], wire[CHECKPOINT_RELEASE_WIRE_SIZE];
	int a, b, c, t, fd, r;

	fresh_dir();
	vm_init(&src_vm, "src", 0x72);
	devices_init();
	tracing = false;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "v3.ckp", false) == 0);
	tracing = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(checkpoint_stop_vm("v5.ckp") == 0);
	tracing = false;
	CHECK(checkpoint_manifest_read_at(dirfd_, "v3.ckp", &m3, &exists, &is_manifest) == 0 &&
	    exists && is_manifest && m3.format_version == 3);
	CHECK(checkpoint_manifest_read_at(dirfd_, "v5.ckp", &m5, &exists, &is_manifest) == 0 &&
	    exists && is_manifest && m5.format_version == 5);
	/* Member names. */
	memset(big, 'n', NAME_MAX + 1);
	big[NAME_MAX + 1] = '\0';
	CHECK(!checkpoint_member_valid(NULL) && !checkpoint_member_valid("") &&
	    !checkpoint_member_valid(".") && !checkpoint_member_valid("..") &&
	    !checkpoint_member_valid("a/b") && !checkpoint_member_valid(big) &&
	    checkpoint_member_valid("ok"));
	/* Reading by path and by directory. */
	snprintf(path, sizeof(path), "%s/v3.ckp", dir);
	CHECK(checkpoint_manifest_read(NULL, &bad, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read(path, NULL, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read(path, &bad, NULL) == EINVAL);
	CHECK(checkpoint_manifest_read(path, &bad, &is_manifest) == 0 && is_manifest &&
	    strcmp(bad.data, m3.data) == 0);
	snprintf(path, sizeof(path), "%s/absent.ckp", dir);
	CHECK(checkpoint_manifest_read(path, &bad, &is_manifest) == ENOENT && !is_manifest);
	CHECK(checkpoint_manifest_read_at(-1, "v3.ckp", &bad, &exists, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read_at(dirfd_, NULL, &bad, &exists, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read_at(dirfd_, "v3.ckp", NULL, &exists, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read_at(dirfd_, "v3.ckp", &bad, NULL, &is_manifest) == EINVAL);
	CHECK(checkpoint_manifest_read_at(dirfd_, "v3.ckp", &bad, &exists, NULL) == EINVAL);
	/* Crafted manifest files: oversized, an overlong field value, and a
	 * read interrupted once. */
	{
		static char huge[8192];
		fd = openat(dirfd_, "huge.ckp", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(fd >= 0);
		memset(huge, 'x', sizeof(huge));
		memcpy(huge, CHECKPOINT_MANIFEST_MAGIC_V5, strlen(CHECKPOINT_MANIFEST_MAGIC_V5));
		CHECK(__real_write(fd, huge, sizeof(huge)) == (ssize_t)sizeof(huge));
		close(fd);
		CHECK(checkpoint_manifest_read_at(dirfd_, "huge.ckp", &bad, &exists, &is_manifest) == EINVAL &&
		    exists);
		fd = openat(dirfd_, "long.ckp", O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(fd >= 0);
		snprintf(huge, sizeof(huge), "%sarchitecture=%s\n", CHECKPOINT_MANIFEST_MAGIC,
		    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
		CHECK(__real_write(fd, huge, strlen(huge)) == (ssize_t)strlen(huge));
		close(fd);
		CHECK(checkpoint_manifest_read_at(dirfd_, "long.ckp", &bad, &exists, &is_manifest) == EINVAL);
		reset_points();
		strlcpy(fault_name, "read", sizeof(fault_name));
		fault_occurrence = 1;
		fault_error = EINTR;
		armed = true;
		r = checkpoint_manifest_read_at(dirfd_, "v3.ckp", &bad, &exists, &is_manifest);
		armed = false;
		fault_name[0] = '\0';
		CHECK(r == 0 && is_manifest);
	}
	/* Compatibility. */
	CHECK(!checkpoint_manifest_compatible(NULL));
	bad = m3; memset(bad.architecture, 'a', sizeof(bad.architecture));
	CHECK(!checkpoint_manifest_compatible(&bad));
	bad = m3; memset(bad.machine, 'a', sizeof(bad.machine));
	CHECK(!checkpoint_manifest_compatible(&bad));
	bad = m3; bad.format_version = 6;
	CHECK(!checkpoint_manifest_compatible(&bad));
	bad = m3; strlcpy(bad.machine, "other", sizeof(bad.machine));
	CHECK(!checkpoint_manifest_compatible(&bad));
	bad = m3; strlcpy(bad.architecture, "nope", sizeof(bad.architecture));
	CHECK(!checkpoint_manifest_compatible(&bad));
	/* Member set validity: generation member grammar. */
	CHECK(!checkpoint_manifest_valid_for(NULL, &m3) && !checkpoint_manifest_valid_for("v3.ckp", NULL));
	CHECK(!checkpoint_manifest_valid_for("", &m3) && !checkpoint_manifest_valid_for(big, &m3));
	bad = m3; bad.format_version = 6;
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; memset(bad.data, 'd', sizeof(bad.data));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; memset(bad.kern, 'k', sizeof(bad.kern));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; memset(bad.meta, 'm', sizeof(bad.meta));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; strlcpy(bad.trace, "x", sizeof(bad.trace));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; strlcpy(bad.trace_sha256, "x", sizeof(bad.trace_sha256));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; strlcpy(bad.data, "x", sizeof(bad.data));
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[strlen(bad.data) - 1] = '\0';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[0] = 'x';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[strlen("v3.ckp")] = '_';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[strlen("v3.ckp.d")] = 'x';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[strlen("v3.ckp.data")] = '_';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; bad.data[strlen(bad.data) - 1] = 'g';
	CHECK(!checkpoint_manifest_valid_for("v3.ckp", &bad));
	bad = m3; hexcase(bad.data, true); hexcase(bad.kern, true); hexcase(bad.meta, true);
	CHECK(checkpoint_manifest_valid_for("v3.ckp", &bad));	/* upper-case hex is accepted */
	bad = m5; memset(bad.trace, 't', sizeof(bad.trace));
	CHECK(!checkpoint_manifest_valid_for("v5.ckp", &bad));
	bad = m5; strlcpy(bad.trace, "x", sizeof(bad.trace));
	CHECK(!checkpoint_manifest_valid_for("v5.ckp", &bad));
	bad = m5; bad.trace[strlen(bad.trace) - 1] ^= 1;
	CHECK(!checkpoint_manifest_valid_for("v5.ckp", &bad));
	bad = m5; bad.trace[strlen(bad.trace) - 1] = bad.trace[strlen(bad.trace) - 1] == '0' ? '1' : '0';
	CHECK(!checkpoint_manifest_valid_for("v5.ckp", &bad));	/* another generation */

	CHECK(checkpoint_manifest_valid_for("v5.ckp", &m5));
	/* Generation name construction. */
	CHECK(checkpoint_generation_names(NULL, &bad, &tmp) == EINVAL);
	CHECK(checkpoint_generation_names("b", NULL, &tmp) == EINVAL);
	CHECK(checkpoint_generation_names("b", &bad, NULL) == EINVAL);
	CHECK(checkpoint_generation_names("a/b", &bad, &tmp) == EINVAL && tmp == NULL);
	big[NAME_MAX] = '\0';
	CHECK(checkpoint_generation_names(big, &bad, &tmp) == ENAMETOOLONG && tmp == NULL);
	big[212] = '\0';	/* the data member fits; the manifest temporary does not */
	CHECK(checkpoint_generation_names(big, &bad, &tmp) == ENAMETOOLONG && tmp == NULL);
	reset_points();
	strlcpy(fault_name, "asprintf", sizeof(fault_name));
	fault_occurrence = 1;
	fault_error = ENOMEM;
	armed = true;
	r = checkpoint_generation_names("ok", &bad, &tmp);
	armed = false;
	fault_name[0] = '\0';
	CHECK(r == ENOMEM && tmp == NULL);
	CHECK(checkpoint_generation_names("ok", &bad, &tmp) == 0 && tmp != NULL &&
	    checkpoint_manifest_valid_for("ok", &bad));
	free(tmp);
	tmp = NULL;
	CHECK(checkpoint_generation_names_trace("b", NULL, &tmp) == EINVAL);
	CHECK(checkpoint_generation_names_trace("b", &bad, NULL) == EINVAL);
	CHECK(checkpoint_generation_names_trace("a/b", &bad, &tmp) == EINVAL && tmp == NULL);
	CHECK(checkpoint_generation_names_fresh("a/b", &bad, &tmp) == EINVAL && tmp == NULL);
	/* Handoff identity and token. */
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", &m3, NULL, digest) == EINVAL);
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", &m3, token, NULL) == EINVAL);
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", NULL, token, digest) == EINVAL);
	bad = m3; bad.data_sha256[0] = 'z';
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", &bad, token, digest) == EINVAL);
	bad = m3; bad.kern_sha256[0] = 'z';
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", &bad, token, digest) == EINVAL);
	bad = m3; bad.meta_sha256[0] = 'z';
	CHECK(checkpoint_manifest_handoff_identity("v3.ckp", &bad, token, digest) == EINVAL);
	bad = m5; bad.trace_sha256[0] = 'z';
	CHECK(checkpoint_manifest_handoff_identity("v5.ckp", &bad, token, digest) == EINVAL);
	CHECK(checkpoint_manifest_handoff_identity("v5.ckp", &m5, token, digest) == 0);
	CHECK(checkpoint_manifest_handoff_token("v3.ckp", &m3, NULL) == EINVAL);
	bad = m3; bad.format_version = 6;
	CHECK(checkpoint_manifest_handoff_token("v3.ckp", &bad, token) == EINVAL);
	bad = m3; strlcpy(bad.data, "x", sizeof(bad.data));
	CHECK(checkpoint_manifest_handoff_token("v3.ckp", &bad, token) == EINVAL);
	CHECK(checkpoint_manifest_handoff_token("v3.ckp", &m3, token) == 0);
	/* Verified opens: descriptor-pointer aliasing and manifest guards. */
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &m3, NULL, &b, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &m3, &a, NULL, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &m3, &a, &b, NULL) == EINVAL);
	{
		int *mis = (int *)((char *)&a + 1);
		int *inside = (int *)&bad.format_version;
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, mis, &b, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, mis, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, mis) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &a, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &a) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &b) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, inside, &b, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, inside, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, inside) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, NULL) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, mis) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, NULL, &b, &c, &t) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &a) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &b) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &c) == EINVAL);
		CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, inside) == EINVAL);
	}
	CHECK(checkpoint_manifest_open_verified_at(-1, &m3, &a, &b, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, NULL, &a, &b, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &m5, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.data, "a/b", sizeof(bad.data));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.kern, "a/b", sizeof(bad.kern));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.meta, "a/b", sizeof(bad.meta));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; bad.data_sha256[0] = 'z';
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; bad.kern_sha256[0] = 'z';
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; bad.meta_sha256[0] = 'z';
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, NULL, &a, &b, &c, &t) == EINVAL);
	bad = m5; bad.format_version = 6;
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	bad = m5; strlcpy(bad.trace, "a/b", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	bad = m5; bad.trace_sha256[0] = 'z';
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	/* Members that are not distinct regular files; a manifest path that
	 * names a directory. */
	CHECK(mkdirat(dirfd_, "adir", 0700) == 0);
	CHECK(checkpoint_manifest_read_at(dirfd_, "adir", &bad, &exists, &is_manifest) == EINVAL);
	bad = m3; strlcpy(bad.data, "adir", sizeof(bad.data));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.kern, "adir", sizeof(bad.kern));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.meta, "adir", sizeof(bad.meta));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.kern, m3.data, sizeof(bad.kern));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.meta, m3.data, sizeof(bad.meta));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	bad = m3; strlcpy(bad.meta, m3.kern, sizeof(bad.meta));
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &bad, &a, &b, &c) == EINVAL);
	CHECK(checkpoint_manifest_open_verified_at(dirfd_, &m3, &a, &b, &c) == 0);
	close(a); close(b); close(c);
	/* The trace member: a directory, empty, oversized (sparse), or one of
	 * the other members under another name. */
	bad = m5; strlcpy(bad.trace, "adir", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	fd = openat(dirfd_, "empty", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0);
	close(fd);
	bad = m5; strlcpy(bad.trace, "empty", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	fd = openat(dirfd_, "sparse", O_WRONLY | O_CREAT | O_TRUNC, 0600);
	CHECK(fd >= 0 && ftruncate(fd, 64LL * 1024 * 1024 + 1) == 0);
	close(fd);
	bad = m5; strlcpy(bad.trace, "sparse", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	CHECK(linkat(dirfd_, m5.data, dirfd_, "datalink", 0) == 0);
	CHECK(linkat(dirfd_, m5.kern, dirfd_, "kernlink", 0) == 0);
	CHECK(linkat(dirfd_, m5.meta, dirfd_, "metalink", 0) == 0);
	bad = m5; strlcpy(bad.trace, "datalink", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	bad = m5; strlcpy(bad.trace, "kernlink", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	bad = m5; strlcpy(bad.trace, "metalink", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == EINVAL);
	bad = m5; strlcpy(bad.trace, "absent", sizeof(bad.trace));
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &bad, &a, &b, &c, &t) == ENOENT);
	CHECK(checkpoint_manifest_open_verified_trace_at(dirfd_, &m5, &a, &b, &c, &t) == 0);
	close(a); close(b); close(c); close(t);
	/* Publication guards. */
	CHECK(checkpoint_generation_names("pub.ckp", &bad, &tmp) == 0);
	CHECK(checkpoint_publish(dirfd_, "pub.ckp", tmp, &bad, NULL) == EINVAL);
	CHECK(checkpoint_publish(-1, "pub.ckp", tmp, &bad, &published) == EINVAL && !published);
	CHECK(checkpoint_publish(dirfd_, "a/b", tmp, &bad, &published) == EINVAL);
	CHECK(checkpoint_publish(dirfd_, "pub.ckp", tmp, NULL, &published) == EINVAL);
	CHECK(checkpoint_publish(dirfd_, "pub.ckp", "a/b", &bad, &published) == EINVAL);
	CHECK(checkpoint_publish(dirfd_, "pub.ckp", "pub.ckp.manifest.00000000000000000000000000000000.tmp",
	    &bad, &published) == EINVAL);
	CHECK(checkpoint_publish(dirfd_, "v3.ckp", tmp, &bad, &published) == EINVAL);	/* another base */
	{
		struct checkpoint_manifest incompatible = bad;
		strlcpy(incompatible.machine, "other", sizeof(incompatible.machine));
		CHECK(checkpoint_publish(dirfd_, "pub.ckp", tmp, &incompatible, &published) == EINVAL);
	}
	/* Valid names whose members do not exist: hashing fails. */
	CHECK(checkpoint_publish(dirfd_, "pub.ckp", tmp, &bad, &published) == ENOENT && !published);
	free(tmp);
	tmp = NULL;
	/* Release records: the token must be set; removal tolerates absence,
	 * reports other unlink failures (with and without errno) and a failed
	 * directory sync (with and without errno). */
	memset(token, 0, sizeof(token));
	CHECK(checkpoint_release_remove_at(dirfd_, NULL) == EINVAL);
	CHECK(checkpoint_release_remove_at(dirfd_, token) == EINVAL);
	memset(token, 0x5a, sizeof(token));
	CHECK(checkpoint_release_remove_at(dirfd_, token) == 0);	/* absent */
	{
		static const char release_name[] = ".hsa.5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
#define MAKE_RELEASE() do { int rfd = openat(dirfd_, release_name, O_WRONLY | O_CREAT, 0600); \
	CHECK(rfd >= 0 && __real_write(rfd, wire, sizeof(wire)) == (ssize_t)sizeof(wire)); close(rfd); } while (0)
		(void)wire;
		MAKE_RELEASE();
		CHECK(fchmod(dirfd_, 0500) == 0);
		CHECK(checkpoint_release_remove_at(dirfd_, token) == EACCES);
		CHECK(fchmod(dirfd_, 0700) == 0);
		fault_once("unlinkat", 1, FAULT_NOERRNO);
		r = checkpoint_release_remove_at(dirfd_, token);
		fault_clear();
		CHECK(r == EIO);
		fault_once("fsync", 1, EIO);
		r = checkpoint_release_remove_at(dirfd_, token);
		fault_clear();
		CHECK(r == EIO && faccessat(dirfd_, release_name, F_OK, 0) != 0);
		MAKE_RELEASE();
		fault_once("fsync", 1, FAULT_NOERRNO);
		r = checkpoint_release_remove_at(dirfd_, token);
		fault_clear();
		CHECK(r == EIO);
		MAKE_RELEASE();
		CHECK(checkpoint_release_remove_at(dirfd_, token) == 0);
#undef MAKE_RELEASE
	}
	printf("snapshot manifest API: guards, member grammar, trace rules, names, verified opens, publish\n");
}

/* Migration capture, commit and fresh resume: argument guards, record and
 * identity checks on capture, malformed and continuity-marked blobs on
 * commit, the admission steps of a fresh resume, and generation cleanup
 * over a previous fresh checkpoint. */
static int
fault_once(const char *name, int occurrence, int error)
{
	reset_points();
	strlcpy(fault_name, name, sizeof(fault_name));
	fault_occurrence = occurrence;
	fault_error = error;
	armed = true;
	return (0);
}

static void
fault_clear(void)
{
	armed = false;
	fault_name[0] = '\0';
}

static void
test_migration_edges(void)
{
	uint8_t *blob = NULL, record[HYPERTRACE_SESSION_RECORD_SIZE], zero[HYPERTRACE_SESSION_RECORD_SIZE];
	size_t len = 0;
	struct pci_devinst *device = NULL;
	struct vm_snapshot_capture cap = {0};
	int r;

	vm_init(&src_vm, "src", 0x73);
	devices_init();
	memset(zero, 0, sizeof(zero));
	/* Capture guards and identity checks. */
	CHECK(vm_snapshot_dev_state_to_mem(NULL, &blob, &len, &cap) == EINVAL);
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, NULL, &len, &cap) == EINVAL);
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, NULL, &cap) == EINVAL);
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, NULL) == EINVAL);
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, NULL, &blob, &len, &cap) == EINVAL);
	/* The TPM migration gate refuses before the capture is examined. */
	tpm_present = true;
	tpm_migration_error = ENOTSUP;
	cap.unresolved = true;
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == ENOTSUP);
	tpm_migration_error = 0;
	tpm_present = false;
	/* An unresolved capture is refused and cannot be finished. */
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == EBUSY);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, false) == EINVAL);
	cap.unresolved = false;
	CHECK(vm_migrate_stop_tracing(NULL, record) == EINVAL);
	CHECK(vm_migrate_stop_tracing(&src_vm, NULL) == EINVAL);
	tracing = true;
	vtdtr_present = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(vm_migrate_stop_tracing(&src_vm, record) == 0);
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, zero, &blob, &len, &cap) != 0 && blob == NULL);
	identity_error = ENXIO;
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == ENXIO);
	identity_error = FAULT_NOERRNO;
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == EIO);
	identity_vmid_delta = 1;
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == ESTALE);
	identity_vmid_delta = 0;
	identity_epoch_delta = 1;
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == ESTALE);
	identity_epoch_delta = 0;
	/* Capture: the metadata stream cannot be finished or flushed; a
	 * failed kernel fence release invalidates the capture. */
	fault_once("xo_finish_h", 1, EIO);
	r = vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap);
	fault_clear();
	CHECK(r == EIO && blob == NULL && !src_vm.session_active && !cap.active);
	fault_once("fflush", 1, EIO);
	r = vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap);
	fault_clear();
	CHECK(r == EIO && blob == NULL);
	fault_once("fflush", 1, FAULT_NOERRNO);
	r = vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap);
	fault_clear();
	CHECK(r == EIO && blob == NULL);
	/* Merged: a capture larger than one migration state is refused before
	 * its members are copied (metadata alone, or metadata plus kernel). */
	ftell_override = (long)MIGRATION_MAX_DEV_STATE;
	r = vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap);
	ftell_override = -1;
	CHECK(r == EMSGSIZE && blob == NULL && !cap.active && !src_vm.session_active);
	lseek_end_override = (off_t)MIGRATION_MAX_DEV_STATE;
	r = vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap);
	lseek_end_override = -1;
	CHECK(r == EMSGSIZE && blob == NULL && !cap.active && !src_vm.session_active);
	CHECK(vm_snapshot_fresh_dev_state_to_mem(&src_vm, record, &blob, &len, &cap) == 0 && blob != NULL);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, true) == 0);
	/* Commit guards and malformed blobs. */
	vm_init(&dst_vm, "dst", 0x73);
	side = 1;
	state = dst_state;
	checkpoint_restore_startup_hold();
	CHECK(vm_migrate_fresh_commit_state(NULL, blob, len, &device) == EINVAL);
	CHECK(vm_migrate_fresh_commit_state(&dst_vm, NULL, len, &device) == EINVAL);
	CHECK(vm_migrate_fresh_commit_state(&dst_vm, blob, MIGRATE_BLOB_HDR - 1, &device) == EINVAL);
	{
		uint8_t *bad = __real_malloc(len);
		memcpy(bad, blob, len);
		le64enc(bad, len);	/* metadata longer than the blob */
		CHECK(vm_migrate_fresh_commit_state(&dst_vm, bad, len, &device) == EBADMSG);
		memcpy(bad, blob, len);
		CHECK(vm_migrate_fresh_commit_state(&dst_vm, bad, len - 1, &device) == EBADMSG);
		/* A continuity marker (handoff version 1) inside the metadata. */
		memcpy(bad, blob, len);
		{
			char *text = (char *)bad + MIGRATE_BLOB_HDR, *key;
			size_t mlen = (size_t)le64dec(bad);
			char saved = text[mlen];
			text[mlen] = '\0';
			key = strstr(text, "\"hypertrace_handoff_version\": 2");
			CHECK(key != NULL);
			key[strlen("\"hypertrace_handoff_version\": ")] = '1';
			text[mlen] = saved;
		}
		/* A fresh image must carry handoff version 2. */
		CHECK(vm_migrate_fresh_commit_state(&dst_vm, bad, len, &device) == EPROTO);
		CHECK(checkpoint_restore_startup_held() && !dst_vm.session_active);
		free(bad);
	}
	/* A fresh commit on a destination without a DTrace device. */
	vtdtr_present = false;
	CHECK(vm_migrate_fresh_commit_state(&dst_vm, blob, len, &device) == EPROTO);
	CHECK(checkpoint_restore_startup_held() && !dst_vm.session_active);
	vtdtr_present = true;
	/* The commit, then every refusal of the fresh resume. */
	CHECK(vm_migrate_fresh_commit_state(&dst_vm, blob, len, &device) == 0 && device != NULL);
	CHECK(vm_migrate_fresh_resume(NULL, device, record) == EINVAL);
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, NULL) == EINVAL);
	start_ready_error = EACCES;
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, record) == EACCES);
	start_ready_error = FAULT_NOERRNO;
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, record) == EIO);
	start_ready_error = 0;
	replay_fake_count = 1;
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, record) == EPROTO);
	replay_fake_count = 0;
	fault_once("hypertrace_take_replay_kills", 1, EIO);
	r = vm_migrate_fresh_resume(&dst_vm, device, record);
	fault_clear();
	CHECK(r == EIO);
	fault_once("vm_restore_time", 1, EIO);
	r = vm_migrate_fresh_resume(&dst_vm, device, record);
	fault_clear();
	CHECK(r == EIO);
	fault_once("vm_restore_time", 1, FAULT_NOERRNO);
	r = vm_migrate_fresh_resume(&dst_vm, device, record);
	fault_clear();
	CHECK(r == EIO);
	fault_once("vm_resume_all_cpus", 1, FAULT_NOERRNO);
	r = vm_migrate_fresh_resume(&dst_vm, device, record);
	fault_clear();
	CHECK(r == EIO && checkpoint_restore_startup_held());
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, record) == 0);
	CHECK(!checkpoint_restore_startup_held());
	CHECK(vm_migrate_fresh_resume(&dst_vm, device, record) == EBUSY);	/* fence released */
	free(blob);
	blob = NULL;
	side = 0;
	state = src_state;
	/* A legacy blob with a continuity marker, and one claiming a fresh
	 * record (version 2) without the fresh format. */
	tracing = false;
	vtdtr_present = false;
	vm_init(&src_vm, "src", 0x74);
	devices_init();
	memset(&cap, 0, sizeof(cap));
	CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == 0);
	CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, false) == 0);
	vm_init(&dst_vm, "dst", 0x74);
	side = 1;
	state = dst_state;
	checkpoint_restore_startup_hold();
	for (int v = 1; v <= 3; v++) {
		uint8_t *bad = __real_malloc(len);
		char *text = (char *)bad + MIGRATE_BLOB_HDR, *key;
		size_t mlen;
		char saved;
		memcpy(bad, blob, len);
		mlen = (size_t)le64dec(bad);
		saved = text[mlen];
		text[mlen] = '\0';
		key = strstr(text, "\"hypertrace_handoff_version\": 0");
		CHECK(key != NULL);
		key[strlen("\"hypertrace_handoff_version\": ")] = (char)('0' + v);
		text[mlen] = saved;
		r = vm_migrate_commit_state(&dst_vm, bad, len);
		CHECK(r == (v == 1 ? EOPNOTSUPP : v == 2 ? EPROTO : EINVAL));
		CHECK(checkpoint_restore_startup_held() && !dst_vm.session_active);
		free(bad);
	}
	CHECK(vm_migrate_commit_state(&dst_vm, blob, len) == 0);
	fault_once("vm_restore_time", 1, FAULT_NOERRNO);
	r = vm_migrate_resume(&dst_vm);
	fault_clear();
	CHECK(r == EIO);
	fault_once("vm_resume_all_cpus", 1, FAULT_NOERRNO);
	r = vm_migrate_resume(&dst_vm);
	fault_clear();
	CHECK(r == EIO && checkpoint_restore_startup_held());
	CHECK(vm_migrate_resume(&dst_vm) == 0);
	free(blob);
	side = 0;
	state = src_state;
	/* Device snapshot extra capacity: a failing hook, an oversized request,
	 * and a working large buffer that round-trips. */
	fresh_dir();
	vm_init(&src_vm, "src", 0x75);
	devices_init();
	extra_capacity_error = EIO;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "x.ckp", false) == EIO);
	extra_capacity_error = 0;
	extra_capacity_value = (size_t)SNAPSHOT_DEVICE_EXTRA_MAX + 1;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "x.ckp", false) == E2BIG);
	extra_capacity_value = 4096;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "x.ckp", false) == 0);
	CHECK(restore_into_destination("x.ckp", true) == 0);
	extra_capacity_value = 0;
	/* A device restore that leaves trailing state is refused. */
	restore_short = true;
	CHECK(restore_into_destination("x.ckp", false) != 0);
	restore_short = false;
	/* Generation cleanup over a previous fresh checkpoint: its trace member
	 * is removed too; an already-missing member is tolerated. */
	tracing = true;
	vtdtr_present = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(checkpoint_stop_vm("gen.ckp") == 0);
	{
		struct checkpoint_manifest m;
		bool exists, is_manifest;
		CHECK(checkpoint_manifest_read_at(dirfd_, "gen.ckp", &m, &exists, &is_manifest) == 0 &&
		    is_manifest && m.format_version == 5);
		CHECK(unlinkat(dirfd_, m.kern, 0) == 0);	/* vanished member */
		vm_init(&src_vm, "src", 0x76);
		devices_init();
		CHECK(checkpoint_stop_vm("gen.ckp") == 0);
		CHECK(faccessat(dirfd_, m.data, F_OK, 0) != 0 && faccessat(dirfd_, m.trace, F_OK, 0) != 0);
	}
	tracing = false;
	vtdtr_present = false;
	printf("snapshot migration edges: capture identity, blob decoding, fresh resume, extra capacity, cleanup\n");
}

/* An interrupted read is retried at every read site of a restore load. */
static void
test_read_eintr(void)
{
	struct restore_state rstate;
	char path[400];
	int failures = 0;

	fresh_dir();
	vm_init(&src_vm, "src", 0x77);
	devices_init();
	tracing = true;
	vtdtr_present = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(checkpoint_stop_vm("e.ckp") == 0);
	tracing = false;
	vtdtr_present = false;
	snprintf(path, sizeof(path), "%s/e.ckp", dir);
	for (int occ = 1; occ <= 24; occ++) {
		int r;
		fault_once("read", occ, EINTR);
		r = load_restore_file(path, &rstate);
		fault_clear();
		if (r != 0) {
			failures++;
			fprintf(stderr, "read EINTR at occurrence %d: load failed\n", occ);
		} else
			destroy_restore_state(&rstate);
	}
	CHECK(failures == 0);
	printf("snapshot read EINTR: 24 occurrences retried\n");
}

/* Progress output on a terminal: the bar is drawn for the saved and
 * restored memory; a narrow window skips the bar; a failed progress write
 * only silences progress while a failed memory write fails the checkpoint.
 * Oracles: the checkpoint result and the restored state. */
static void
test_progress_tty(void)
{
	int silenced = 0, failed = 0;

	fresh_dir();
	vm_init(&src_vm, "src", 0x78);
	devices_init();
	fake_tty = true;
	fake_cols = 80;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tty.ckp", false) == 0);
	CHECK(restore_into_destination("tty.ckp", true) == 0);
	fake_cols = 2;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tty2.ckp", false) == 0);
	fake_cols = 5;		/* a bar narrower than its prefix */
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tty5.ckp", false) == 0);
	fake_cols = 65535;	/* wider than the progress buffer */
	CHECK(vm_checkpoint(&src_vm, dirfd_, "ttyw.ckp", false) == 0);
	fake_cols = 0;		/* a terminal without a known width */
	CHECK(vm_checkpoint(&src_vm, dirfd_, "tty0.ckp", false) == 0);
	fake_cols = 80;
	/* Memory reads on restore: interrupted reads are retried; a read that
	 * makes no progress fails the restore. */
	{
		int stalled = 0;
		for (int occ = 1; occ <= 12; occ++) {
			int r;
			fault_once("read", occ, EINTR);
			r = restore_into_destination("tty.ckp", true);
			fault_clear();
			CHECK(r == 0);
			/* A read returning 0 is either the natural end of a file
			 * (no effect: the restore is still exact) or a stall that
			 * fails the restore; never a wrong restore. */
			fault_once("read", occ, FAULT_ZERO);
			r = restore_into_destination("tty.ckp", true);
			fault_clear();
			if (r != 0)
				stalled++;
		}
		CHECK(stalled > 0);
		/* Errno-less read and seek failures: a failure that is seen refuses
		 * the restore; one that a reader tolerates (the parser reading to
		 * the end) still leaves an exact restore, never a wrong one. */
		{
			int refused = 0;
			for (int occ = 1; occ <= 40; occ++) {
				int r;
				fault_once("read", occ, FAULT_NOERRNO);
				r = restore_into_destination("tty.ckp", true);
				fault_clear();
				refused += r != 0;
				fault_once("lseek", occ, FAULT_NOERRNO);
				r = restore_into_destination("tty.ckp", true);
				fault_clear();
				refused += r != 0;
			}
			CHECK(refused > 0);
			printf("snapshot errno-less read/seek faults on restore: %d of 80 refused\n", refused);
		}
	}
	for (int occ = 1; occ <= 40; occ++) {
		int r;

		fault_once("write", occ, EIO);
		r = vm_checkpoint(&src_vm, dirfd_, "ttyf.ckp", false);
		fault_clear();
		if (r == 0) {
			silenced++;	/* the fault hit a progress write */
			CHECK(restore_into_destination("ttyf.ckp", true) == 0);
		} else
			failed++;
		fault_once("write", occ, EINTR);
		r = vm_checkpoint(&src_vm, dirfd_, "ttye.ckp", false);
		fault_clear();
		CHECK(r == 0);
		fault_once("write", occ, FAULT_ZERO);
		r = vm_checkpoint(&src_vm, dirfd_, "ttyz.ckp", false);
		fault_clear();
		if (r == 0)
			CHECK(restore_into_destination("ttyz.ckp", true) == 0);
	}
	CHECK(silenced > 0 && failed > 0);
	fake_tty = false;
	printf("snapshot progress on a terminal: %d progress writes silenced, %d memory writes failed\n",
	    silenced, failed);
}

/* Lookups and preflights called directly with invalid arguments or a
 * loaded image whose metadata was altered on disk. */
static void
mutate_meta(const char *key, const char *replacement, bool rename)
{
	char *meta, *hit, *mutated;
	size_t len, mlen, prefix, vlen;
	char needle[128];

	meta = slurp(good_manifest.meta, &len);
	snprintf(needle, sizeof(needle), "\"%s\": ", key);
	hit = strstr(meta, needle);
	CHECK(hit != NULL);
	mutated = __real_malloc(len + 256);
	if (rename) {
		memcpy(mutated, meta, len);
		mutated[(size_t)(hit - meta) + 1] ^= 0x20;
		mlen = len;
	} else {
		const char *value = hit + strlen(needle), *end = value;
		while (*end != '\n' && *end != '\0')
			end++;
		vlen = (size_t)(end - value);
		if (vlen > 0 && value[vlen - 1] == ',')
			vlen--;
		prefix = (size_t)(value - meta);
		memcpy(mutated, meta, prefix);
		mlen = prefix;
		memcpy(mutated + mlen, replacement, strlen(replacement));
		mlen += strlen(replacement);
		memcpy(mutated + mlen, value + vlen, len - prefix - vlen);
		mlen += len - prefix - vlen;
	}
	spill(good_manifest.meta, mutated, mlen);	/* the caller rehashes its manifest */
	free(meta);
	free(mutated);
}


/*
 * Merged checkpoint vCPU fence and restore-compatibility helpers.  Oracles:
 * argument and state refusals; a failed suspend whose resume works leaves
 * the guest runnable and the fence released, one whose resume fails keeps
 * the fence owned; a failed kernel resume keeps the userspace gate closed.
 */
static void
test_merged_helpers(void)
{
	bool runnable, owned;

	vm_init(&src_vm, "src", 0x5e);
	devices_init();
	checkpoint_active = false;
	restore_startup_hold = false;
	CPU_ZERO(&vcpus_active);
	CPU_ZERO(&vcpus_suspended);
	CHECK(checkpoint_vcpu_pause(NULL, &runnable, &owned) == EINVAL);
	CHECK(checkpoint_vcpu_pause(&src_vm, NULL, &owned) == EINVAL);
	CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, NULL) == EINVAL);
	checkpoint_active = true;
	CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, &owned) == EBUSY && !owned && !runnable);
	checkpoint_active = false;
	suspend_error = ENXIO;
	CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, &owned) == ENXIO);
	CHECK(runnable && !owned && !checkpoint_active);
	suspend_error = FAULT_NOERRNO;
	CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, &owned) == EIO && runnable);
	suspend_error = EIO;
	fault_once("vm_resume_all_cpus", 1, EIO);
	CHECK(checkpoint_vcpu_pause(&src_vm, &runnable, &owned) == EIO);
	fault_clear();
	CHECK(!runnable && owned && checkpoint_active);
	suspend_error = 0;
	/* Resume refusals and a failed kernel resume. */
	CHECK(checkpoint_vcpu_resume(NULL) == EINVAL);
	restore_startup_hold = true;
	CHECK(checkpoint_vcpu_resume(&src_vm) == EINVAL && checkpoint_active);
	restore_startup_hold = false;
	fault_once("vm_resume_all_cpus", 1, EBUSY);
	CHECK(checkpoint_vcpu_resume(&src_vm) == EBUSY && checkpoint_active);
	fault_clear();
	fault_once("vm_resume_all_cpus", 1, FAULT_NOERRNO);
	CHECK(checkpoint_vcpu_resume(&src_vm) == EIO && checkpoint_active);
	fault_clear();
	CHECK(checkpoint_vcpu_resume(&src_vm) == 0 && !checkpoint_active);
	CHECK(checkpoint_vcpu_resume(&src_vm) == EINVAL);	/* not paused */
	CHECK(checkpoint_restore_cpu_contract(NULL, NULL) == EINVAL);
	/* Restore compatibility: the previous machine ABI is admitted only on
	 * opt-in, with canonical padding; other ABIs never. */
	{
		struct checkpoint_manifest m, prev;
		char *tmp = NULL;
		CHECK(checkpoint_generation_names("vm.ckp", &m, &tmp) == 0);
		free(tmp);
		CHECK(!checkpoint_manifest_restore_compatible(NULL, true));
		CHECK(checkpoint_manifest_restore_compatible(&m, false));
		prev = m;
		memset(prev.machine, 0, sizeof(prev.machine));
		strlcpy(prev.machine, CHECKPOINT_MACHINE_ABI_PREVIOUS, sizeof(prev.machine));
		CHECK(!checkpoint_manifest_compatible(&prev));
		CHECK(!checkpoint_manifest_restore_compatible(&prev, false));
		CHECK(checkpoint_manifest_restore_compatible(&prev, true));
		prev.machine[sizeof(prev.machine) - 1] = 'x';	/* padding */
		CHECK(!checkpoint_manifest_restore_compatible(&prev, true));
		memset(prev.machine, 0, sizeof(prev.machine));
		strlcpy(prev.machine, "bhyve-virtio-v1", sizeof(prev.machine));
		CHECK(!checkpoint_manifest_restore_compatible(&prev, true));
		memset(prev.machine, 0, sizeof(prev.machine));
		strlcpy(prev.machine, "bhyve-virtio-v22", sizeof(prev.machine));
		CHECK(!checkpoint_manifest_restore_compatible(&prev, true));
		/* A current manifest with non-zero padding is not compatible. */
		prev = m;
		prev.architecture[sizeof(prev.architecture) - 1] = 'x';
		CHECK(!checkpoint_manifest_compatible(&prev));
		prev = m;
		prev.machine[sizeof(prev.machine) - 1] = 'x';
		CHECK(!checkpoint_manifest_compatible(&prev));
		/* An older format with the previous ABI stays refused. */
		prev = m;
		prev.format_version = 2;
		memset(prev.machine, 0, sizeof(prev.machine));
		strlcpy(prev.machine, CHECKPOINT_MACHINE_ABI_PREVIOUS, sizeof(prev.machine));
		CHECK(!checkpoint_manifest_restore_compatible(&prev, true));
	}
	/* Migration commit: the TPM gate and the state-size limit come first. */
	{
		uint8_t blob[64] = {0};
		struct pci_devinst *device = NULL;
		tpm_present = true;
		tpm_migration_error = ENOTSUP;
		CHECK(vm_migrate_commit_state(&src_vm, blob, sizeof(blob)) == ENOTSUP);
		tpm_migration_error = 0;
		tpm_present = false;
		CHECK(vm_migrate_fresh_commit_state(&src_vm, blob,
		    (size_t)MIGRATION_MAX_DEV_STATE + 1, &device) == EMSGSIZE && device == NULL);
	}
	/* A capture whose fence release never resolves becomes unresolved. */
	{
		static const int release_eio[] = { EIO, EIO, EIO, EIO, EIO, EIO };
		struct vm_snapshot_capture cap = {0};
		uint8_t *blob = NULL;
		size_t len = 0;
		tracing = false;
		vtdtr_present = false;
		CHECK(vm_snapshot_dev_state_to_mem(&src_vm, &blob, &len, &cap) == 0);
		free(blob);
		script(release_eio, 6);
		CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, true) == EIO);
		session_script = NULL;
		CHECK(cap.unresolved && cap.active);
		CHECK(vm_snapshot_dev_state_finish(&src_vm, &cap, true) == EINVAL);
		src_vm.session_active = false;
	}
	printf("snapshot merged helpers: vCPU fence, restore compatibility, commit gates\n");
}

static void
test_lookup_guards(void)
{
	struct restore_state rstate;
	struct restore_state blank;
	char path[400], *meta;
	size_t len;
	int ncpus;
	uint16_t sockets, cores, threads, domains[8];
	uint64_t sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
	size_t count;
	int r;

	fresh_dir();
	vm_init(&src_vm, "src", 0x79);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "vm.ckp", false) == 0);
	{
		bool exists, is_manifest;
		CHECK(checkpoint_manifest_read_at(dirfd_, "vm.ckp", &good_manifest, &exists,
		    &is_manifest) == 0);
	}
	snprintf(path, sizeof(path), "%s/vm.ckp", dir);
	memset(&blank, 0, sizeof(blank));
	CHECK(lookup_guest_ncpus(&blank) == 0);
	CHECK(lookup_memsize(&blank) == 0);
	CHECK(lookup_cpu_topology(&blank, &ncpus, &sockets, &cores, &threads) == EINVAL);
	CHECK(lookup_cpu_topology(NULL, &ncpus, &sockets, &cores, &threads) == EINVAL);
	CHECK(lookup_cpu_topology(&blank, NULL, &sockets, &cores, &threads) == EINVAL);
	CHECK(lookup_cpu_topology(&blank, &ncpus, NULL, &cores, &threads) == EINVAL);
	CHECK(lookup_cpu_topology(&blank, &ncpus, &sockets, NULL, &threads) == EINVAL);
	CHECK(lookup_cpu_topology(&blank, &ncpus, &sockets, &cores, NULL) == EINVAL);
	CHECK(lookup_numa_topology(NULL, 2, LOWMEM + HIGHMEM, sizes, &count, domains) == EINVAL);
	CHECK(lookup_numa_topology(&blank, 2, LOWMEM + HIGHMEM, NULL, &count, domains) == EINVAL);
	CHECK(lookup_numa_topology(&blank, 2, LOWMEM + HIGHMEM, sizes, NULL, domains) == EINVAL);
	CHECK(lookup_numa_topology(&blank, 2, LOWMEM + HIGHMEM, sizes, &count, NULL) == EINVAL);
	CHECK(lookup_numa_topology(&blank, 2, LOWMEM + HIGHMEM, sizes, &count, domains) == EINVAL);
	CHECK(vm_restore_memory_preflight(NULL, &blank) == EINVAL);
	CHECK(vm_restore_memory_preflight(&src_vm, NULL) == EINVAL);
	{
		int flags;
		struct checkpoint_cpu_contract contract;
		struct checkpoint_memory_geometry geometry;
		CHECK(lookup_memflags(NULL, &flags) == EINVAL);
		CHECK(lookup_memflags(&blank, NULL) == EINVAL);
		CHECK(lookup_memflags(&blank, &flags) == EINVAL);
		CHECK(lookup_cpu_contract(NULL, &contract) == EINVAL);
		CHECK(lookup_cpu_contract(&blank, NULL) == EINVAL);
		CHECK(lookup_cpu_contract(&blank, &contract) == EINVAL);
		CHECK(lookup_memory_geometry(NULL, &geometry) == EINVAL);
		CHECK(lookup_memory_geometry(&blank, NULL) == EINVAL);
		CHECK(lookup_memory_geometry(&blank, &geometry) == EINVAL);
	}
	/* A loaded image whose RAM member is shorter than its memsize. */
	CHECK(load_restore_file(path, &rstate) == 0);
	{
		size_t saved = rstate.vmmem_len;
		rstate.vmmem_len = 1;
		CHECK(vm_restore_memory_preflight(&src_vm, &rstate) == EINVAL);
		rstate.vmmem_len = saved;
		CHECK(vm_restore_memory_preflight(&src_vm, &rstate) == 0);
	}
	destroy_restore_state(&rstate);
	/* Metadata edits and the lookups bhyverun performs on them. */
	meta = slurp(good_manifest.meta, &len);
	{
		static const struct { const char *key, *value; bool rename; int ncpus; } rows[] = {
			{ "ncpus", "0", false, 0 },
			{ "ncpus", "4294967297", false, 0 },
			{ "ncpus", "\"x\"", false, 0 },
			{ "ncpus", NULL, true, 0 },
			{ "memsize", "0", false, -1 },
			{ "memsize", "\"x\"", false, -1 },
			{ "memsize", NULL, true, -1 },
			{ "numa_topology_version", "\"x\"", false, -1 },
			{ "numa_topology_version", NULL, true, -1 },
			{ "cpu_sockets", NULL, true, -1 },
			{ "cpu_sockets", "\"x\"", false, -1 },
		};
		for (size_t i = 0; i < nitems(rows); i++) {
			spill(good_manifest.meta, meta, len);
			mutate_meta(rows[i].key, rows[i].value, rows[i].rename);
			rehash("meta", good_manifest.meta);
			CHECK(load_restore_file(path, &rstate) == 0);
			if (strcmp(rows[i].key, "ncpus") == 0)
				CHECK(lookup_guest_ncpus(&rstate) == rows[i].ncpus);
			else if (strcmp(rows[i].key, "memsize") == 0)
				CHECK(lookup_memsize(&rstate) == 0);
			else if (strcmp(rows[i].key, "numa_topology_version") == 0)
				CHECK(lookup_numa_topology(&rstate, 2, LOWMEM + HIGHMEM, sizes, &count, domains) == EINVAL);
			else
				CHECK(lookup_cpu_topology(&rstate, &ncpus, &sockets, &cores, &threads) == EINVAL);
			destroy_restore_state(&rstate);
		}
		/* A zero memsize passes the record validators and is refused by
		 * the memory preflight inside the transaction. */
		spill(good_manifest.meta, meta, len);
		mutate_meta("memsize", "0", false);
		rehash("meta", good_manifest.meta);
		CHECK(restore_into_destination("vm.ckp", false) == EINVAL);
		spill(good_manifest.meta, meta, len);
		rehash("meta", good_manifest.meta);
		CHECK(load_restore_file(path, &rstate) == 0);
		CHECK(lookup_guest_ncpus(&rstate) == 2);
		destroy_restore_state(&rstate);
	}
	free(meta);
	/* Records that leave bytes behind: a kernel record and a validator. */
	kern_restore_short = true;
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	kern_restore_short = false;
	validate_short = true;
	CHECK(restore_into_destination("vm.ckp", false) != 0);
	validate_short = false;
	/* A destination TPM that cannot migrate refuses before any mutation. */
	tpm_present = true;
	tpm_migration_error = ENOTSUP;
	CHECK(restore_into_destination("vm.ckp", false) == ENOTSUP);
	tpm_migration_error = 0;
	tpm_present = false;
	/* The startup fence released during a plain checkpoint: no hold. */
	release_fence_on_pause = true;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "nofence.ckp", false) == 0);
	CHECK(release_fence_result == EINVAL);
	/* An existing manifest under this name that belongs to another base. */
	{
		char *text = slurp("vm.ckp", &len);
		spill("other.ckp", text, len);
		free(text);
		CHECK(vm_checkpoint(&src_vm, dirfd_, "other.ckp", false) == EINVAL);
	}
	/* Kernel session release that never proves release, and a release
	 * failure after an earlier error, during a checkpoint and a capture. */
	{
		static const int stuck[] = { 0, EIO, EIO, EIO, EIO, EIO, EIO };
		static const int release_fails[] = { 0, EIO, EIO, EIO, EIO, EIO, EIO };
		static const int noerrno_begin[] = { FAULT_NOERRNO };
		static const int noerrno_retry[] = { EFAULT, FAULT_NOERRNO, ESTALE };
		static const int noerrno_release[] = { 0, FAULT_NOERRNO, 0 };
		static const int noerrno_release2[] = { 0, EIO, FAULT_NOERRNO, 0 };
		uint8_t *blob = NULL;
		size_t blen = 0;
		struct vm_snapshot_session sess;
		bool resolved, released;

		script(stuck, 7);
		r = vm_checkpoint(&src_vm, dirfd_, "stuck.ckp", false);
		session_script = NULL;
		CHECK(r == EIO && src_vm.suspended);
		checkpoint_active = false;
		src_vm.session_active = false;
		src_vm.suspended = false;
		script(release_fails, 7);
		fault_once("xo_finish_h", 1, EIO);
		r = vm_checkpoint(&src_vm, dirfd_, "rel.ckp", false);
		fault_clear();
		session_script = NULL;
		CHECK(r == EIO);
		checkpoint_active = false;
		src_vm.session_active = false;
		src_vm.suspended = false;
		{
			/* A failed capture whose fence release also fails leaves the
			 * capture unresolved: it is neither reusable nor finishable. */
			struct vm_snapshot_capture failed = {0};
			script(release_fails, 7);
			fault_once("xo_finish_h", 1, EIO);
			r = vm_snapshot_dev_state_to_mem(&src_vm, &blob, &blen, &failed);
			fault_clear();
			session_script = NULL;
			CHECK(r == EIO && blob == NULL && failed.active && failed.unresolved);
			CHECK(vm_snapshot_dev_state_finish(&src_vm, &failed, false) == EINVAL);
			src_vm.session_active = false;
		}
		/* Errno-less kernel replies. */
		script(noerrno_begin, 1);
		CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, &resolved) == EIO);
		script(noerrno_retry, 3);
		CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, &resolved) == EFAULT);
		session_script = NULL;
		src_vm.session_active = false;
		script(noerrno_release, 3);
		CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, &resolved) == 0);
		CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, true, &released) == EIO && released);
		session_script = NULL;
		src_vm.session_active = false;
		script(noerrno_release2, 4);
		CHECK(vm_snapshot_session_begin_exact(&src_vm, &sess, &resolved) == 0);
		CHECK(vm_snapshot_session_release_exact(&src_vm, &sess, true, &released) == EIO);
		session_script = NULL;
		src_vm.session_active = false;
	}
	/* Second faults while the checkpoint already failed: the stream flush
	 * or close, the member closes, the resume of the devices. */
	{
		static const char *const seconds[] = { "fflush", "fclose", "close", "pci_resume" };
		for (size_t i = 0; i < nitems(seconds); i++) {
			strlcpy(fault2_name, seconds[i], sizeof(fault2_name));
			fault2_occurrence = 0;
			fault2_error = EIO;
			fault_once("xo_finish_h", 1, EIO);
			r = vm_checkpoint(&src_vm, dirfd_, "two.ckp", false);
			fault_clear();
			fault2_name[0] = '\0';
			CHECK(r == EIO);
			if (strcmp(seconds[i], "pci_resume") == 0) {
				/* The devices stayed paused; release them. */
				for (int d = 0; d < 2; d++)
					state[d].paused = false;
				src_vm.suspended = false;
				checkpoint_active = false;
			}
		}
		/* A fresh checkpoint whose trace member cannot be created, with
		 * every close failing: the metadata descriptor's close error is
		 * not the reported one. */
		tracing = true;
		vtdtr_present = true;
		{
			int before = 0;
			reset_points();
			strlcpy(fault_name, "openat", sizeof(fault_name));
			fault_occurrence = 0;	/* calibrated below */
			fault_error = 0;
			armed = true;
			recording = true;
			nseen = 0;
			CHECK(checkpoint_stop_vm("calib.ckp") == 0);
			recording = false;
			armed = false;
			for (int k = 0; k < nseen; k++)
				if (strcmp(seen[k].name, "openat") == 0)
					before = seen[k].last;
			CHECK(before >= 4);
			vm_init(&src_vm, "src", 0x7c);
			devices_init();
			stop_status_busy = 0;
			collectors_remaining = 0;
			strlcpy(fault2_name, "close", sizeof(fault2_name));
			fault2_occurrence = 0;
			fault2_error = EIO;
			/* The trace member is the fourth generation member opened
			 * (lock, kern, data, meta, trace). */
			fault_once("openat", 5, ENOSPC);
			r = checkpoint_stop_vm("trace.ckp");
			fault_clear();
			fault2_name[0] = '\0';
			CHECK(r == ENOSPC);
			strlcpy(fault2_name, "close", sizeof(fault2_name));
			fault2_occurrence = 0;
			fault2_error = EIO;
			fault_once("xo_finish_h", 1, EIO);
			r = checkpoint_stop_vm("trace2.ckp");
			fault_clear();
			fault2_name[0] = '\0';
			CHECK(r == EIO);
		}
		tracing = false;
		vtdtr_present = false;
	}
	/* IPC: a request without the suspend flag or the directory. */
	{
		nvlist_t *request = nvlist_create(0), *reply;
		nvlist_add_string(request, "filename", "ipc2.ckp");
		reply = ipc_lookup("checkpoint")(&src_vm, request);
		CHECK(nvlist_exists_string(reply, "error"));
		nvlist_destroy(reply);
		nvlist_add_bool(request, "suspend", false);
		reply = ipc_lookup("checkpoint")(&src_vm, request);
		CHECK(nvlist_exists_string(reply, "error"));
		nvlist_destroy(reply);
		nvlist_destroy(request);
	}
	/* Buffer helpers on a restore buffer that is too short. */
	{
		uint8_t tiny[1];
		struct vm_snapshot_meta load = { .buffer = { .buf_start = tiny, .buf_size = 1,
		    .buf = tiny, .buf_rem = 1 }, .op = VM_SNAPSHOT_RESTORE };
		uint32_t v32;
		uint64_t v64;
		int nn;
		CHECK(vm_snapshot_le32(&v32, &load) != 0);
		load.buffer.buf = tiny; load.buffer.buf_rem = 1;
		CHECK(vm_snapshot_le64(&v64, &load) != 0);
		load.buffer.buf = tiny; load.buffer.buf_rem = 1;
		CHECK(vm_snapshot_nonnegative_int(&nn, &load) != 0);
	}
	/* A device whose compatibility record cannot be produced on restore. */
	compat_error = EIO;
	CHECK(restore_into_destination("vm.ckp", false) == EIO);
	compat_error = 0;
	/* A recorded machine digest that is canonical but not the source's. */
	meta = slurp(good_manifest.meta, &len);
	{
		char wrong[80];
		memset(wrong, 'a', 64);
		wrong[64] = '\0';
		snprintf(path, sizeof(path), "\"%s\"", wrong);
		mutate_meta("machine_topology_digest", path, false);
		rehash("meta", good_manifest.meta);
		CHECK(restore_into_destination("vm.ckp", false) == EINVAL);
		/* A compatibility schema recorded for a device that has none. */
		spill(good_manifest.meta, meta, len);
		{
			char *text = slurp(good_manifest.meta, &(size_t){0}), *hit, *out;
			size_t tlen = strlen(text), at;
			static const char insert[] = "\"compat_schema\": 1,\n";
			hit = strstr(text, "\"device\": \"plain0\"");
			CHECK(hit != NULL);
			hit = strchr(hit, '\n');
			CHECK(hit != NULL);
			at = (size_t)(hit + 1 - text);
			out = __real_malloc(tlen + sizeof(insert));
			memcpy(out, text, at);
			memcpy(out + at, insert, strlen(insert));
			memcpy(out + at + strlen(insert), text + at, tlen - at);
			spill(good_manifest.meta, out, tlen + strlen(insert));
			rehash("meta", good_manifest.meta);
			CHECK(restore_into_destination("vm.ckp", false) == ENOTSUP);
			free(out);
			free(text);
		}
		spill(good_manifest.meta, meta, len);
		rehash("meta", good_manifest.meta);
	}
	free(meta);
	snprintf(path, sizeof(path), "%s/vm.ckp", dir);
	/* The destination's device compatibility differs from the source's. */
	compat_variant = 1;
	CHECK(restore_into_destination("vm.ckp", false) == ENOTSUP);
	compat_variant = 0;
	/* A destination device without a complete restore validator. */
	emu_plain.pe_snapshot_validate = NULL;
	CHECK(restore_into_destination("vm.ckp", false) == ENOTSUP);
	emu_plain.pe_snapshot_validate = fake_validate;
	/* Without the firmware configuration device the image omits it. */
	fwcfg_on = false;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "nofw.ckp", false) == 0);
	CHECK(restore_into_destination("nofw.ckp", false) == 0);
	fwcfg_on = true;
	/* A name whose lock file name would exceed NAME_MAX. */
	{
		char longish[NAME_MAX];
		memset(longish, 'n', NAME_MAX - 3);
		longish[NAME_MAX - 3] = '\0';
		CHECK(vm_checkpoint(&src_vm, dirfd_, longish, false) == ENAMETOOLONG);
	}
	/* Capture shapes of the DTrace device's private image on a fresh
	 * restore: incomplete, absent, empty, outside the record, too long;
	 * and two devices both claiming the image. */
	tracing = true;
	vtdtr_present = true;
	stop_status_busy = 0;
	collectors_remaining = 0;
	CHECK(checkpoint_stop_vm("cap.ckp") == 0);
	for (int shape = 1; shape <= 7; shape++) {
		struct restore_state rs;
		int r;
		snprintf(path, sizeof(path), "%s/cap.ckp", dir);
		if (shape == 7)
			vtdtr_both = true;
		else
			capture_shape = shape;
		CHECK(load_restore_file(path, &rs) == 0);
		vm_init(&dst_vm, "dst", 0x99);
		side = 1;
		state = dst_state;
		checkpoint_restore_startup_hold();
		r = vm_restore_transaction(&dst_vm, &rs);
		capture_shape = 0;
		vtdtr_both = false;
		CHECK(r == (shape == 1 ? EOPNOTSUPP : EPROTO));
		CHECK(checkpoint_restore_startup_held() && !dst_vm.session_active);
		(void)checkpoint_restore_startup_release();
		destroy_restore_state(&rs);
		side = 0;
		state = src_state;
	}
	tracing = false;
	vtdtr_present = false;
	/* Pausing fails and the unwind of the paused prefix fails as well
	 * (a fresh source: the capture rows above destroyed the previous one). */
	vm_init(&src_vm, "src", 0x7b);
	devices_init();
	reset_points();
	strlcpy(fault_name, "pci_pause", sizeof(fault_name));
	fault_occurrence = 2;
	fault_error = EIO;
	strlcpy(fault2_name, "pci_resume", sizeof(fault2_name));
	fault2_occurrence = 1;
	fault2_error = EBUSY;
	armed = true;
	CHECK(vm_checkpoint(&src_vm, dirfd_, "pp.ckp", false) == EBUSY);
	armed = false;
	fault_name[0] = fault2_name[0] = '\0';
	printf("snapshot lookup guards: direct argument checks, metadata edits, compat and pause unwind faults\n");
}

/* The remaining contracts of the codec modules, called directly. */
static void
test_codec_edges(void)
{
	struct checkpoint_cpu_contract c, d;
	char *text, bad[CHECKPOINT_MACHINE_DIGEST_LENGTH + 1];
	uint64_t sizes[2] = { 4096, 8192 };
	uint16_t domains[2] = { 0, 1 };
	char *sizes_text = NULL, *mapping_text = NULL;
	struct checkpoint_memory_geometry a = { .page_size = PAGE_SIZE, .lowmem_size = LOWMEM,
	    .highmem_base = HIGHBASE, .highmem_size = HIGHMEM }, b;
	int r;

	random_contract(&c, 3);
	d = c;
	d.version++;
	CHECK(checkpoint_cpu_contract_match(&c, &d) != 0);
	CHECK(checkpoint_cpu_contract_encode(&c, &text) == 0);
	{
		size_t n = strlen(text);
		char *huge = __real_malloc(200064);	/* far beyond 256 records */
		memset(huge, '0', 200000);
		huge[200000] = '\0';
		CHECK(checkpoint_cpu_contract_decode(huge, &d) == E2BIG);
		free(huge);
		text[n - 1] = '!';		/* below '0' */
		CHECK(checkpoint_cpu_contract_decode(text, &d) == EINVAL);
		text[n - 1] = ':';		/* between '9' and 'a' */
		CHECK(checkpoint_cpu_contract_decode(text, &d) == EINVAL);
		text[n - 1] = 'G';
		CHECK(checkpoint_cpu_contract_decode(text, &d) == EINVAL);
	}
	free(text);
	CHECK(checkpoint_cpu_contract_encode(&c, &text) == 0);
	fault_once("malloc", 1, ENOMEM);
	r = checkpoint_cpu_contract_decode(text, &d);
	fault_clear();
	CHECK(r == ENOMEM);
	free(text);
	/* NUMA: no domains; an allocation failure while decoding. */
	CHECK(checkpoint_numa_encode(sizes, 0, domains, 2, &sizes_text, &mapping_text) == EINVAL);
	CHECK(checkpoint_numa_encode(sizes, 2, domains, 0, &sizes_text, &mapping_text) == EINVAL);
	CHECK(checkpoint_numa_encode(sizes, 2, domains, 2, &sizes_text, &mapping_text) == 0);
	{
		uint64_t out_sizes[CHECKPOINT_NUMA_MAX_DOMAINS];
		uint16_t out_domains[2];
		size_t out_count;
		fault_once("calloc", 1, ENOMEM);
		r = checkpoint_numa_decode(sizes_text, mapping_text, 2, 12288, out_sizes, &out_count, out_domains);
		fault_clear();
		CHECK(r == ENOMEM);
	}
	free(sizes_text);
	free(mapping_text);
	/* Machine digest text with characters outside the hex alphabet. */
	memset(bad, 'a', CHECKPOINT_MACHINE_DIGEST_LENGTH - 1);	/* 64 hex digits */
	bad[CHECKPOINT_MACHINE_DIGEST_LENGTH - 1] = '\0';
	CHECK(checkpoint_machine_digest_canonical(bad));
	bad[3] = '!';
	CHECK(!checkpoint_machine_digest_canonical(bad));
	bad[3] = ':';
	CHECK(!checkpoint_machine_digest_canonical(bad));
	bad[3] = 'G';
	CHECK(!checkpoint_machine_digest_canonical(bad));
	bad[3] = 'g';
	CHECK(!checkpoint_machine_digest_canonical(bad));
	/* Memory geometry: the high segment differs in base or length. */
	b = a; b.highmem_base += PAGE_SIZE;
	CHECK(checkpoint_memory_geometry_match(&a, &b, LOWMEM + HIGHMEM) != 0);
	b = a; b.highmem_size += PAGE_SIZE;
	CHECK(checkpoint_memory_geometry_match(&a, &b, LOWMEM + HIGHMEM) != 0);
	CHECK(checkpoint_memory_geometry_match(&a, &a, LOWMEM + HIGHMEM) == 0);
	printf("snapshot codec edges: cpu contract, numa, machine digest, geometry\n");
}

/* Manifest I/O faults and write-size edges, called directly. */
static void
test_manifest_io(void)
{
	struct checkpoint_manifest m;
	bool is_manifest;
	char path[400];
	int r;

	fresh_dir();
	vm_init(&src_vm, "src", 0x7a);
	devices_init();
	CHECK(vm_checkpoint(&src_vm, dirfd_, "io.ckp", false) == 0);
	snprintf(path, sizeof(path), "%s/io.ckp", dir);
	fault_once("close", 1, EIO);
	r = checkpoint_manifest_read(path, &m, &is_manifest);
	fault_clear();
	CHECK(r == EIO && !is_manifest);
	fault_once("close", 1, FAULT_NOERRNO);
	r = checkpoint_manifest_read(path, &m, &is_manifest);
	fault_clear();
	CHECK(r == EIO && !is_manifest);
	fault_once("open", 1, FAULT_NOERRNO);
	r = checkpoint_manifest_read(path, &m, &is_manifest);
	fault_clear();
	CHECK(r == EIO && !is_manifest);
	/* An interrupted lock request is retried. */
	fault_once("flock", 1, EINTR);
	r = vm_checkpoint(&src_vm, dirfd_, "io.ckp", false);
	fault_clear();
	CHECK(r == 0);
	/* A close failing after an earlier error keeps the first error: the
	 * manifest read of a non-manifest, the member hash, the publication
	 * and the restore loads. */
	{
		int fd = openat(dirfd_, "plain.ckp", O_WRONLY | O_CREAT, 0600);
		CHECK(fd >= 0 && __real_write(fd, "x", 1) == 1);
		close(fd);
		strlcpy(fault2_name, "close", sizeof(fault2_name));
		fault2_occurrence = 0;
		fault2_error = EIO;
		fault_once("fstat", 1, EBADF);	/* the manifest read fails before its close */
		snprintf(path, sizeof(path), "%s/plain.ckp", dir);
		r = checkpoint_manifest_read(path, &m, &is_manifest);
		CHECK(r == EBADF);
		{
			bool exists;
			reset_points();
			r = checkpoint_manifest_read_at(dirfd_, "plain.ckp", &m, &exists, &is_manifest);
			CHECK(r == EBADF);
		}
		fault_clear();
		fault2_name[0] = '\0';
		/* Publication: the member hash's lseek fails, then its close. */
		strlcpy(fault2_name, "close", sizeof(fault2_name));
		fault2_occurrence = 0;
		fault2_error = EIO;
		fault_once("lseek", 1, ESPIPE);
		r = vm_checkpoint(&src_vm, dirfd_, "io2.ckp", false);
		fault_clear();
		fault2_name[0] = '\0';
		CHECK(r == ESPIPE);
		/* Publication: the manifest write fails, then its close. */
		strlcpy(fault2_name, "close", sizeof(fault2_name));
		fault2_occurrence = 0;
		fault2_error = EIO;
		fault_once("write", 1, ENOSPC);
		r = vm_checkpoint(&src_vm, dirfd_, "io3.ckp", false);
		fault_clear();
		fault2_name[0] = '\0';
		CHECK(r == ENOSPC);
	}
	/* The checkpoint's writes: an interrupted write is retried everywhere;
	 * a write that makes no progress fails the checkpoint and publishes
	 * nothing new. */
	{
		struct checkpoint_manifest before, after;
		bool exists;
		int zero_failures = 0;
		CHECK(checkpoint_manifest_read_at(dirfd_, "io.ckp", &before, &exists, &is_manifest) == 0);
		for (int occ = 1; occ <= 60; occ++) {
			fault_once("write", occ, EINTR);
			r = vm_checkpoint(&src_vm, dirfd_, "io.ckp", false);
			fault_clear();
			CHECK(r == 0);
			CHECK(checkpoint_manifest_read_at(dirfd_, "io.ckp", &before, &exists, &is_manifest) == 0);
			fault_once("write", occ, FAULT_ZERO);
			r = vm_checkpoint(&src_vm, dirfd_, "io.ckp", false);
			fault_clear();
			CHECK(checkpoint_manifest_read_at(dirfd_, "io.ckp", &after, &exists, &is_manifest) == 0);
			if (r != 0) {
				zero_failures++;
				CHECK(strcmp(before.data, after.data) == 0);
			}
		}
		CHECK(zero_failures > 0);
	}
	printf("snapshot manifest I/O: read faults, interrupted and stalled writes\n");
}

/* Generic device memory: crafted extension headers and entries, transfer
 * faults, and a region larger than the digest chunk. */
static void
test_devmem_edges(void)
{
	static uint8_t src[3][5000], dst[3][5000];
	struct bhyve_devmem_region sr[3], dr[3];
	off_t normal = 8192;
	size_t extsize;
	int fd = devmem_file(normal), r;
	uint8_t hdr[32], ent[3][40];

	for (int i = 0; i < 3; i++)
		for (int j = 0; j < 5000; j++)
			src[i][j] = (uint8_t)(i * 31 + j * 7);
	devmem_regions(sr, src[0], src[1], src[2]);
	devmem_regions(dr, dst[0], dst[1], dst[2]);
	CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &extsize) == 0);
	CHECK(pread(fd, hdr, 32, normal) == 32);
	for (int i = 0; i < 3; i++)
		CHECK(pread(fd, ent[i], 40, normal + 32 + 40 * i) == 40);
#define PUT_HDR() CHECK(pwrite(fd, hdr, 32, normal) == 32)
#define PUT_ENT(i) CHECK(pwrite(fd, ent[i], 40, normal + 32 + 40 * (i)) == 40)
#define VALIDATE() bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)extsize, dr, 3)
#define RESTORE_HDR() CHECK(pread(fd, hdr, 32, normal) == 32)
#define RESTORE_ENT(i) CHECK(pread(fd, ent[i], 40, normal + 32 + 40 * (i)) == 40)
	/* Header: count 0; count larger than the extension can hold. */
	{
		uint8_t saved[32];
		memcpy(saved, hdr, 32);
		le32enc(hdr + 16, 0);
		PUT_HDR();
		CHECK(VALIDATE() == EPROTO);
		memcpy(hdr, saved, 32);
		le32enc(hdr + 16, 0xffffffffU);
		PUT_HDR();
		CHECK(VALIDATE() == EPROTO);
		memcpy(hdr, saved, 32);
		PUT_HDR();
		CHECK(VALIDATE() == 0);
	}
	/* Entries (sorted by name: alpha, mid, zeta): a name without a
	 * terminator; an empty name; a zero length; an offset past the
	 * extension; a length past the extension; names out of order; and a
	 * last entry ending short of the extension. */
	{
		uint8_t saved[40];
		memcpy(saved, ent[0], 40);
		memset(ent[0], 'a', 16);
		PUT_ENT(0);
		CHECK(VALIDATE() == EPROTO);
		memcpy(ent[0], saved, 40);
		ent[0][0] = '\0';
		PUT_ENT(0);
		CHECK(VALIDATE() == EPROTO);
		memcpy(ent[0], saved, 40);
		le64enc(ent[0] + 16, 0);
		PUT_ENT(0);
		CHECK(VALIDATE() == EPROTO);
		memcpy(ent[0], saved, 40);
		le64enc(ent[0] + 24, extsize + 1);
		PUT_ENT(0);
		CHECK(VALIDATE() == EPROTO);
		memcpy(ent[0], saved, 40);
		PUT_ENT(0);
		CHECK(VALIDATE() == 0);
	}
	{
		uint8_t s0[40], s1[40];
		memcpy(s0, ent[0], 40);
		memcpy(s1, ent[1], 40);
		/* Swap the first two entries' names: order check. */
		memcpy(ent[0], s1, 16);
		memcpy(ent[1], s0, 16);
		PUT_ENT(0);
		PUT_ENT(1);
		CHECK(VALIDATE() == EPROTO);
		memcpy(ent[0], s0, 40);
		memcpy(ent[1], s1, 40);
		PUT_ENT(0);
		PUT_ENT(1);
		CHECK(VALIDATE() == 0);
	}
	/* A header whose entry table does not fit the (truncated) extension;
	 * an extension longer than its entries account for. */
	{
		uint8_t saved[32];
		off_t size = normal + (off_t)extsize;
		memcpy(saved, hdr, 32);
		le64enc(hdr + 24, 32 + 40);
		PUT_HDR();
		CHECK(ftruncate(fd, normal + 32 + 40) == 0);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + 32 + 40, dr, 3) == EPROTO);
		CHECK(ftruncate(fd, size) == 0);
		memcpy(hdr, saved, 32);
		CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &extsize) == 0);
		CHECK(pread(fd, hdr, 32, normal) == 32);
		for (int i = 0; i < 3; i++)
			CHECK(pread(fd, ent[i], 40, normal + 32 + 40 * i) == 40);
		memcpy(saved, hdr, 32);
		le64enc(hdr + 24, extsize + 7);
		PUT_HDR();
		CHECK(ftruncate(fd, size + 7) == 0);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, size + 7, dr, 3) == EPROTO);
		CHECK(ftruncate(fd, size) == 0);
		memcpy(hdr, saved, 32);
		PUT_HDR();
		CHECK(VALIDATE() == 0);
	}
	/* Two regions of equal length whose entries are out of order. */
	{
		static uint8_t p[64], q[64], pd[64], qd[64];
		struct bhyve_devmem_region two[2], twod[2];
		size_t sz = 0;
		uint8_t e0[40], e1[40];
		memset(two, 0, sizeof(two));
		strlcpy(two[0].name, "bb", sizeof(two[0].name));
		two[0].host_base = p; two[0].length = 64;
		strlcpy(two[1].name, "aa", sizeof(two[1].name));
		two[1].host_base = q; two[1].length = 64;
		memcpy(twod, two, sizeof(two));
		twod[0].host_base = pd; twod[1].host_base = qd;
		CHECK(bhyve_devmem_snapshot_save(fd, normal, two, 2, &sz) == 0);
		CHECK(pread(fd, e0, 40, normal + 32) == 40 && pread(fd, e1, 40, normal + 72) == 40);
		CHECK(pwrite(fd, e1, 16, normal + 32) == 16 && pwrite(fd, e0, 16, normal + 72) == 16);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)sz, twod, 2) == EPROTO);
		CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &extsize) == 0);
	}
	/* Transfer faults: an interrupted read is retried; a read or write that
	 * makes no progress is an error. */
	fault_once("pread", 1, EINTR);
	r = VALIDATE();
	fault_clear();
	CHECK(r == 0);
	fault_once("pread", 1, FAULT_ZERO);
	r = VALIDATE();
	fault_clear();
	CHECK(r == EIO);
	fault_once("pread", 2, FAULT_ZERO);
	r = VALIDATE();
	fault_clear();
	CHECK(r == EIO);
	{
		size_t sz = 0;
		fault_once("pwrite", 1, EINTR);
		r = bhyve_devmem_snapshot_save(fd, normal, sr, 3, &sz);
		fault_clear();
		CHECK(r == 0 && sz == extsize);
		fault_once("pwrite", 1, FAULT_ZERO);
		r = bhyve_devmem_snapshot_save(fd, normal, sr, 3, &sz);
		fault_clear();
		CHECK(r == EIO);
		CHECK(bhyve_devmem_snapshot_save(fd, normal, sr, 3, &sz) == 0);
	}
	/* A region larger than the digest chunk. */
	{
		size_t big = 1024 * 1024 + 4096, sz = 0;
		uint8_t *a = __real_malloc(big), *b = __real_malloc(big);
		struct bhyve_devmem_region one, two;
		for (size_t i = 0; i < big; i++)
			a[i] = (uint8_t)(i * 3);
		memset(b, 0, big);
		memset(&one, 0, sizeof(one));
		strlcpy(one.name, "wide", sizeof(one.name));
		one.host_base = a;
		one.length = big;
		two = one;
		two.host_base = b;
		CHECK(bhyve_devmem_snapshot_save(fd, normal, &one, 1, &sz) == 0);
		CHECK(bhyve_devmem_snapshot_validate(fd, normal, normal + (off_t)sz, &two, 1) == 0);
		CHECK(bhyve_devmem_snapshot_restore(fd, normal, normal + (off_t)sz, &two, 1) == 0);
		CHECK(memcmp(a, b, big) == 0);
		free(a);
		free(b);
	}
#undef PUT_HDR
#undef PUT_ENT
#undef VALIDATE
#undef RESTORE_HDR
#undef RESTORE_ENT
	close(fd);
	printf("snapshot device memory edges: crafted headers and entries, transfer faults, wide region\n");
}

static const struct scenario scenarios[] = {
	{ "fresh-checkpoint", fresh_ckpt_prepare, fresh_ckpt_operate, fresh_ckpt_verify },
	{ "checkpoint", ckpt_prepare, ckpt_operate, ckpt_verify },
	{ "restore", restore_prepare, restore_operate, restore_verify },
	{ "migration-capture", blob_prepare, blob_operate, blob_verify },
	{ "migration-commit", commit_prepare, commit_operate, commit_verify },
	{ "fresh-restore", fresh_restore_prepare, restore_operate, fresh_restore_verify },
	{ "fresh-migration-capture", fresh_blob_prepare, fresh_blob_operate, fresh_blob_verify },
	{ "fresh-migration-commit", fresh_commit_prepare, fresh_commit_operate,
	    fresh_commit_verify },
};

static void
test_faults(void)
{
	for (size_t i = 0; i < nitems(scenarios); i++)
		enumerate(&scenarios[i]);
}

static void
debug_metadata(void)
{
	struct checkpoint_cpu_contract c;
	char *text = NULL, digest[CHECKPOINT_MACHINE_DIGEST_LENGTH];
	struct checkpoint_memory_geometry g = { .page_size = PAGE_SIZE, .lowmem_size = LOWMEM,
	    .highmem_base = HIGHBASE, .highmem_size = HIGHMEM };
	int e;

	e = checkpoint_cpu_contract_capture(fbsdrun_vcpu(0), &c);
	fprintf(stderr, "capture %d\n", e);
	if (e == 0)
		fprintf(stderr, "encode %d\n", checkpoint_cpu_contract_encode(&c, &text));
	fprintf(stderr, "geometry %d\n", checkpoint_memory_geometry_validate(&g, LOWMEM + HIGHMEM));
	devices_init();
	fprintf(stderr, "digest %d\n", vm_machine_topology_digest_current(digest, sizeof(digest)));
	free(text);
}

int
main(void)
{
	signal(SIGPIPE, SIG_IGN);
	if (getenv("SNAP_DEBUG") != NULL)
		debug_metadata();
	test_round_trip();
	test_fenced_checkpoint();
	test_stop_vm(false);
	test_stop_vm(true);
	test_refusals();
	test_continuity_refusal();
	test_migration_blob(false);
	test_migration_blob(true);
	test_session_protocol();
	test_topology_rules();
	test_cpu_capture();
	test_numa_codec();
	test_cpu_contract_codec();
	test_compat_and_machine();
	test_buffer_helpers();
	test_progress();
	test_vcpu_fence();
	test_devmem_extension();
	test_vmgenid_codec();
	test_vmgenid();
	devmem_enabled = true;
	for (int seg = 0; seg < 2; seg++)
		for (int i = 0; i < 8192; i++)
			devmem_buf[0][seg][i] = (uint8_t)(seg * 31 + i * 7);
	test_round_trip();
	test_migration_blob(false);
	test_stop_protocol();
	test_restore_refusals();
	test_manifest_api();
	test_migration_edges();
	test_merged_helpers();
	test_read_eintr();
	test_progress_tty();
	test_lookup_guards();
	test_codec_edges();
	test_manifest_io();
	test_devmem_edges();
	/* The second half reports in raw-console mode (EPRINTLN line endings). */
	raw_stdio = 1;
	test_metadata_mutations();
	test_member_mutations();
	test_faults();
	raw_stdio = 0;
	printf("PASS: snapshot.c production configuration\n");
	return (0);
}
