/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Preloaded only into the subr-faults harness (built without sanitizers).
 *
 * Fault injection at documented failure returns.  One function is armed at
 * a time: its Nth call (counting from 0) made by libdtrace itself (the
 * caller's object is libdtrace.so) fails with the documented error value and
 * errno.  "Repeat" mode fails every call from that point on.  Every other
 * call goes to the real implementation.
 *
 * pdself() and PDIOC_GET_BIRTH_IDENTITY are also answered here when
 * shim_birth() enables it: the host's capability policy refuses pdself() to
 * tests, and dtraced's consumer hello needs the kernel birth identity.
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/procdesc.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static char armed_name[64];
static long armed_nth = -1;
static long armed_calls;
static int armed_errno, armed_repeat, armed_value;
static int fired;

void
fault_arm(const char *name, long nth, int error, int repeat, int value)
{
	strlcpy(armed_name, name, sizeof(armed_name));
	armed_nth = nth;
	armed_calls = 0;
	armed_errno = error;
	armed_repeat = repeat;
	armed_value = value;
	fired = 0;
}

int
fault_disarm(void)
{
	armed_name[0] = '\0';
	armed_nth = -1;
	return (fired);
}

long
fault_calls(void)
{
	return (armed_calls);
}

static int
from_libdtrace(const void *caller)
{
	static void *base;
	Dl_info info;

	if (base == NULL) {
		void *sym = dlsym(RTLD_DEFAULT, "dtrace_open");
		if (sym == NULL || dladdr(sym, &info) == 0)
			return (0);
		base = info.dli_fbase;
	}
	return (dladdr(caller, &info) != 0 && info.dli_fbase == base);
}

#define	should_fail(name) should_fail_at(name, __builtin_return_address(0))
static int
should_fail_at(const char *name, const void *caller)
{
	if (armed_name[0] == '\0' || strcmp(name, armed_name) != 0)
		return (0);
	if (!from_libdtrace(caller))
		return (0);
	if (armed_calls++ < armed_nth)
		return (0);
	if (!armed_repeat && armed_calls - 1 != armed_nth)
		return (0);
	fired = 1;
	errno = armed_errno;
	return (1);
}

#define	REAL(type, name, args)						\
	static type (*real_##name) args;				\
	if (real_##name == NULL)					\
		real_##name = (type (*) args)dlsym(RTLD_NEXT, #name)

void *
malloc(size_t size)
{
	REAL(void *, malloc, (size_t));
	if (should_fail("malloc"))
		return (NULL);
	return (real_malloc(size));
}

/* The compiler folds malloc()+bzero() (dt_zalloc) into calloc(), so an armed
 * "malloc" fault counts and fails zeroed allocations too; arming "calloc"
 * still selects only those. */
void *
calloc(size_t n, size_t size)
{
	REAL(void *, calloc, (size_t, size_t));
	if (should_fail("calloc") || should_fail("malloc"))
		return (NULL);
	return (real_calloc(n, size));
}

void *
realloc(void *p, size_t size)
{
	REAL(void *, realloc, (void *, size_t));
	if (should_fail("realloc"))
		return (NULL);
	return (real_realloc(p, size));
}

char *
strdup(const char *s)
{
	REAL(char *, strdup, (const char *));
	if (should_fail("strdup"))
		return (NULL);
	return (real_strdup(s));
}

/* value 1: a zero-byte transfer instead of an error. */
ssize_t
send(int s, const void *buf, size_t len, int flags)
{
	REAL(ssize_t, send, (int, const void *, size_t, int));
	if (should_fail("send"))
		return (armed_value == 1 ? 0 : -1);
	return (real_send(s, buf, len, flags));
}

ssize_t
recv(int s, void *buf, size_t len, int flags)
{
	REAL(ssize_t, recv, (int, void *, size_t, int));
	if (should_fail("recv"))
		return (armed_value == 1 ? 0 : -1);
	return (real_recv(s, buf, len, flags));
}

/* value 1: report POLLNVAL instead of failing. */
int
poll(struct pollfd *fds, nfds_t n, int timeout)
{
	REAL(int, poll, (struct pollfd *, nfds_t, int));
	if (should_fail("poll")) {
		if (armed_value == 1) {
			fds[0].revents = POLLNVAL;
			return (1);
		}
		return (-1);
	}
	return (real_poll(fds, n, timeout));
}

int
clock_gettime(clockid_t id, struct timespec *ts)
{
	REAL(int, clock_gettime, (clockid_t, struct timespec *));
	if (should_fail("clock_gettime"))
		return (-1);
	return (real_clock_gettime(id, ts));
}

int
socket(int domain, int type, int protocol)
{
	REAL(int, socket, (int, int, int));
	if (should_fail("socket"))
		return (-1);
	return (real_socket(domain, type, protocol));
}

int
sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
    const void *newp, size_t newlen)
{
	REAL(int, sysctlbyname, (const char *, void *, size_t *,
	    const void *, size_t));
	if (strcmp(name, "kern.smp.maxid") == 0 && should_fail("sysctlbyname"))
		return (-1);
	return (real_sysctlbyname(name, oldp, oldlenp, newp, newlen));
}

int
fcntl(int fd, int cmd, ...)
{
	REAL(int, fcntl, (int, int, ...));
	va_list ap;
	long arg;

	va_start(ap, cmd);
	arg = va_arg(ap, long);
	va_end(ap);
	if (cmd == F_DUPFD_CLOEXEC && should_fail("fcntl"))
		return (-1);
	return (real_fcntl(fd, cmd, arg));
}

int
pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *),
    void *arg)
{
	REAL(int, pthread_create, (pthread_t *, const pthread_attr_t *,
	    void *(*)(void *), void *));
	if (should_fail("pthread_create"))
		return (armed_errno);
	return (real_pthread_create(t, a, fn, arg));
}

int
fpurge(FILE *fp)
{
	REAL(int, fpurge, (FILE *));
	if (should_fail("fpurge"))
		return (EOF);
	return (real_fpurge(fp));
}

ssize_t
pread(int fd, void *buf, size_t len, off_t off)
{
	REAL(ssize_t, pread, (int, void *, size_t, off_t));
	if (should_fail("pread"))
		return (armed_value == 1 ? 0 : -1);
	return (real_pread(fd, buf, len, off));
}

/* ---- Process birth identity -------------------------------------- */

#define	BIRTH_SEC	0x0102030405060708ULL
#define	BIRTH_USEC	123456ULL

static int birth_mode, birth_fd = -1;

/*
 * 0: real pdself(); 1: good identity; 2: the query fails; 3: close fails;
 * 4: both fail; 5: a birth in the first second of the epoch clock
 * (start_sec 0, start_usec 5), which is valid.
 */
void
shim_birth(int mode)
{
	birth_mode = mode;
}

int
pdself(int *fdp, int flags)
{
	REAL(int, pdself, (int *, int));
	if (birth_mode == 0)
		return (real_pdself(fdp, flags));
	*fdp = birth_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	return (*fdp < 0 ? -1 : 0);
}

int
ioctl(int fd, unsigned long request, ...)
{
	REAL(int, ioctl, (int, unsigned long, ...));
	struct pd_birth_identity *b;
	va_list ap;
	void *arg;

	va_start(ap, request);
	arg = va_arg(ap, void *);
	va_end(ap);
	if (birth_mode != 0 && fd == birth_fd &&
	    request == PDIOC_GET_BIRTH_IDENTITY) {
		if (birth_mode == 2 || birth_mode == 4) {
			errno = EIO;
			return (-1);
		}
		b = arg;
		memset(b, 0, sizeof(*b));
		b->pid = getpid();
		b->start_sec = birth_mode == 5 ? 0 : BIRTH_SEC;
		b->start_usec = birth_mode == 5 ? 5 : BIRTH_USEC;
		return (0);
	}
	return (real_ioctl(fd, request, arg));
}

int
close(int fd)
{
	REAL(int, close, (int));
	if ((birth_mode == 3 || birth_mode == 4) && fd == birth_fd &&
	    fd >= 0) {
		birth_fd = -1;
		(void)real_close(fd);
		errno = EIO;
		return (-1);
	}
	return (real_close(fd));
}
