/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Preloaded only into the offline elf-coverage-matrix harness.
 *
 * Fault injection at documented API failure returns: the Nth call (counting
 * from 0) of one armed function returns that function's documented error
 * value (NULL / -1 / EV_NONE / ELF_K_NONE) with errno set, or, for read and
 * write, -1/EINTR once or a 0-byte transfer.  Memory functions model ENOMEM.
 * Nothing else is altered: every other call goes to the real implementation.
 *
 * Allocations returned by dt_alloc, dt_zalloc, calloc and strdup while
 * tracking is enabled are recorded so that the harness can assert that an
 * operation released everything it allocated.
 */
#include <sys/types.h>
#include <sys/stat.h>

#include <dlfcn.h>
#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { FAULT_FAIL = 0, FAULT_EINTR = 1, FAULT_ZERO = 2 };

static char armed_name[64];
static long armed_nth = -1;
static long armed_calls;
static int armed_mode;
static int fired;
static int tracking;

#define	TRACK_SLOTS	65536
static void *tracked[TRACK_SLOTS];
static long live;

void
fault_arm(const char *name, long nth, int mode)
{
	strlcpy(armed_name, name, sizeof(armed_name));
	armed_nth = nth;
	armed_calls = 0;
	armed_mode = mode;
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

void
fault_track(int on)
{
	tracking = on;
}

long
fault_live(void)
{
	return (live);
}

/* Only calls made by libdtrace itself are counted. */
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

/* Returns non-zero when this call of 'name' must fail. */
#define	should_fail(name) should_fail_at(name, __builtin_return_address(0))
static int
should_fail_at(const char *name, const void *caller)
{
	if (armed_name[0] == '\0' || strcmp(name, armed_name) != 0)
		return (0);
	if (!from_libdtrace(caller))
		return (0);
	if (armed_calls++ != armed_nth)
		return (0);
	fired = 1;
	return (1);
}

/* Called by operator new (elf-fault-new.cc) with its caller. */
int
fault_should_fail_new(const void *caller)
{
	return (should_fail_at("new", caller));
}

static void
track_any(void *p)
{
	size_t h = ((uintptr_t)p >> 4) % TRACK_SLOTS;
	for (size_t i = 0; i < TRACK_SLOTS; i++) {
		size_t s = (h + i) % TRACK_SLOTS;
		if (tracked[s] == NULL) {
			tracked[s] = p;
			live++;
			return;
		}
	}
	abort();
}

static void
untrack(void *p)
{
	if (p == NULL || live == 0)
		return;
	size_t h = ((uintptr_t)p >> 4) % TRACK_SLOTS;
	for (size_t i = 0; i < TRACK_SLOTS; i++) {
		size_t s = (h + i) % TRACK_SLOTS;
		if (tracked[s] == p) {
			tracked[s] = NULL;
			live--;
			/* Keep probe chains intact: reinsert the rest of the run. */
			for (size_t j = 1; j < TRACK_SLOTS; j++) {
				size_t t = (s + j) % TRACK_SLOTS;
				void *q = tracked[t];
				if (q == NULL)
					break;
				tracked[t] = NULL;
				live--;
				track_any(q);
			}
			return;
		}
		if (tracked[s] == NULL)
			return;
	}
}

/* Record allocations requested by libdtrace while tracking is on. */
#define	track(p) track_at(p, __builtin_return_address(0))
static void
track_at(void *p, const void *caller)
{
	if (p != NULL && tracking && from_libdtrace(caller))
		track_any(p);
}

void
fault_forget_all(void)
{
	memset(tracked, 0, sizeof(tracked));
	live = 0;
}

#define	REAL(type, name, args)						\
	static type (*real_##name) args;				\
	if (real_##name == NULL)					\
		real_##name = (type (*) args)dlsym(RTLD_NEXT, #name)

void
free(void *p)
{
	REAL(void, free, (void *));
	untrack(p);
	real_free(p);
}

void *
calloc(size_t n, size_t size)
{
	REAL(void *, calloc, (size_t, size_t));
	if (should_fail("calloc")) {
		errno = ENOMEM;
		return (NULL);
	}
	void *p = real_calloc(n, size);
	track(p);
	return (p);
}

char *
strdup(const char *s)
{
	REAL(void *, malloc, (size_t));
	if (should_fail("strdup")) {
		errno = ENOMEM;
		return (NULL);
	}
	size_t n = strlen(s) + 1;
	char *p = real_malloc(n);
	if (p != NULL) {
		memcpy(p, s, n);
		track(p);
	}
	return (p);
}

void *
dt_alloc(void *dtp, size_t size)
{
	REAL(void *, malloc, (size_t));
	(void)dtp;
	if (should_fail("dt_alloc")) {
		errno = ENOMEM;
		return (NULL);
	}
	void *p = real_malloc(size);
	track(p);
	return (p);
}

void *
dt_zalloc(void *dtp, size_t size)
{
	REAL(void *, malloc, (size_t));
	(void)dtp;
	if (should_fail("dt_zalloc") || should_fail("dt_alloc")) {
		errno = ENOMEM;
		return (NULL);
	}
	void *p = real_malloc(size);
	if (p != NULL) {
		memset(p, 0, size);
		track(p);
	}
	return (p);
}

int
mkstemp(char *template)
{
	REAL(int, mkstemp, (char *));
	if (should_fail("mkstemp")) {
		errno = EMFILE;
		return (-1);
	}
	return (real_mkstemp(template));
}

int
unlink(const char *path)
{
	REAL(int, unlink, (const char *));
	if (should_fail("unlink")) {
		/* Model a failure after the name was created: remove it anyway
		 * so that the test leaves nothing behind, then report EACCES. */
		(void)real_unlink(path);
		errno = EACCES;
		return (-1);
	}
	return (real_unlink(path));
}

ssize_t
read(int fd, void *buf, size_t n)
{
	REAL(ssize_t, read, (int, void *, size_t));
	if (should_fail("read")) {
		if (armed_mode == FAULT_EINTR) {
			errno = EINTR;
			return (-1);
		}
		if (armed_mode == FAULT_ZERO)
			return (0);
		errno = EIO;
		return (-1);
	}
	return (real_read(fd, buf, n));
}

ssize_t
write(int fd, const void *buf, size_t n)
{
	REAL(ssize_t, write, (int, const void *, size_t));
	if (should_fail("write")) {
		if (armed_mode == FAULT_EINTR) {
			errno = EINTR;
			return (-1);
		}
		if (armed_mode == FAULT_ZERO)
			return (0);
		errno = ENOSPC;
		return (-1);
	}
	return (real_write(fd, buf, n));
}

int
fstat(int fd, struct stat *sb)
{
	REAL(int, fstat, (int, struct stat *));
	if (should_fail("fstat")) {
		errno = EIO;
		return (-1);
	}
	return (real_fstat(fd, sb));
}

off_t
lseek(int fd, off_t off, int whence)
{
	REAL(off_t, lseek, (int, off_t, int));
	if (should_fail("lseek")) {
		errno = ESPIPE;
		return (-1);
	}
	return (real_lseek(fd, off, whence));
}

unsigned char *
SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
	REAL(unsigned char *, SHA256, (const unsigned char *, size_t,
	    unsigned char *));
	if (should_fail("SHA256"))
		return (NULL);
	return (real_SHA256(d, n, md));
}

/* libelf entry points: documented failure returns. */
#define	ELF_PTR_FN(rtype, name, params, args)				\
rtype name params							\
{									\
	REAL(rtype, name, params);					\
	if (should_fail(#name))						\
		return (NULL);						\
	return (real_##name args);					\
}

ELF_PTR_FN(Elf *, elf_begin, (int fd, Elf_Cmd c, Elf *e), (fd, c, e))
ELF_PTR_FN(Elf32_Ehdr *, elf32_newehdr, (Elf *e), (e))
ELF_PTR_FN(Elf32_Phdr *, elf32_newphdr, (Elf *e, size_t n), (e, n))
ELF_PTR_FN(Elf_Scn *, elf_newscn, (Elf *e), (e))
ELF_PTR_FN(Elf_Data *, elf_newdata, (Elf_Scn *s), (s))
ELF_PTR_FN(Elf32_Shdr *, elf32_getshdr, (Elf_Scn *s), (s))
ELF_PTR_FN(Elf_Data *, elf_getdata, (Elf_Scn *s, Elf_Data *d), (s, d))
ELF_PTR_FN(Elf_Scn *, elf_getscn, (Elf *e, size_t i), (e, i))
ELF_PTR_FN(GElf_Ehdr *, gelf_getehdr, (Elf *e, GElf_Ehdr *h), (e, h))
ELF_PTR_FN(GElf_Shdr *, gelf_getshdr, (Elf_Scn *s, GElf_Shdr *h), (s, h))

unsigned int
elf_version(unsigned int v)
{
	REAL(unsigned int, elf_version, (unsigned int));
	if (should_fail("elf_version"))
		return (EV_NONE);
	return (real_elf_version(v));
}

off_t
elf_update(Elf *e, Elf_Cmd c)
{
	REAL(off_t, elf_update, (Elf *, Elf_Cmd));
	if (should_fail("elf_update"))
		return (-1);
	return (real_elf_update(e, c));
}

Elf_Kind
elf_kind(Elf *e)
{
	REAL(Elf_Kind, elf_kind, (Elf *));
	if (should_fail("elf_kind"))
		return (ELF_K_NONE);
	return (real_elf_kind(e));
}

int
gelf_getclass(Elf *e)
{
	REAL(int, gelf_getclass, (Elf *));
	if (should_fail("gelf_getclass"))
		return (ELFCLASSNONE);
	return (real_gelf_getclass(e));
}

int
elf_getshdrstrndx(Elf *e, size_t *n)
{
	REAL(int, elf_getshdrstrndx, (Elf *, size_t *));
	if (should_fail("elf_getshdrstrndx"))
		return (-1);
	return (real_elf_getshdrstrndx(e, n));
}

int
elf_getshdrnum(Elf *e, size_t *n)
{
	REAL(int, elf_getshdrnum, (Elf *, size_t *));
	if (should_fail("elf_getshdrnum"))
		return (-1);
	return (real_elf_getshdrnum(e, n));
}
