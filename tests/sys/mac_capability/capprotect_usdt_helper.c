/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 *
 * Fixture for the capprotect debug and tracing pins
 * (capprotect_debug_pins_test.c, capprotect_dtrace_test.sh).
 *
 * usage: capprotect_usdt_helper MODE
 *
 *   plain             no protection
 *   self              shields itself with CP_SF_PTRACE|SIGNAL|SIGKILL
 *   self-signal-only  shields itself with CP_SF_SIGNAL|SIGKILL (no PTRACE)
 *   flags=HEX         shields itself with exactly HEX
 *   capmode           enters capability mode and re-executes itself
 *                     (fexecve) in "plain" mode
 *
 * The fixture then prints one line
 *
 *   READY pid=PID canary=ADDR value=VALUE
 *
 * on standard output and serves commands, one per line, from standard input.
 * Standard output may be a socket, which "mint" needs.  Every reply is one
 * line:
 *
 *   canary            CANARY VALUE 
 *   set HEX           SET 0, after storing HEX in the canary
 *   shield HEX        SHIELD ERRNO (CP_OP_SHIELD with flags HEX)
 *   mint HEX          MINT ERRNO, with the token descriptor attached when
 *                     ERRNO is 0 (CP_OP_MINT on the shield descriptor)
 *   pid               PID PID
 *   sigcount          SIGCOUNT N (SIGUSR1 deliveries counted so far)
 *   ticks             TICKS N (the number of cpusdt:::tick sites passed)
 *   dof               DOF ADDR BASE: the address of this executable's DOF
 *                     (its read-only .SUNW_dof section) and
 *                     the executable's load base, as drti passes them to
 *                     DTRACEHIOC_ADDDOF; "DOF 0 0" without a provider
 *   heapdof           HEAPDOF ADDR: a copy of that DOF in the heap
 *   cowdof            COWDOF ERRNO: makes the pages of that DOF writable,
 *                     rewrites one byte with its own value (so the pages
 *                     become private copies) and makes them read-only
 *   loop MODE         LOOP ERRNO, then a thread changes the map until
 *                     "stop": "unmap" unmaps the DOF's pages and maps the
 *                     file back; "crafted" first puts anonymous read-only
 *                     pages there holding the same bytes with the provider
 *                     renamed cpusdx; "churn" maps and unmaps anonymous
 *                     memory elsewhere
 *   stop              STOP N: stops the loop thread after N rounds
 *   exec              re-executes this program in "plain" mode; the new
 *                     image prints a new READY line
 *   exit              the server exits with status 0
 *
 * End of file on standard input makes the fixture exit.  The cpusdt:::tick
 * probe fires about ten times a second while the server waits, and
 * cpusdt:::ready once after the mode is applied.  An alarm ends every
 * process of the fixture after FIXTURE_TIMEOUT seconds.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>

#include <dlfcn.h>
#include <errno.h>
#include <gelf.h>
#include <libelf.h>
#include <link.h>
#include <pthread.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mac_capability_ioctl.h"
#include "mac_capability_capprotect_proto.h"

#ifdef WITH_DTRACE
#include "capprotect_usdt_helper_provider.h"
#else
#define	CPUSDT_TICK(n)	((void)(n))
#define	CPUSDT_READY()	do { } while (0)
#endif

#define	FIXTURE_TIMEOUT	600

/* The leading fields of dof_hdr_t (sys/dtrace.h, a CDDL kernel header). */
struct cp_dof_hdr {
	uint8_t		dofh_ident[16];
	uint32_t	dofh_flags;
	uint32_t	dofh_hdrsize;
	uint32_t	dofh_secsize;
	uint32_t	dofh_secnum;
	uint64_t	dofh_secoff;
	uint64_t	dofh_loadsz;
};

extern char **environ;

/*
 * The canary lives in .data, so a fork copy and a sharer see it at the same
 * address as the parent.  The tests read and write it through PT_IO.
 */
static volatile uint64_t cp_canary __used = 0x5ec2e75ec2e75ec2ULL;
static volatile sig_atomic_t cp_sigusr1;
static int cp_ticks;
static const char *cp_self;
/* The shield descriptor of the process that applied it; -1 if none. */
static int cp_shield_fd = -1;

static void
on_alarm(int sig __unused)
{

	_exit(99);
}

static void
on_usr1(int sig __unused)
{

	cp_sigusr1++;
}

/*
 * Replies are formatted on the stack and written with one write(2).
 */
static void __printflike(1, 2)
reply(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= sizeof(buf))
		_exit(98);
	if (write(STDOUT_FILENO, buf, n) != n)
		_exit(97);
}

static int
cp_connect(void)
{
	struct mac_capability_connect_args ca;
	int ctl, saved;

	ctl = open("/dev/mac_capability", O_RDWR);
	if (ctl < 0)
		return (-1);
	memset(&ca, 0, sizeof(ca));
	strlcpy(ca.name, "capprotect", sizeof(ca.name));
	if (ioctl(ctl, MAC_CAPABILITY_CONNECT, &ca) != 0) {
		saved = errno;
		close(ctl);
		errno = saved;
		return (-1);
	}
	close(ctl);
	return (ca.fd);
}

/* CP_OP_SHIELD on this process; returns 0 or an errno. */
static int
shield_self(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	int error, fd;

	fd = cp_connect();
	if (fd < 0)
		return (errno);
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_SHIELD;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	if (ioctl(fd, MAC_CAPABILITY_CALL, &ca) != 0) {
		error = errno;
		close(fd);
		return (error);
	}
	if (cp_shield_fd >= 0)
		close(cp_shield_fd);
	cp_shield_fd = fd;
	return (0);
}

/* CP_OP_MINT on the shield descriptor; the token goes out with the reply. */
static void
mint_token(uint32_t flags)
{
	struct mac_capability_call_args ca;
	struct cp_request req;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	char line[64];
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int))];
	} control;
	int token;

	token = -1;
	memset(&req, 0, sizeof(req));
	req.op = CP_OP_MINT;
	req.flags = flags;
	memset(&ca, 0, sizeof(ca));
	ca.req = &req;
	ca.req_len = sizeof(req);
	ca.reply_fds = &token;
	ca.reply_nfds = 1;
	if (cp_shield_fd < 0) {
		reply("MINT %d\n", EBADF);
		return;
	}
	if (ioctl(cp_shield_fd, MAC_CAPABILITY_CALL, &ca) != 0 ||
	    ca.reply_nfds != 1 || token < 0) {
		reply("MINT %d\n", errno != 0 ? errno : EIO);
		return;
	}
	snprintf(line, sizeof(line), "MINT 0\n");
	iov.iov_base = line;
	iov.iov_len = strlen(line);
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(&control, 0, sizeof(control));
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &token, sizeof(int));
	if (sendmsg(STDOUT_FILENO, &msg, 0) != (ssize_t)iov.iov_len)
		_exit(96);
	close(token);
}

/*
 * Read one command line.  Returns false at end of file.  Waits in poll(2)
 * so that cpusdt:::tick keeps firing while no command arrives.
 */
static bool
read_command(char *buf, size_t len)
{
	struct pollfd pfd;
	size_t n;
	ssize_t r;
	char c;

	for (;;) {
		pfd.fd = STDIN_FILENO;
		pfd.events = POLLIN;
		pfd.revents = 0;
		r = poll(&pfd, 1, 100);
		if (r < 0 && errno != EINTR)
			_exit(95);
		if (r > 0)
			break;
		CPUSDT_TICK(cp_ticks);
		cp_ticks++;
	}
	n = 0;
	for (;;) {
		r = read(STDIN_FILENO, &c, 1);
		if (r < 0 && errno == EINTR)
			continue;
		if (r <= 0)
			return (false);
		if (c == '\n')
			break;
		if (n + 1 < len)
			buf[n++] = c;
	}
	buf[n] = '\0';
	return (true);
}

#ifdef WITH_DTRACE
/*
 * The executable's DOF: dtrace -G puts it in a .SUNW_dof section, which
 * drti registers with DTRACEHIOC_ADDDOF.  Its symbol is local to the
 * provider object, so the section is found in the executable's file.
 */
static char *cp_dof;		/* the DOF in memory, or NULL */
static uintptr_t cp_base;	/* the executable's load base */

static int
main_object(struct dl_phdr_info *info, size_t size __unused, void *arg)
{

	*(uintptr_t *)arg = info->dlpi_addr;
	return (1);		/* the first object is the executable */
}

static void
find_dof(const char *self)
{
	GElf_Shdr shdr;
	Elf_Scn *scn;
	size_t shstrndx;
	const char *name;
	Elf *elf;
	int fd;

	if (elf_version(EV_CURRENT) == EV_NONE ||
	    (fd = open(self, O_RDONLY | O_CLOEXEC)) < 0)
		return;
	dl_iterate_phdr(main_object, &cp_base);
	if ((elf = elf_begin(fd, ELF_C_READ, NULL)) != NULL &&
	    elf_getshdrstrndx(elf, &shstrndx) == 0) {
		for (scn = NULL; (scn = elf_nextscn(elf, scn)) != NULL; ) {
			if (gelf_getshdr(scn, &shdr) == NULL)
				continue;
			name = elf_strptr(elf, shstrndx, shdr.sh_name);
			if (name != NULL && strcmp(name, ".SUNW_dof") == 0) {
				cp_dof = (char *)(cp_base + shdr.sh_addr);
				break;
			}
		}
	}
	if (elf != NULL)
		elf_end(elf);
	close(fd);
}
#endif

static void
report_dof(void)
{
#ifdef WITH_DTRACE
	if (cp_dof != NULL) {
		reply("DOF %p %#jx\n", (void *)cp_dof, (uintmax_t)cp_base);
		return;
	}
#endif
	reply("DOF 0 0\n");
}

/* A heap copy of the DOF, for the read-only file mapping pins. */
static void
report_heapdof(void)
{
#ifdef WITH_DTRACE
	const struct cp_dof_hdr *hdr = (const void *)cp_dof;
	char *copy;

	copy = cp_dof != NULL ? malloc(hdr->dofh_loadsz) : NULL;
	if (copy == NULL) {
		reply("HEAPDOF 0\n");
		return;
	}
	memcpy(copy, cp_dof, hdr->dofh_loadsz);
	reply("HEAPDOF %p\n", (void *)copy);
#else
	reply("HEAPDOF 0\n");
#endif
}

#ifdef WITH_DTRACE
/*
 * The map-changing loops.  The DOF pages may hold other read-only data of
 * this program, so the loop replaces them only while it holds cp_maplock,
 * and the command loop holds it while it handles a command.
 */
static pthread_mutex_t cp_maplock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t cp_loop_thread;
static bool cp_loop_running;
static volatile int cp_loop_stop;
static volatile unsigned long cp_loop_rounds;
static char *cp_dof_page;		/* first page of the DOF */
static size_t cp_dof_len;		/* the DOF's pages, in bytes */
static off_t cp_dof_off;		/* their offset in the executable */
static int cp_self_fd = -1;
static char *cp_crafted;		/* the same bytes, provider renamed */

struct cp_phdr_find {
	uintptr_t	addr;
	off_t		off;
	bool		found;
};

static int
find_phdr(struct dl_phdr_info *info, size_t size __unused, void *arg)
{
	struct cp_phdr_find *f = arg;
	const Elf_Phdr *ph;
	uintptr_t start;

	for (int i = 0; i < info->dlpi_phnum; i++) {
		ph = &info->dlpi_phdr[i];
		if (ph->p_type != PT_LOAD)
			continue;
		start = info->dlpi_addr + ph->p_vaddr;
		if (f->addr >= start && f->addr < start + ph->p_memsz) {
			f->off = ph->p_offset + (f->addr - start);
			f->found = true;
			return (1);
		}
	}
	return (0);
}

/* Locate the DOF's pages and their offset in the executable file. */
static int
dof_pages(void)
{
	const struct cp_dof_hdr *hdr = (const void *)cp_dof;
	struct cp_phdr_find f;
	uintptr_t start, end;

	if (cp_dof == NULL)
		return (ENOENT);
	start = trunc_page((uintptr_t)cp_dof);
	end = round_page((uintptr_t)cp_dof + hdr->dofh_loadsz);
	f.addr = start;
	f.found = false;
	dl_iterate_phdr(find_phdr, &f);
	if (!f.found || (f.off & PAGE_MASK) != 0)
		return (ENOENT);
	cp_dof_page = (char *)start;
	cp_dof_len = end - start;
	cp_dof_off = f.off;
	return (0);
}

/* Turn the DOF's pages into private copies holding the same bytes. */
static int
cow_dof(void)
{
	volatile char *c;
	int error;

	error = dof_pages();
	if (error == 0 && mprotect(cp_dof_page, cp_dof_len,
	    PROT_READ | PROT_WRITE) != 0)
		error = errno;
	if (error == 0) {
		c = cp_dof_page;
		*c = *c;
		if (mprotect(cp_dof_page, cp_dof_len, PROT_READ) != 0)
			error = errno;
	}
	return (error);
}

static void
map_file_back(void)
{

	if (mmap(cp_dof_page, cp_dof_len, PROT_READ, MAP_PRIVATE | MAP_FIXED,
	    cp_self_fd, cp_dof_off) == MAP_FAILED)
		_exit(80);
}

static void *
loop_unmap(void *arg)
{
	bool crafted = arg != NULL;

	while (!cp_loop_stop) {
		pthread_mutex_lock(&cp_maplock);
		if (munmap(cp_dof_page, cp_dof_len) != 0)
			_exit(81);
		if (crafted) {
			if (mmap(cp_dof_page, cp_dof_len, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0) ==
			    MAP_FAILED)
				_exit(82);
			memcpy(cp_dof_page, cp_crafted, cp_dof_len);
			if (mprotect(cp_dof_page, cp_dof_len, PROT_READ) != 0)
				_exit(83);
			usleep(200);
			if (munmap(cp_dof_page, cp_dof_len) != 0)
				_exit(84);
		}
		map_file_back();
		pthread_mutex_unlock(&cp_maplock);
		cp_loop_rounds++;
		usleep(200);
	}
	return (NULL);
}

static void *
loop_churn(void *arg __unused)
{
	void *p;

	while (!cp_loop_stop) {
		p = mmap(NULL, 64 * 1024, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
		if (p != MAP_FAILED)
			munmap(p, 64 * 1024);
		cp_loop_rounds++;
		usleep(1000);
	}
	return (NULL);
}

static int
loop_start(const char *mode)
{
	void *(*fn)(void *);
	void *arg;
	char *name;

	if (cp_loop_running)
		return (EBUSY);
	arg = NULL;
	if (strcmp(mode, "churn") == 0)
		fn = loop_churn;
	else if (strcmp(mode, "unmap") == 0 || strcmp(mode, "crafted") == 0) {
		fn = loop_unmap;
		if (dof_pages() != 0)
			return (ENOENT);
		if (cp_self_fd < 0 && (cp_self_fd = open(cp_self, O_RDONLY)) < 0)
			return (errno);
		if (strcmp(mode, "crafted") == 0) {
			cp_crafted = malloc(cp_dof_len);
			if (cp_crafted == NULL)
				return (ENOMEM);
			memcpy(cp_crafted, cp_dof_page, cp_dof_len);
			name = memmem(cp_crafted, cp_dof_len, "cpusdt", 7);
			if (name == NULL)
				return (ENOENT);
			name[5] = 'x';
			arg = cp_crafted;
		}
	} else
		return (EINVAL);
	cp_loop_stop = 0;
	cp_loop_rounds = 0;
	if (pthread_create(&cp_loop_thread, NULL, fn, arg) != 0)
		return (EAGAIN);
	cp_loop_running = true;
	return (0);
}

static void
loop_end(void)
{

	if (cp_loop_running) {
		cp_loop_stop = 1;
		pthread_join(cp_loop_thread, NULL);
		cp_loop_running = false;
	}
	reply("STOP %lu\n", (unsigned long)cp_loop_rounds);
}
#endif

static void
handle(const char *cmd)
{
	unsigned long long v;

	if (strcmp(cmd, "canary") == 0)
		reply("CANARY %#" PRIx64 "\n", (uint64_t)cp_canary);
	else if (sscanf(cmd, "set %llx", &v) == 1) {
		cp_canary = v;
		reply("SET 0\n");
	} else if (sscanf(cmd, "shield %llx", &v) == 1)
		reply("SHIELD %d\n", shield_self((uint32_t)v));
	else if (sscanf(cmd, "mint %llx", &v) == 1)
		mint_token((uint32_t)v);
	else if (strcmp(cmd, "pid") == 0)
		reply("PID %d\n", (int)getpid());
	else if (strcmp(cmd, "sigcount") == 0)
		reply("SIGCOUNT %d\n", (int)cp_sigusr1);
	else if (strcmp(cmd, "exec") == 0) {
		execl(cp_self, "capprotect_usdt_helper", "plain",
		    (char *)NULL);
		reply("EXEC %d\n", errno);
	} else if (strcmp(cmd, "ticks") == 0)
		reply("TICKS %d\n", cp_ticks);
	else if (strcmp(cmd, "dof") == 0)
		report_dof();
	else if (strcmp(cmd, "heapdof") == 0)
		report_heapdof();
#ifdef WITH_DTRACE
	else if (strcmp(cmd, "cowdof") == 0)
		reply("COWDOF %d\n", cow_dof());
	else if (strncmp(cmd, "loop ", 5) == 0)
		reply("LOOP %d\n", loop_start(cmd + 5));
#endif
	else if (strcmp(cmd, "exit") == 0)
		_exit(0);
	else
		reply("ERROR unknown command\n");
}

static void __dead2
serve(void)
{
	char cmd[128];

	while (read_command(cmd, sizeof(cmd))) {
#ifdef WITH_DTRACE
		if (strcmp(cmd, "stop") == 0) {
			loop_end();
			continue;
		}
		pthread_mutex_lock(&cp_maplock);
		handle(cmd);
		pthread_mutex_unlock(&cp_maplock);
#else
		handle(cmd);
#endif
	}
	_exit(0);
}

int
main(int argc, char **argv)
{
	uint32_t flags;
	int error;

	if (argc != 2) {
		fprintf(stderr, "usage: capprotect_usdt_helper MODE\n");
		return (2);
	}
	/* "exec" re-executes argv[0]: the tests run the fixture by full path. */
	cp_self = argv[0];
	signal(SIGALRM, on_alarm);
	signal(SIGUSR1, on_usr1);
	signal(SIGPIPE, SIG_IGN);
	alarm(FIXTURE_TIMEOUT);

	if (strcmp(argv[1], "plain") == 0)
		flags = 0;
	else if (strcmp(argv[1], "self") == 0)
		flags = CP_SF_PTRACE | CP_SF_SIGNAL | CP_SF_SIGKILL;
	else if (strcmp(argv[1], "self-signal-only") == 0)
		flags = CP_SF_SIGNAL | CP_SF_SIGKILL;
	else if (strcmp(argv[1], "capmode") == 0) {
		char *nargv[] = { argv[0], __DECONST(char *, "plain"),
		    NULL };
		char fds[32];
		int fd, lib, usrlib;

		/*
		 * In capability mode the run-time linker opens the new
		 * image's libraries through LD_LIBRARY_PATH_FDS only.
		 */
		fd = open(argv[0], O_RDONLY | O_EXEC);
		lib = open("/lib", O_RDONLY | O_DIRECTORY);
		usrlib = open("/usr/lib", O_RDONLY | O_DIRECTORY);
		snprintf(fds, sizeof(fds), "%d:%d", lib, usrlib);
		if (fd < 0 || lib < 0 || usrlib < 0 ||
		    setenv("LD_LIBRARY_PATH_FDS", fds, 1) != 0 ||
		    cap_enter() != 0) {
			reply("FAILED capmode %d\n", errno);
			return (1);
		}
		fexecve(fd, nargv, environ);
		reply("FAILED fexecve %d\n", errno);
		return (1);
	} else if (strncmp(argv[1], "flags=", 6) == 0)
		flags = (uint32_t)strtoul(argv[1] + 6, NULL, 16);
	else {
		fprintf(stderr, "capprotect_usdt_helper: unknown mode %s\n",
		    argv[1]);
		return (2);
	}
	if (flags != 0 && (error = shield_self(flags)) != 0) {
		reply("FAILED shield %d\n", error);
		return (1);
	}
#ifdef WITH_DTRACE
	find_dof(argv[0]);
#endif
	CPUSDT_READY();
	reply("READY pid=%d canary=%p value=%#" PRIx64 "\n", (int)getpid(),
	    (void *)(uintptr_t)&cp_canary, (uint64_t)cp_canary);
	serve();
}
