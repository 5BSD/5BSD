/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * The Linux-ABI half of the boundary pins (dq-boundary design, part b0,
 * section 6.1 items 1-3, 6 and 18): what a Linux process that is NOT
 * attached to a dq(4) controller gets from the calls that name another
 * process, from TIOCSTI on its controlling terminal and from System V
 * IPC.  The program prints one row per call, "name value", with nothing
 * in a row that varies between runs: a result of zero or more that is a
 * descriptor, a count or an order is printed as 0, an error as the
 * negative Linux errno.  The callers compare the rows with what the
 * kernel of commit f52f6da3d34 printed (linux_boundary_test.sh and
 * procnet_outside_test:linux_probe_attached_target).
 *
 * Freestanding (no Linux libc), built at test time as
 * fdops/linux_fdops.c is.
 *
 *   run SELF         as root: become the unprivileged uid, exec "main".
 *   main SELF        every row, against a target this program starts.
 *   probe PID TID    the by-pid rows against a process the caller made;
 *                    as root, becomes the unprivileged uid first.
 *   target           the process the rows name: starts a second thread,
 *                    writes its pid and that thread's tid (two ints) to
 *                    descriptor 1, reads descriptor 0 to end of file.
 *   target-drop SELF as root: become the unprivileged uid, exec "target"
 *                    (a process that changed uid without exec is P_SUGID
 *                    and refuses every debugger: not what is pinned).
 */

#define	SYS_read		0
#define	SYS_write		1
#define	SYS_open		2
#define	SYS_close		3
#define	SYS_ioctl		16
#define	SYS_pipe		22
#define	SYS_shmget		29
#define	SYS_shmat		30
#define	SYS_shmctl		31
#define	SYS_dup2		33
#define	SYS_pause		34
#define	SYS_nanosleep		35
#define	SYS_alarm		37
#define	SYS_getpid		39
#define	SYS_clone		56
#define	SYS_fork		57
#define	SYS_execve		59
#define	SYS_exit		60
#define	SYS_wait4		61
#define	SYS_kill		62
#define	SYS_semget		64
#define	SYS_semop		65
#define	SYS_semctl		66
#define	SYS_shmdt		67
#define	SYS_msgget		68
#define	SYS_msgsnd		69
#define	SYS_msgrcv		70
#define	SYS_msgctl		71
#define	SYS_readlink		89
#define	SYS_ptrace		101
#define	SYS_getuid		102
#define	SYS_setuid		105
#define	SYS_setgid		106
#define	SYS_setsid		112
#define	SYS_setgroups		116
#define	SYS_exit_group		231
#define	SYS_tgkill		234
#define	SYS_get_robust_list	274
#define	SYS_process_vm_readv	310
#define	SYS_kcmp		312
#define	SYS_pidfd_send_signal	424
#define	SYS_pidfd_open		434
#define	SYS_pidfd_getfd		438

#define	EINTR		4

#define	O_RDONLY	0
#define	O_RDWR		2
#define	O_NOCTTY	0400
#define	O_DIRECTORY	0200000

#define	WNOHANG		1
#define	__WALL		0x40000000

#define	PTRACE_ATTACH	16
#define	PTRACE_DETACH	17

#define	TIOCSTI		0x5412
#define	TIOCGPTN	0x80045430
#define	TIOCSPTLCK	0x40045431

#define	IPC_CREAT	01000
#define	IPC_EXCL	02000
#define	IPC_NOWAIT	04000
#define	IPC_RMID	0
#define	IPC_SET		1
#define	IPC_STAT	2
#define	IPC_INFO	3
#define	MSG_INFO	12
#define	SHM_STAT	13
#define	SHM_INFO	14
#define	GETPID		11
#define	GETVAL		12
#define	GETALL		13
#define	GETNCNT		14
#define	GETZCNT		15
#define	SETVAL		16
#define	SETALL		17
#define	SEM_STAT	18
#define	SEM_INFO	19
#define	SEM_UNDO	0x1000

#define	CLONE_VM		0x00000100
#define	CLONE_FS		0x00000200
#define	CLONE_FILES		0x00000400
#define	CLONE_SIGHAND		0x00000800
#define	CLONE_THREAD		0x00010000
#define	CLONE_SYSVSEM		0x00040000
#define	CLONE_PARENT_SETTID	0x00100000
#define	CLONE_CHILD_CLEARTID	0x00200000
#define	THREAD_FLAGS	(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | \
    CLONE_THREAD | CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)

/* The unprivileged identity of procnet_common.h. */
#define	PN_UID		4242
#define	PN_GID		4242

/* A tid that names nothing, and a row that could not be asked. */
#define	NOTID		0x3ffffffe
#define	NA		-9999

struct ltimespec {
	long	tv_sec;
	long	tv_nsec;
};

struct liovec {
	void		*iov_base;
	unsigned long	 iov_len;
};

struct lsembuf {
	unsigned short	sem_num;
	short		sem_op;
	short		sem_flg;
};

struct lmsg {
	long	mtype;
	char	mtext[16];
};

static long
call(long nr, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long result;

	__asm__ volatile("syscall" : "=a"(result) :
	    "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (result);
}

#define	S0(n)			call(n, 0, 0, 0, 0, 0, 0)
#define	S1(n, a)		call(n, (long)(a), 0, 0, 0, 0, 0)
#define	S2(n, a, b)		call(n, (long)(a), (long)(b), 0, 0, 0, 0)
#define	S3(n, a, b, c)		call(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define	S4(n, a, b, c, d)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), 0, 0)
#define	S5(n, a, b, c, d, e)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), 0)
#define	S6(n, a, b, c, d, e, f)	call(n, (long)(a), (long)(b), (long)(c), \
    (long)(d), (long)(e), (long)(f))

/*
 * long l_thread(long flags, void *stack, int *ptid, int *ctid): clone a
 * thread that sleeps for ever; it never returns through a C frame.
 */
long l_thread(long, void *, int *, int *);
__asm__(
	".text\n"
	"l_thread:\n"
	"	mov %rcx, %r10\n"
	"	xor %r8, %r8\n"
	"	mov $56, %eax\n"
	"	syscall\n"
	"	test %rax, %rax\n"
	"	jnz 1f\n"
	"2:	mov $34, %eax\n"
	"	syscall\n"
	"	jmp 2b\n"
	"1:	ret\n");

/* The compiler may emit these for struct copies and zeroing. */
void *memset(void *, int, unsigned long);
void *memcpy(void *, const void *, unsigned long);
void *
memset(void *p, int v, unsigned long n)
{
	volatile char *c = p;

	while (n-- > 0)
		*c++ = (char)v;
	return (p);
}
void *
memcpy(void *d, const void *s, unsigned long n)
{
	volatile char *dc = d;
	const char *sc = s;

	while (n-- > 0)
		*dc++ = *sc++;
	return (d);
}

static unsigned long
slen(const char *s)
{
	unsigned long n = 0;

	while (s[n] != '\0')
		n++;
	return (n);
}

static int
seq(const char *a, const char *b)
{

	while (*a != '\0' && *a == *b) {
		a++;
		b++;
	}
	return (*a == *b);
}

static int
sfind(const char *hay, long n, const char *needle)
{
	long i, j, m = (long)slen(needle);

	for (i = 0; i + m <= n; i++) {
		for (j = 0; j < m && hay[i + j] == needle[j]; j++)
			continue;
		if (j == m)
			return (1);
	}
	return (0);
}

static void
out(const char *s)
{

	(void)S3(SYS_write, 1, s, slen(s));
}

static char *
fmtn(long v, char *end)
{
	unsigned long u = v < 0 ? -(unsigned long)v : (unsigned long)v;

	*--end = '\0';
	do {
		*--end = '0' + u % 10;
		u /= 10;
	} while (u != 0);
	if (v < 0)
		*--end = '-';
	return (end);
}

static long
aton(const char *s)
{
	long v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (*s++ - '0');
	return (v);
}

static const char *g_prefix = "";

/* One row; the callers hold the table. */
static void
row(const char *name, long got)
{
	char buf[24];

	out(g_prefix);
	out(name);
	out(" ");
	out(fmtn(got, buf + sizeof(buf)));
	out("\n");
}

/* A result that is a descriptor, a count or an order: 0; else the errno. */
static long
z(long r)
{

	return (r >= 0 ? 0 : r);
}

/*
 * No wait here is unbounded: a process that is still running when its
 * time is up dies of SIGALRM, and that is a row (a status of 14) or the
 * program's failure, not a hung test.
 */
static void
bound(long seconds)
{

	(void)S1(SYS_alarm, seconds);
}

static void
nap(void)
{
	struct ltimespec ts = { 0, 10 * 1000 * 1000 };

	(void)S2(SYS_nanosleep, &ts, 0);
}

static void
drop(void)
{
	unsigned int g = PN_GID;

	if (S0(SYS_getuid) != 0)
		return;
	if (S2(SYS_setgroups, 1, &g) != 0 || S1(SYS_setgid, PN_GID) != 0 ||
	    S1(SYS_setuid, PN_UID) != 0)
		(void)S1(SYS_exit_group, 90);
}

static void
procpath(char *buf, long pid, const char *node)
{
	char num[24], *p;

	*buf = '\0';
	memcpy(buf, "/proc/", 6);
	buf += 6;
	p = fmtn(pid, num + sizeof(num));
	memcpy(buf, p, slen(p));
	buf += slen(p);
	memcpy(buf, node, slen(node) + 1);
}

/* A word the target and the actor both have at this address (static). */
static volatile long g_magic = 0x626f756e64617279;

/*
 * The by-pid rows.  tid is a thread of pid that is not its first; for a
 * pid that names nothing it is NOTID.
 */
static void
probe(long pid, long tid)
{
	struct liovec liov, riov;
	char path[64], buf[256];
	void *head;
	unsigned long len;
	long pfd, r, self, word;
	int i, status;

	self = S0(SYS_getpid);
	row("kill(pid, 0)", S2(SYS_kill, pid, 0));
	row("tgkill(pid, pid, 0)", S3(SYS_tgkill, pid, pid, 0));
	row("tgkill(pid, tid, 0)", S3(SYS_tgkill, pid, tid, 0));
	pfd = S2(SYS_pidfd_open, pid, 0);
	row("pidfd_open(pid)", z(pfd));
	row("pidfd_send_signal(pidfd, 0)", pfd < 0 ? NA :
	    S4(SYS_pidfd_send_signal, pfd, 0, 0, 0));
	row("pidfd_getfd(pidfd, 0)", pfd < 0 ? NA :
	    z(S3(SYS_pidfd_getfd, pfd, 0, 0)));
	row("pidfd_open(tid of a second thread)",
	    z(S2(SYS_pidfd_open, tid, 0)));
	row("kcmp(self, pid, KCMP_FILE, 0, 0)",
	    z(S5(SYS_kcmp, self, pid, 0, 0, 0)));
	word = 0;
	liov.iov_base = &word;
	liov.iov_len = sizeof(word);
	riov.iov_base = (void *)&g_magic;
	riov.iov_len = sizeof(word);
	r = S6(SYS_process_vm_readv, pid, &liov, 1, &riov, 1, 0);
	row("process_vm_readv(pid)", r);
	row("  read the target's word", r < 0 ? NA : word == g_magic);
	head = (void *)0;
	len = 0;
	row("get_robust_list(tid of a second thread)",
	    S3(SYS_get_robust_list, tid, &head, &len));
	row("get_robust_list(pid)", S3(SYS_get_robust_list, pid, &head,
	    &len));
	procpath(path, pid, "/mem");
	row("open(/proc/pid/mem, O_RDONLY)", z(S2(SYS_open, path, O_RDONLY)));
	procpath(path, pid, "/fd");
	row("open(/proc/pid/fd, O_DIRECTORY)", z(S2(SYS_open, path,
	    O_RDONLY | O_DIRECTORY)));
	procpath(path, pid, "/cwd");
	row("readlink(/proc/pid/cwd)", z(S3(SYS_readlink, path, buf,
	    sizeof(buf))));
	procpath(path, pid, "/exe");
	row("readlink(/proc/pid/exe)", z(S3(SYS_readlink, path, buf,
	    sizeof(buf))));

	/* Last: it stops the target. */
	r = S4(SYS_ptrace, PTRACE_ATTACH, pid, 0, 0);
	row("ptrace(PTRACE_ATTACH, pid)", r);
	if (r != 0) {
		row("  wait4 reports the stop", NA);
		row("  ptrace(PTRACE_DETACH, pid)", NA);
		return;
	}
	status = 0;
	r = 0;
	for (i = 0; i < 2000 && r == 0; i++) {
		r = S4(SYS_wait4, pid, &status, WNOHANG | __WALL, 0);
		if (r == 0)
			nap();
	}
	/* Stopped by SIGSTOP (19): 0x137f. */
	row("  wait4 reports the stop", r == pid ? status : r < 0 ? r : -1);
	row("  ptrace(PTRACE_DETACH, pid)", S4(SYS_ptrace, PTRACE_DETACH,
	    pid, 0, 0));
}

static char stack1[16384] __attribute__((aligned(16)));
static int g_ptid, g_ctid;

static int
target(void)
{
	char buf[64];
	int ids[2];
	long r;

	if (l_thread(THREAD_FLAGS, stack1 + sizeof(stack1), &g_ptid,
	    &g_ctid) <= 0)
		return (91);
	ids[0] = (int)S0(SYS_getpid);
	ids[1] = g_ptid;
	if (S3(SYS_write, 1, ids, sizeof(ids)) != (long)sizeof(ids))
		return (92);
	/* A debugger's stop may interrupt the read. */
	while ((r = S3(SYS_read, 0, buf, sizeof(buf))) > 0 || r == -EINTR)
		continue;
	(void)S1(SYS_exit_group, 0);
	return (0);
}

/* TIOCSTI by an unprivileged session leader on its controlling terminal. */
static void
tiocsti(void)
{
	char path[32], num[24], buf[8], *p;
	long m, pid, r, r2, s;
	int n, status, zero = 0;

	m = S2(SYS_open, "/dev/ptmx", O_RDWR | O_NOCTTY);
	row("open(/dev/ptmx)", z(m));
	row("ioctl(TIOCSPTLCK)", S3(SYS_ioctl, m, TIOCSPTLCK, &zero));
	n = -1;
	row("ioctl(TIOCGPTN)", S3(SYS_ioctl, m, TIOCGPTN, &n));
	memcpy(path, "/dev/pts/", 9);
	p = fmtn(n, num + sizeof(num));
	memcpy(path + 9, p, slen(p) + 1);
	pid = S0(SYS_fork);
	if (pid == 0) {
		bound(60);
		row("setsid()", z(S0(SYS_setsid)));
		/* A session leader's first terminal becomes its own. */
		s = S2(SYS_open, path, O_RDWR);
		row("open(the slave)", z(s));
		r = S3(SYS_ioctl, s, TIOCSTI, "x");
		row("ioctl(TIOCSTI, 'x')", r);
		r2 = S3(SYS_ioctl, s, TIOCSTI, "\n");
		row("ioctl(TIOCSTI, newline)", r2);
		/*
		 * Today both are EIO (linux_ioctl.c refuses TIOCSTI as
		 * Linux 6.2 does by default) and nothing was pushed: a
		 * read would sleep, so there is one only after a push.
		 */
		if (r == 0 && r2 == 0) {
			memset(buf, 0, sizeof(buf));
			r = S3(SYS_read, s, buf, sizeof(buf));
			row("read of the terminal", r);
			row("  is the line pushed", r == 2 &&
			    buf[0] == 'x' && buf[1] == '\n');
		}
		(void)S1(SYS_exit_group, 0);
	}
	r = S4(SYS_wait4, pid, &status, 0, 0);
	row("the session leader's exit", r == pid ? status : r);
	(void)S1(SYS_close, m);
}

static int
listed(const char *path, long key)
{
	static char buf[65536];
	char num[24], pat[32], *p;
	long fd, n, r;

	fd = S2(SYS_open, path, O_RDONLY);
	if (fd < 0)
		return ((int)fd);
	n = 0;
	while (n < (long)sizeof(buf) &&
	    (r = S3(SYS_read, fd, buf + n, sizeof(buf) - n)) > 0)
		n += r;
	(void)S1(SYS_close, fd);
	/* A line of the listing starts with the key, right-aligned. */
	p = fmtn(key, num + sizeof(num));
	pat[0] = ' ';
	memcpy(pat + 1, p, slen(p));
	pat[1 + slen(p)] = ' ';
	pat[2 + slen(p)] = '\0';
	return (sfind(buf, n, pat));
}

/*
 * System V IPC of two unattached processes of one uid: this process
 * makes, a fork uses.  The fork is handed IPC_PRIVATE ids over a pipe.
 */
static void
sysv(void)
{
	static char big[4096];
	struct lsembuf op;
	struct lmsg m;
	unsigned short vals[2];
	long key, pid, r, self, shm, sem, msg, pshm, psem, pmsg;
	int ids[3], p[2], status;
	char *a;

	self = S0(SYS_getpid);
	key = 0x504c0000 | (self & 0xffff);

	shm = S3(SYS_shmget, key, 8192, IPC_CREAT | IPC_EXCL | 0600);
	row("shmget(key, IPC_CREAT|IPC_EXCL)", z(shm));
	a = (char *)S3(SYS_shmat, shm, 0, 0);
	row("shmat", (long)a < 0 && (long)a > -4096 ? (long)a : 0);
	memcpy(a, "sysv", 4);
	sem = S3(SYS_semget, key, 2, IPC_CREAT | IPC_EXCL | 0600);
	row("semget(key, IPC_CREAT|IPC_EXCL)", z(sem));
	msg = S2(SYS_msgget, key, IPC_CREAT | IPC_EXCL | 0600);
	row("msgget(key, IPC_CREAT|IPC_EXCL)", z(msg));
	m.mtype = 1;
	memcpy(m.mtext, "msg", 3);
	row("msgsnd", S4(SYS_msgsnd, msg, &m, 3, 0));

	pshm = S3(SYS_shmget, 0, 4096, 0600);
	row("shmget(IPC_PRIVATE)", z(pshm));
	psem = S3(SYS_semget, 0, 1, 0600);
	row("semget(IPC_PRIVATE)", z(psem));
	pmsg = S2(SYS_msgget, 0, 0600);
	row("msgget(IPC_PRIVATE)", z(pmsg));

	row("/proc/sysvipc/shm lists the key", listed("/proc/sysvipc/shm",
	    key));
	row("/proc/sysvipc/sem lists the key", listed("/proc/sysvipc/sem",
	    key));
	row("/proc/sysvipc/msg lists the key", listed("/proc/sysvipc/msg",
	    key));

	(void)S1(SYS_pipe, p);
	pid = S0(SYS_fork);
	if (pid == 0) {
		bound(60);
		g_prefix = "other: ";
		r = S3(SYS_shmget, key, 0, 0);
		row("shmget(key) is the maker's id", r == shm);
		row("shmget(key, IPC_CREAT|IPC_EXCL)", S3(SYS_shmget, key,
		    8192, IPC_CREAT | IPC_EXCL | 0600));
		row("semget(key) is the maker's id", S3(SYS_semget, key, 0,
		    0) == sem);
		row("semget(key, IPC_CREAT|IPC_EXCL)", S3(SYS_semget, key, 2,
		    IPC_CREAT | IPC_EXCL | 0600));
		row("msgget(key) is the maker's id", S2(SYS_msgget, key, 0) ==
		    msg);
		row("msgget(key, IPC_CREAT|IPC_EXCL)", S2(SYS_msgget, key,
		    IPC_CREAT | IPC_EXCL | 0600));
		memset(&m, 0, sizeof(m));
		row("msgrcv of the maker's message", S5(SYS_msgrcv, msg, &m,
		    sizeof(m.mtext), 0, IPC_NOWAIT));
		row("msgrcv with none left", S5(SYS_msgrcv, msg, &m,
		    sizeof(m.mtext), 0, IPC_NOWAIT));

		row("read of the ids", S3(SYS_read, p[0], ids, sizeof(ids)));
		a = (char *)S3(SYS_shmat, ids[0], 0, 0);
		row("shmat(the IPC_PRIVATE id)", (long)a < 0 &&
		    (long)a > -4096 ? (long)a : 0);
		memcpy(a, "priv", 4);
		op.sem_num = 0;
		op.sem_op = 3;
		op.sem_flg = 0;
		row("semop(the IPC_PRIVATE id, +3)", S3(SYS_semop, ids[1],
		    &op, 1));
		m.mtype = 2;
		memcpy(m.mtext, "priv", 4);
		row("msgsnd(the IPC_PRIVATE id)", S4(SYS_msgsnd, ids[2], &m,
		    4, 0));

		/* An adjustment with SEM_UNDO is taken back at exit. */
		op.sem_num = 1;
		op.sem_op = 2;
		op.sem_flg = SEM_UNDO;
		row("semop(+2, SEM_UNDO)", S3(SYS_semop, sem, &op, 1));
		row("GETVAL before exit", S4(SYS_semctl, sem, 1, GETVAL, 0));
		(void)S1(SYS_exit_group, 0);
	}
	ids[0] = (int)pshm;
	ids[1] = (int)psem;
	ids[2] = (int)pmsg;
	(void)S3(SYS_write, p[1], ids, sizeof(ids));
	r = S4(SYS_wait4, pid, &status, 0, 0);
	row("the other process's exit", r == pid ? status : r);
	row("GETVAL after its exit", S4(SYS_semctl, sem, 1, GETVAL, 0));
	a = (char *)S3(SYS_shmat, pshm, 0, 0);
	row("the IPC_PRIVATE segment has its bytes", a[0] == 'p' &&
	    a[3] == 'v');
	row("GETVAL of the IPC_PRIVATE set", S4(SYS_semctl, psem, 0, GETVAL,
	    0));
	memset(&m, 0, sizeof(m));
	row("msgrcv from the IPC_PRIVATE queue", S5(SYS_msgrcv, pmsg, &m,
	    sizeof(m.mtext), 2, IPC_NOWAIT));

	/* Every control command. */
	row("shmctl(IPC_STAT)", S3(SYS_shmctl, shm, IPC_STAT, big));
	row("shmctl(IPC_SET) of what IPC_STAT gave", S3(SYS_shmctl, shm,
	    IPC_SET, big));
	row("shmctl(SHM_STAT) by index is the id", S3(SYS_shmctl,
	    shm & 0xffff, SHM_STAT, big) == shm);
	row("shmctl(IPC_INFO)", z(S3(SYS_shmctl, 0, IPC_INFO, big)));
	row("shmctl(SHM_INFO)", z(S3(SYS_shmctl, 0, SHM_INFO, big)));
	row("shmctl(no such command)", S3(SYS_shmctl, shm, 999, big));
	row("semctl(IPC_STAT)", S4(SYS_semctl, sem, 0, IPC_STAT, big));
	row("semctl(IPC_SET) of what IPC_STAT gave", S4(SYS_semctl, sem, 0,
	    IPC_SET, big));
	row("semctl(SEM_STAT) by index is the id", S4(SYS_semctl,
	    sem & 0xffff, 0, SEM_STAT, big) == sem);
	row("semctl(IPC_INFO)", z(S4(SYS_semctl, 0, 0, IPC_INFO, big)));
	row("semctl(SEM_INFO)", z(S4(SYS_semctl, 0, 0, SEM_INFO, big)));
	row("semctl(SETVAL, 5)", S4(SYS_semctl, sem, 0, SETVAL, 5));
	row("semctl(GETVAL)", S4(SYS_semctl, sem, 0, GETVAL, 0));
	row("semctl(GETPID) is the caller", S4(SYS_semctl, sem, 0, GETPID,
	    0) == self);
	row("semctl(GETNCNT)", S4(SYS_semctl, sem, 0, GETNCNT, 0));
	row("semctl(GETZCNT)", S4(SYS_semctl, sem, 0, GETZCNT, 0));
	vals[0] = 0;
	vals[1] = 4;
	row("semctl(SETALL)", S4(SYS_semctl, sem, 0, SETALL, vals));
	vals[0] = vals[1] = 9;
	row("semctl(GETALL)", S4(SYS_semctl, sem, 0, GETALL, vals));
	row("  values", vals[0] * 10 + vals[1]);
	row("semctl(no such command)", S4(SYS_semctl, sem, 0, 999, big));
	row("msgctl(IPC_STAT)", S3(SYS_msgctl, msg, IPC_STAT, big));
	row("msgctl(IPC_SET) of what IPC_STAT gave", S3(SYS_msgctl, msg,
	    IPC_SET, big));
	row("msgctl(IPC_INFO)", z(S3(SYS_msgctl, 0, IPC_INFO, big)));
	row("msgctl(MSG_INFO)", z(S3(SYS_msgctl, 0, MSG_INFO, big)));
	row("msgctl(no such command)", S3(SYS_msgctl, msg, 999, big));

	/* Removal under a sleeper: semaphore 0 is 0. */
	pid = S0(SYS_fork);
	if (pid == 0) {
		bound(60);
		op.sem_num = 0;
		op.sem_op = -1;
		op.sem_flg = 0;
		r = S3(SYS_semop, sem, &op, 1);
		(void)S1(SYS_exit_group, r < 0 ? -r : 0);
	}
	for (r = 0, status = 0; status < 2000 && r != 1; status++) {
		r = S4(SYS_semctl, sem, 0, GETNCNT, 0);
		if (r != 1)
			nap();
	}
	row("a fork sleeps in semop(-1): GETNCNT", r);
	row("semctl(IPC_RMID) under the sleeper", S4(SYS_semctl, sem, 0,
	    IPC_RMID, 0));
	r = S4(SYS_wait4, pid, &status, 0, 0);
	/* The sleeper exits with its errno: EIDRM is 43 (0x2b00). */
	row("the sleeper's exit", r == pid ? status : r);

	/* IPC_RMID of a mapped segment. */
	a = (char *)S3(SYS_shmat, shm, 0, 0);
	row("shmctl(IPC_RMID) while mapped", S3(SYS_shmctl, shm, IPC_RMID,
	    0));
	row("the mapping still reads", a[0] == 's' && a[3] == 'v');
	row("shmget(key) after", S3(SYS_shmget, key, 0, 0));
	row("shmat(the id) after", S3(SYS_shmat, shm, 0, 0));
	row("shmdt", S1(SYS_shmdt, a));
	row("msgctl(IPC_RMID)", S3(SYS_msgctl, msg, IPC_RMID, 0));
	row("msgget(key) after", S2(SYS_msgget, key, 0));
	row("semget(key) after", S3(SYS_semget, key, 0, 0));
	row("/proc/sysvipc/shm lists the key after",
	    listed("/proc/sysvipc/shm", key));
	row("/proc/sysvipc/sem lists the key after",
	    listed("/proc/sysvipc/sem", key));
	row("/proc/sysvipc/msg lists the key after",
	    listed("/proc/sysvipc/msg", key));
	row("shmctl(invalid id)", S3(SYS_shmctl, 0x7fffffff, IPC_STAT, big));
	row("semctl(invalid id)", S4(SYS_semctl, 0x7fffffff, 0, GETVAL, 0));
	row("msgctl(invalid id)", S3(SYS_msgctl, 0x7fffffff, IPC_STAT, big));
	(void)S3(SYS_shmctl, pshm, IPC_RMID, 0);
	(void)S4(SYS_semctl, psem, 0, IPC_RMID, 0);
	(void)S3(SYS_msgctl, pmsg, IPC_RMID, 0);
}

static int
test_main(char *self)
{
	char *xargv[3], *xenvp[1];
	long actor, pid, r;
	int ids[2], status, tin[2], tout[2];

	bound(280);
	/* A target that is not the actor's child or parent. */
	if (S1(SYS_pipe, tin) != 0 || S1(SYS_pipe, tout) != 0)
		return (93);
	pid = S0(SYS_fork);
	if (pid == 0) {
		bound(60);
		(void)S2(SYS_dup2, tin[0], 0);
		(void)S2(SYS_dup2, tout[1], 1);
		(void)S1(SYS_close, tin[1]);
		(void)S1(SYS_close, tout[0]);
		xargv[0] = self;
		xargv[1] = (char *)"target";
		xargv[2] = (char *)0;
		xenvp[0] = (char *)0;
		(void)S3(SYS_execve, self, xargv, xenvp);
		(void)S1(SYS_exit_group, 94);
	}
	(void)S1(SYS_close, tin[0]);
	(void)S1(SYS_close, tout[1]);
	if (S3(SYS_read, tout[0], ids, sizeof(ids)) != (long)sizeof(ids) ||
	    ids[0] != pid)
		return (95);
	actor = S0(SYS_fork);
	if (actor == 0) {
		bound(60);
		g_prefix = "live: ";
		probe(ids[0], ids[1]);
		(void)S1(SYS_exit_group, 0);
	}
	r = S4(SYS_wait4, actor, &status, 0, 0);
	row("the actor's exit", r == actor ? status : r);
	(void)S1(SYS_close, tin[1]);
	r = S4(SYS_wait4, pid, &status, 0, 0);
	row("the target's exit", r == pid ? status : r);

	/* The same calls on a pid and a tid that name nothing. */
	g_prefix = "dead: ";
	probe(pid, NOTID);
	g_prefix = "tty: ";
	tiocsti();
	g_prefix = "sysv: ";
	sysv();
	return (0);
}

static int
start(int argc, char **argv)
{
	char *xargv[4], *xenvp[1];

	if (argc < 2)
		return (64);
	if (seq(argv[1], "target"))
		return (target());
	if (seq(argv[1], "probe") && argc == 4) {
		drop();
		probe(aton(argv[2]), aton(argv[3]));
		return (0);
	}
	if (seq(argv[1], "main") && argc == 3)
		return (test_main(argv[2]));
	if ((seq(argv[1], "run") || seq(argv[1], "target-drop")) &&
	    argc == 3) {
		drop();
		xargv[0] = argv[2];
		xargv[1] = (char *)(seq(argv[1], "run") ? "main" : "target");
		xargv[2] = argv[2];
		xargv[3] = (char *)0;
		xenvp[0] = (char *)0;
		(void)S3(SYS_execve, argv[2], xargv, xenvp);
		return (96);
	}
	return (64);
}

void _start_c(long *);
void
_start_c(long *sp)
{

	(void)S1(SYS_exit_group, start((int)sp[0], (char **)(sp + 1)));
	__builtin_unreachable();
}

__asm__(
	".text\n"
	".global _start\n"
	"_start:\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call _start_c\n"
	"	hlt\n");
