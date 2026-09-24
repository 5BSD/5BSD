/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding Linux ABI tests; invoke each named case in a fresh process. */
#if defined(__x86_64__)
#define NR(a,b) (a)
static long
sc(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long r;
	__asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b),
	    "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return (r);
}
__asm__(".text\n.globl _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\n"
    "call start_c\nud2\n");
#elif defined(__aarch64__)
#define NR(a,b) (b)
static long
sc(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2),
	    "r"(x3), "r"(x4), "r"(x5) : "memory", "cc");
	return (x0);
}
__asm__(".text\n.globl _start\n_start:\nmov x0,sp\nbl start_c\nbrk #0\n");
#else
#error Unsupported Linux ABI
#endif
#define CALL(n,a,b,c) sc(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do { if (!(x)) return (__LINE__); } while (0)
#define CLOSE(fd) CALL(NR(3,57),fd,0,0)
#define MEMFD(name,flags) CALL(NR(319,279),name,flags,0)
#define FCNTL(fd,cmd,arg) CALL(NR(72,25),fd,cmd,arg)
#define RA(fd,off,len) CALL(NR(187,213),fd,off,len)
#define FADV(fd,off,len,advice) sc(NR(221,223),fd,off,len,advice,0,0)
#define SFR(fd,off,len,flags) sc(NR(277,84),fd,off,len,flags,0,0)
#define SETX(path,name,val,len,flags) sc(NR(188,5),(long)(path),(long)(name),(long)(val),len,flags,0)
#define GETX(path,name,val,len) sc(NR(191,8),(long)(path),(long)(name),(long)(val),len,0,0)
#define EPOLL_CREATE() CALL(NR(291,20),0,0,0)
#define EVENTFD() CALL(NR(290,19),0,0,0)
#define EPOLL_CTL(ep,op,fd,ev) sc(NR(233,21),ep,op,fd,(long)(ev),0,0)
#define UMOUNT(path,flags) CALL(NR(166,39),path,flags,0)
#define OPEN(path,flags) sc(NR(257,56),-100,(long)(path),flags,0600,0,0)
#define UNLINK(path) CALL(NR(263,35),-100,path,0)

static void
put(const char *s)
{
	long n = 0;
	while (s[n] != 0) n++;
	(void)CALL(NR(1,64),1,s,n);
}
static int
equal(const char *a, const char *b)
{
	while (*a != 0 && *a == *b) { a++; b++; }
	return (*a == *b);
}
static int
memfd_valid(void)
{
	long fd, copy;
	char c;
	for (int flags = 0; flags < 4; flags++) {
		fd = MEMFD("gate",flags);
		CHECK(fd >= 0);
		CHECK(FCNTL(fd,1,0) == (flags & 1)); /* F_GETFD */
		CHECK(FCNTL(fd,1034,0) == ((flags & 2) ? 0 : 1));
		CHECK(CALL(NR(1,64),fd,"x",1) == 1);
		CHECK(CALL(NR(8,62),fd,0,0) == 0);
		CHECK(CALL(NR(0,63),fd,&c,1) == 1 && c == 'x');
		copy = FCNTL(fd,0,0);
		CHECK(copy >= 0 && FCNTL(copy,1,0) == 0);
		CHECK(CLOSE(fd) == 0);
		CHECK(FCNTL(copy,1034,0) == ((flags & 2) ? 0 : 1));
		CHECK(CLOSE(copy) == 0);
	}
	fd = MEMFD("",0);
	CHECK(fd >= 0 && CLOSE(fd) == 0);
	return (0);
}
static int
memfd_unknown(void)
{
	/* Includes currently unsupported MFD_NOEXEC_SEAL and MFD_EXEC. */
	for (unsigned bit = 3; bit < 26; bit++)
		for (unsigned flags = 0; flags < 8; flags++)
			CHECK(MEMFD("gate",(1U << bit) | flags) == -22);
	CHECK(MEMFD("gate",0xffffffffU) == -22);
	CHECK(MEMFD(0,0x20) == -22); /* Flags precede name faults. */
	return (0);
}
static int
memfd_huge_encoding(void)
{
	for (unsigned size = 1; size < 64; size++)
		for (unsigned flags = 0; flags < 4; flags++)
			CHECK(MEMFD("gate",(size << 26) | flags) == -22);
	return (0);
}
static int
memfd_faults(void)
{
	char name[300];
	long p, fd;
	CHECK(MEMFD(0,0) == -14);
	CHECK(MEMFD(-1,0) == -14);
	for (unsigned i = 0; i < sizeof(name); i++) name[i] = 'a';
	name[sizeof(name)-1] = 0;
	CHECK(MEMFD(name,0) == -22);
	/* Linux permits 249 bytes excluding the memfd: prefix and NUL. */
	for (unsigned len = 246; len <= 250; len++) {
		name[len-1] = 'a';
		name[len] = 0;
		fd = MEMFD(name,0);
		if (len <= 249) CHECK(fd >= 0 && CLOSE(fd) == 0);
		else CHECK(fd == -22);
	}
	p = sc(NR(9,222),0,8192,3,0x22,-1,0);
	CHECK(p > 0);
	CHECK(CALL(NR(10,226),p+4096,4096,0) == 0);
	*(char *)(p+4095) = 'x';
	CHECK(MEMFD(p+4095,0) == -14);
	CHECK(CALL(NR(11,215),p,8192,0) == 0);
	return (0);
}
static int
memfd_seals(void)
{
	long fd = MEMFD("gate",2);
	CHECK(fd >= 0);
	CHECK(CALL(NR(77,46),fd,4096,0) == 0);
	CHECK(FCNTL(fd,1033,0x80000000U) == -22);
	CHECK(FCNTL(fd,1034,0) == 0);
	CHECK(FCNTL(fd,1033,2|4|8) == 0);
	CHECK(FCNTL(fd,1034,0) == (2|4|8));
	CHECK(CALL(NR(1,64),fd,"x",1) == -1);
	CHECK(CALL(NR(77,46),fd,0,0) == -1);
	CHECK(CALL(NR(77,46),fd,8192,0) == -1);
	CHECK(FCNTL(fd,1033,1) == 0);
	CHECK(FCNTL(fd,1033,2) == -1);
	CHECK(CLOSE(fd) == 0);
	return (0);
}
static int
memfd_churn(void)
{
	long first = MEMFD("gate", 0), fd;
	CHECK(first >= 0 && CLOSE(first) == 0);
	for (unsigned i = 0; i < 1024; i++) {
		CHECK(MEMFD("invalid",0x20) == -22);
		CHECK(MEMFD(0,0) == -14);
		fd = MEMFD("gate",3);
		CHECK(fd == first);
		CHECK(FCNTL(fd,1033,1) == 0);
		CHECK(CLOSE(fd) == 0);
	}
	return (0);
}
static int
readahead_valid(void)
{
	long fd = OPEN("file",2|0100|01000);
	char c;
	CHECK(fd >= 0);
	CHECK(CALL(NR(1,64),fd,"abcd",4) == 4);
	CHECK(CALL(NR(8,62),fd,1,0) == 1);
	CHECK(RA(fd,0,4) == 0 && RA(fd,0,0) == 0);
	CHECK(RA(fd,-1,4) == 0);
	CHECK(RA(fd,0x7ffffffffffffffeL,4) == 0);
	CHECK(RA(fd,0,0xffffffffffffffffUL) == -22);
	CHECK(RA(fd,0x7ffffffffffffffeL,0xffffffffffffffffUL) == -22);
	CHECK(CALL(NR(0,63),fd,&c,1) == 1 && c == 'b');
	CHECK(CLOSE(fd) == 0);
	fd = OPEN("file",0);
	CHECK(fd >= 0 && RA(fd,0,4) == 0 && CLOSE(fd) == 0);
	CHECK(UNLINK("file") == 0);
	return (0);
}
static int
readahead_invalid(void)
{
	long fd;
	int pipes[2];
	CHECK(RA(-1,0,1) == -9);
	fd = OPEN("file",1|0100|01000);
	CHECK(fd >= 0 && RA(fd,0,1) == -9 && CLOSE(fd) == 0);
	fd = OPEN(".",0);
	CHECK(fd >= 0 && RA(fd,0,1) == -22 && CLOSE(fd) == 0);
	fd = OPEN("file",010000000); /* O_PATH */
	CHECK(fd >= 0 && RA(fd,0,1) == -9 && CLOSE(fd) == 0);
	CHECK(CALL(NR(293,59),pipes,0,0) == 0);
	CHECK(RA(pipes[0],0,1) == -22 && RA(pipes[1],0,1) == -9);
	CHECK(CLOSE(pipes[0]) == 0 && CLOSE(pipes[1]) == 0);
	fd = CALL(NR(41,198),1,1,0);
	CHECK(fd >= 0 && RA(fd,0,1) == -22 && CLOSE(fd) == 0);
	CHECK(UNLINK("file") == 0);
	return (0);
}
static int
sync_valid(void)
{
	long fd = OPEN("file",2|0100|01000);
	CHECK(fd >= 0 && CALL(NR(1,64),fd,"sync",4) == 4);
	CHECK(CALL(NR(162,81),0,0,0) == 0);
	CHECK(CALL(NR(162,81),-1,-1,-1) == 0); /* No arguments. */
	CHECK(CLOSE(fd) == 0 && UNLINK("file") == 0);
	return (0);
}
static int
sync_file_range_options(void)
{
	long fd, dirfd, sock;
	int pipes[2];

	fd = OPEN("file",2|0100|01000);
	CHECK(fd >= 0 && CALL(NR(1,64),fd,"range",5) == 5);
	for (unsigned flags = 0; flags < 8; flags++)
		CHECK(SFR(fd,0,5,flags) == 0);
	CHECK(SFR(fd,0,0,0) == 0);
	CHECK(SFR(fd,0x7ffffffffffffffeL,1,0) == 0);
	CHECK(SFR(fd,-1,1,0) == -22);
	CHECK(SFR(fd,0,-1,0) == -22);
	CHECK(SFR(fd,0x7fffffffffffffffL,1,0) == -22);
	CHECK(SFR(fd,0,1,8) == -22);
	/* Descriptor lookup precedes range and flag validation. */
	CHECK(SFR(9999,-1,-1,8) == -9);
	CHECK(CLOSE(fd) == 0);
	fd = OPEN("file",0);
	CHECK(fd >= 0 && SFR(fd,0,0,7) == 0 && CLOSE(fd) == 0);
	dirfd = OPEN(".",0);
	CHECK(dirfd >= 0 && SFR(dirfd,0,0,0) == 0 && CLOSE(dirfd) == 0);
	CHECK(CALL(NR(293,59),pipes,0,0) == 0);
	CHECK(SFR(pipes[0],0,0,0) == -29);
	CHECK(SFR(pipes[1],-1,-1,8) == -22);
	CHECK(CLOSE(pipes[0]) == 0 && CLOSE(pipes[1]) == 0);
	sock = CALL(NR(41,198),1,1,0);
	CHECK(sock >= 0 && SFR(sock,0,0,0) == -29 && CLOSE(sock) == 0);
	CHECK(UNLINK("file") == 0);
	return (0);
}
static int
fadvise_options(void)
{
	int pipes[2];
	long dir, fd, sock;

	fd = OPEN("fadvise-file",2|0100|01000);
	CHECK(fd >= 0 && CALL(NR(1,64),fd,"fadvise",7) == 7);
	for (int advice = 0; advice <= 5; advice++)
		CHECK(FADV(fd,0,7,advice) == 0);
	CHECK(FADV(fd,-1,1,0) == 0);
	CHECK(FADV(fd,0x7fffffffffffffffUL,2,0) == 0);
	CHECK(FADV(fd,0,-1,0) == -22);
	CHECK(FADV(fd,0,1,0x7fffffff) == -22);
	CHECK(FADV(9999,0,1,0x7fffffff) == -9);
	CHECK(sc(NR(293,59),(long)pipes,0,0,0,0,0) == 0);
	CHECK(FADV(pipes[0],0,1,0x7fffffff) == -29);
	CHECK(FADV(pipes[0],0,-1,0) == -29);
	CHECK(CLOSE(pipes[0]) == 0 && CLOSE(pipes[1]) == 0);
	dir = OPEN(".",0200000);
	CHECK(dir >= 0 && FADV(dir,0,1,0) == 0 &&
	    FADV(dir,0,1,0x7fffffff) == -22 && CLOSE(dir) == 0);
	sock = CALL(NR(41,198),1,1,0);
	CHECK(sock >= 0 && FADV(sock,0,1,3) == 0 &&
	    FADV(sock,0,1,0x7fffffff) == -22 && CLOSE(sock) == 0);
	CHECK(CLOSE(fd) == 0 && UNLINK("fadvise-file") == 0);
	return (0);
}

struct epoll_event {
	unsigned events;
	unsigned long long data;
} __attribute__((packed));

static int
epoll_options(void)
{
	struct epoll_event ev;
	long epfd, efd;

	epfd = EPOLL_CREATE();
	efd = EVENTFD();
	CHECK(epfd >= 0 && efd >= 0);
	ev.events = 1;
	ev.data = 0x1111;
	CHECK(EPOLL_CTL(epfd,1,efd,&ev) == 0);
	CHECK(EPOLL_CTL(epfd,1,efd,&ev) == -17);
	ev.data = 0x2222;
	CHECK(EPOLL_CTL(epfd,3,efd,&ev) == 0);
	/* Every operation except DEL imports the event pointer first. */
	CHECK(EPOLL_CTL(epfd,99,efd,(void *)1) == -14);
	CHECK(EPOLL_CTL(epfd,99,efd,&ev) == -22);
	CHECK(EPOLL_CTL(epfd,2,efd,(void *)1) == 0);
	CHECK(EPOLL_CTL(epfd,2,efd,(void *)1) == -2);
	CHECK(EPOLL_CTL(9999,1,efd,&ev) == -9);
	CHECK(EPOLL_CTL(epfd,1,9999,&ev) == -9);
	CHECK(EPOLL_CTL(epfd,1,epfd,&ev) == -22);
	/* ADD/MOD copy their event before resolving descriptors. */
	CHECK(EPOLL_CTL(9999,1,9999,(void *)1) == -14);
	CHECK(CLOSE(efd) == 0 && CLOSE(epfd) == 0);
	return (0);
}

static int
xattr_options(void)
{
	char val[16];
	long fd;

	fd = OPEN("xattr-file",2|0100|01000);
	CHECK(fd >= 0);
	CHECK(SETX("xattr-file","user.options","abcdefgh",8,0) == 0);
	/* Existence checks must not use the shorter replacement value size. */
	CHECK(SETX("xattr-file","user.options","x",1,1) == -17);
	for (unsigned i = 0; i < sizeof(val); i++) val[i] = 0;
	CHECK(GETX("xattr-file","user.options",val,sizeof(val)) == 8);
	for (unsigned i = 0; i < 8; i++) CHECK(val[i] == "abcdefgh"[i]);
	CHECK(SETX("xattr-file","user.missing","x",1,2) == -61);
	CHECK(SETX("xattr-file","user.options","new",3,2) == 0);
	CHECK(SETX("xattr-file","user.options","bad",3,4) == -22);
	/* Linux accepts both defined flags; existence selects the errno. */
	CHECK(SETX("xattr-file","user.options","bad",3,3) == -17);
	CHECK(SETX("xattr-file","user.both-missing","bad",3,3) == -61);
	CHECK(GETX("xattr-file","user.options",0,0) == 3);
	CHECK(GETX("xattr-file","user.options",val,2) == -34);
	CHECK(GETX("xattr-file","user.absent",val,sizeof(val)) == -61);
	CHECK(CLOSE(fd) == 0 && UNLINK("xattr-file") == 0);
	return (0);
}

static int
umount_invalid(void)
{
	CHECK(UMOUNT("/no-such-linuxulator-gate-mount",0) == -2);
	CHECK(UMOUNT(0,0) == -14);
	CHECK(UMOUNT("/",0x80000000U) == -22);
	CHECK(UMOUNT("/",2) == -22); /* Unsupported lazy unmount. */
	CHECK(UMOUNT("/",4) == -22); /* Unsupported expiry. */
	CHECK(CALL(NR(266,36),"/",-100,"link") == 0);
	CHECK(UMOUNT("link",8) == -22);
	CHECK(UNLINK("link") == 0);
	return (0);
}
static int
umount_lifecycle(void)
{
	const char *path = "/tmp/linuxulator-gate-mount";
	CHECK(CALL(NR(258,34),-100,path,0700) == 0);
	CHECK(sc(NR(165,40),(long)"tmpfs",(long)path,(long)"tmpfs",0,0,0) == 0);
	CHECK(UMOUNT(path,8) == 0);
	CHECK(UMOUNT(path,0) == -22);
	CHECK(CALL(NR(263,35),-100,path,0x200) == 0);
	return (0);
}
static int
umount_unprivileged(void)
{
	CHECK(CALL(NR(105,146),65534,0,0) == 0);
	CHECK(UMOUNT("/",0) == -1);
	return (0);
}
static const struct { const char *name; int (*fn)(void); } cases[] = {
	{ "memfd_valid", memfd_valid },
	{ "memfd_unknown", memfd_unknown },
	{ "memfd_huge_encoding", memfd_huge_encoding },
	{ "memfd_faults", memfd_faults },
	{ "memfd_seals", memfd_seals },
	{ "memfd_churn", memfd_churn },
	{ "readahead_valid", readahead_valid },
	{ "readahead_invalid", readahead_invalid },
	{ "sync_valid", sync_valid },
	{ "sync_file_range_options", sync_file_range_options },
	{ "fadvise_options", fadvise_options },
	{ "epoll_options", epoll_options },
	{ "xattr_options", xattr_options },
	{ "umount_invalid", umount_invalid },
	{ "umount_lifecycle", umount_lifecycle },
	{ "umount_unprivileged", umount_unprivileged },
};
void
start_c(long *sp)
{
	char **argv = (char **)(sp+1);
	int result = 111;
	if (sp[0] == 2) {
		for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
			if (equal(argv[1],"-l")) {
				put(cases[i].name); put("\n"); result = 0;
			} else if (equal(argv[1],cases[i].name)) {
				result = cases[i].fn(); break;
			}
		}
	}
	if (result != 0) {
		char buf[16];
		unsigned n = sizeof(buf)-1, v = result;
		buf[n] = 0;
		do { buf[--n] = '0'+v%10; v /= 10; } while (v != 0);
		put("FAIL line "); put(buf+n); put("\n");
	}
	(void)CALL(NR(231,94),result != 0,0,0);
	__builtin_unreachable();
}
