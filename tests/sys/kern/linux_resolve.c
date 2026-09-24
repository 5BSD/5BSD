/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding amd64/arm64 openat2 link-resolution contract tests.
 * Run each named case in a fresh directory; magic cases require proc/fdesc mounts. */
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
#define CLOSE(fd) CALL(NR(3,57),fd,0,0)
#define CHECK(x) do { if (!(x)) return (__LINE__); } while (0)
#define OPEN(p,f) sc(NR(257,56),-100,(long)(p),f,0600,0,0)
#define MKDIR(p,m) CALL(NR(258,34),-100,p,m)
#define LINK(t,p) CALL(NR(266,36),t,-100,p)
#define UNLINK(p) CALL(NR(263,35),-100,p,0)
#define RENAME(a,b) sc(NR(264,38),-100,(long)(a),-100,(long)(b),0,0)
#define READ(fd,p,n) CALL(NR(0,63),fd,p,n)
#define WRITE(fd,p,n) CALL(NR(1,64),fd,p,n)
#define RDONLY 0
#define RDWR 2
#define CREAT 0100
#define EXCL 0200
#define TRUNC 01000
#define DIRECTORY NR(0200000,040000)
#define NOFOLLOW NR(0400000,0100000)
#define CLOEXEC 02000000
#define PATH 010000000
#define NOMAGIC 2
#define NOSYM 4
#define BENEATH 8
#define EFAULT 14
#define ELOOP 40
#define ENOENT 2
#define EINVAL 22
#define EBADF 9
#define EACCES 13
#define EXDEV 18
#define ENOTDIR 20
#define EEXIST 17
struct how { unsigned long flags, mode, resolve; };
static long
open2(long dfd, const char *path, long flags, long resolve)
{
	struct how h = { flags, flags & CREAT ? 0600 : 0, resolve };
	return (sc(437,dfd,(long)path,(long)&h,sizeof(h),0,0));
}
static int
opened(long fd)
{
	return (fd >= 0 && CLOSE(fd) == 0);
}
static int
setup(void)
{
	long fd;
	CHECK(MKDIR("dir",0755) == 0);
	fd = OPEN("dir/file",CREAT|RDWR|EXCL);
	CHECK(fd >= 0 && WRITE(fd,"safe",4) == 4 && CLOSE(fd) == 0);
	CHECK(LINK("dir","dirlink") == 0);
	CHECK(LINK("file","dir/link") == 0);
	CHECK(LINK("missing","dir/dangling") == 0);
	CHECK(LINK("loop","dir/loop") == 0);
	return (0);
}
static int
plain(void)
{
	long fd, dfd;
	CHECK(setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (int r = 2; r <= 6; r += 2) {
		CHECK(opened(open2(dfd,"file",RDONLY,r)));
		CHECK(opened(open2(dfd,"./file",PATH|CLOEXEC,r)));
		CHECK(opened(open2(dfd,".",RDONLY|DIRECTORY,r)));
		CHECK(open2(dfd,"file/",RDONLY,r) == -ENOTDIR);
		CHECK(open2(dfd,"missing",RDONLY,r) == -ENOENT);
		CHECK(open2(dfd,"",RDONLY,r) == -ENOENT);
		CHECK(open2(9999,"file",RDONLY,r) == -EBADF);
		CHECK(opened(open2(9999,"/",PATH|DIRECTORY,r)));
		fd = open2(dfd,"new",RDWR|CREAT|EXCL|CLOEXEC,r);
		CHECK(fd >= 0 && CALL(NR(72,25),fd,1,0) == 1);
		CHECK(CLOSE(fd) == 0 && UNLINK("dir/new") == 0);
	}
	CHECK(CLOSE(dfd) == 0);
	return (0);
}
static int
symlinks(void)
{
	long fd;
	char buf[16];
	CHECK(setup() == 0);
	for (int n = 0; n < 64; n++) {
		CHECK(opened(open2(-100,"dir/link",RDONLY,NOMAGIC)));
		CHECK(opened(open2(-100,"dirlink/file",RDONLY,NOMAGIC)));
		CHECK(open2(-100,"dir/link",RDONLY,NOSYM) == -ELOOP);
		CHECK(open2(-100,"dirlink/file",RDONLY,NOSYM) == -ELOOP);
		CHECK(open2(-100,"dirlink/",PATH|NOFOLLOW,NOSYM) == -ELOOP);
		CHECK(open2(-100,"dir/dangling",RDONLY,NOSYM) == -ELOOP);
		CHECK(open2(-100,"dir/loop",RDONLY,NOSYM) == -ELOOP);
	}
	for (int r = 2; r <= 6; r += 2) {
		CHECK(open2(-100,"dir/link",RDONLY|NOFOLLOW,r) == -ELOOP);
		CHECK(open2(-100,"dir/link",RDWR|CREAT|EXCL,r) == -EEXIST);
		CHECK(open2(-100,"dir/dangling",RDWR|CREAT|EXCL,r) == -EEXIST);
		fd = open2(-100,"dir/link",PATH|NOFOLLOW,r);
		CHECK(fd >= 0);
		CHECK(sc(NR(267,78),fd,(long)"",(long)buf,sizeof(buf),0,0) == 4);
		CHECK(buf[0] == 'f' && buf[3] == 'e');
		CHECK(READ(fd,buf,1) == -EBADF && CLOSE(fd) == 0);
		CHECK(opened(open2(-100,"dir/dangling",PATH|NOFOLLOW,r)));
		CHECK(open2(-100,"dir/link",PATH|NOFOLLOW|DIRECTORY,r) == -ENOTDIR);
	}
	CHECK(open2(-100,"dir/dangling",RDWR|CREAT,NOSYM) == -ELOOP);
	CHECK(open2(-100,"dir/missing",RDONLY,0) == -ENOENT);
	CHECK(open2(-100,"dir/link",RDWR|TRUNC,NOSYM) == -ELOOP);
	fd = OPEN("dir/file",RDONLY);
	CHECK(fd >= 0 && READ(fd,buf,sizeof(buf)) == 4 && CLOSE(fd) == 0);
	return (0);
}
static int
magic(void)
{
	const char *paths[] = {"/proc/self/exe", "/proc/self/cwd", "/proc/self/root"};
	long fd;
	char b[512];
	for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
		CHECK(opened(open2(-100,paths[i],PATH,0)));
		for (int r = 2; r <= 6; r += 2) {
			CHECK(open2(-100,paths[i],RDONLY,r) == -ELOOP);
			CHECK(open2(-100,paths[i],PATH,r) == -ELOOP);
			CHECK(open2(-100,paths[i],RDONLY|NOFOLLOW,r) == -ELOOP);
			/* /proc/self is an ordinary link: use its directory fd. */
		}
	}
	fd = OPEN("/proc/self",PATH|DIRECTORY);
	CHECK(fd >= 0);
	for (int r = 2; r <= 6; r += 2) {
		long linkfd = open2(fd,"exe",PATH|NOFOLLOW,r);
		CHECK(linkfd >= 0);
		CHECK(sc(NR(267,78),linkfd,(long)"",(long)b,sizeof(b),0,0) > 0);
		CHECK(CLOSE(linkfd) == 0);
		CHECK(open2(fd,"cwd/",PATH|NOFOLLOW,r) == -ELOOP);
		CHECK(open2(fd,"root/tmp",PATH,r) == -ELOOP);
	}
	CHECK(CLOSE(fd) == 0);
	CHECK(LINK("/proc/self/exe","indirect") == 0);
	CHECK(open2(-100,"indirect",PATH,NOMAGIC) == -ELOOP);
	CHECK(opened(open2(-100,"/proc/self",PATH|DIRECTORY,NOMAGIC)));
	return (0);
}
static void
fdpath(char *path, const char *prefix, long fd, const char *suffix)
{
	char digits[20];
	int n = 0;
	while (*prefix) *path++ = *prefix++;
	do { digits[n++] = '0' + fd % 10; fd /= 10; } while (fd);
	while (n) *path++ = digits[--n];
	while (*suffix) *path++ = *suffix++;
	*path = 0;
}
static int
fd_links(void)
{
	char p[80], b[512];
	long fd, dfd, procfd, linkfd;
	CHECK(setup() == 0);
	fd = OPEN("dir/file",RDONLY);
	dfd = OPEN("dir",PATH|DIRECTORY);
	procfd = OPEN("/proc/self/fd",PATH|DIRECTORY);
	CHECK(fd >= 0 && dfd >= 0 && procfd >= 0);
	fdpath(p,"",fd,"");
	for (int r = 2; r <= 6; r += 2) {
		CHECK(open2(procfd,p,RDONLY,r) == -ELOOP);
		CHECK(open2(procfd,p,PATH,r) == -ELOOP);
		CHECK(open2(procfd,p,RDONLY|NOFOLLOW,r) == -ELOOP);
		linkfd = open2(procfd,p,PATH|NOFOLLOW,r);
		CHECK(linkfd >= 0);
		CHECK(sc(NR(267,78),linkfd,(long)"",(long)b,sizeof(b),0,0) > 0);
		CHECK(CLOSE(linkfd) == 0);
	}
	fdpath(p,"",dfd,"/file");
	CHECK(opened(open2(procfd,p,RDONLY,0)));
	for (int r = 2; r <= 6; r += 2)
		CHECK(open2(procfd,p,RDONLY,r) == -ELOOP);
	fdpath(p,"",dfd,"/");
	for (int r = 2; r <= 6; r += 2)
		CHECK(open2(procfd,p,PATH|NOFOLLOW,r) == -ELOOP);
	CHECK(CLOSE(fd) == 0 && CLOSE(dfd) == 0 && CLOSE(procfd) == 0);
	return (0);
}
static int
faults(void)
{
	long p, fd;
	struct how h = {0,0,NOSYM};
	unsigned long big[4] = {0,0,NOSYM,0};
	CHECK(setup() == 0);
	CHECK(sc(437,-100,(long)"dir/file",0,24,0,0) == -EFAULT);
	CHECK(sc(437,-100,0,(long)&h,24,0,0) == -EFAULT);
	CHECK(sc(437,-100,(long)"dir/file",(long)&h,23,0,0) == -EINVAL);
	CHECK(opened(sc(437,-100,(long)"dir/file",(long)big,32,0,0)));
	big[3] = 1;
	CHECK(sc(437,-100,(long)"dir/file",(long)big,32,0,0) == -7);
	for (unsigned bit = 6; bit < 64; bit++) {
		h.resolve = (1UL << bit) | NOSYM;
		CHECK(sc(437,-100,(long)"dir/file",(long)&h,24,0,0) == -EINVAL);
	}
	h.resolve = NOSYM;
	p = sc(NR(9,222),0,8192,3,0x22,-1,0);
	CHECK(p > 0 && CALL(NR(10,226),p+4096,4096,0) == 0);
	*(char *)(p+4095) = 'x';
	CHECK(open2(-100,(const char *)(p+4095),RDONLY,NOSYM) == -EFAULT);
	CHECK(sc(437,-100,(long)"dir/file",p+4080,24,0,0) == -EFAULT);
	*(struct how *)(p+4096-24) = h;
	fd = sc(437,-100,(long)"dir/file",p+4096-24,24,0,0);
	CHECK(opened(fd));
	CHECK(sc(437,-100,(long)"dir/file",p+4096-24,25,0,0) == -EFAULT);
	CHECK(CALL(NR(11,215),p,8192,0) == 0);
	return (0);
}
static int
beneath(void)
{
	long dfd;
	CHECK(setup() == 0);
	CHECK(LINK("/","dir/abs") == 0);
	CHECK(LINK("..","dir/up") == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	CHECK(opened(open2(dfd,"link",RDONLY,BENEATH|NOMAGIC)));
	CHECK(open2(dfd,"link",RDONLY,BENEATH|NOSYM) == -ELOOP);
	for (int r = 2; r <= 6; r += 2) {
		CHECK(opened(open2(dfd,"file",RDONLY,BENEATH|r)));
		CHECK(open2(dfd,"../dir/file",RDONLY,BENEATH|r) == -EXDEV);
		CHECK(open2(dfd,"/",PATH,BENEATH|r) == -EXDEV);
		CHECK(open2(dfd,"abs/tmp",PATH,BENEATH|r) == -(r & NOSYM ? ELOOP : EXDEV));
		CHECK(open2(dfd,"up/dir/file",RDONLY,BENEATH|r) == -(r & NOSYM ? ELOOP : EXDEV));
	}
	CHECK(CLOSE(dfd) == 0);
	return (0);
}
static int
lifetime(void)
{
	long dfd, linkfd;
	char p[80], b[512];
	CHECK(setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0 && RENAME("dir","moved") == 0);
	CHECK(opened(open2(dfd,"file",RDONLY,NOSYM)));
	CHECK(open2(dfd,"link",RDONLY,NOSYM) == -ELOOP);
	CHECK(opened(open2(dfd,"link",RDONLY,NOMAGIC)));
	fdpath(p,"/proc/self/fd/",dfd,"/file");
	CHECK(opened(open2(-100,p,RDONLY,0)));
	CHECK(open2(-100,p,RDONLY,NOMAGIC) == -ELOOP);
	linkfd = open2(dfd,"link",PATH|NOFOLLOW,NOSYM);
	CHECK(linkfd >= 0 && UNLINK("moved/link") == 0);
	CHECK(sc(NR(267,78),linkfd,(long)"",(long)b,sizeof(b),0,0) == 4);
	CHECK(CLOSE(linkfd) == 0 && CLOSE(dfd) == 0);
	return (0);
}
static int
permissions(void)
{
	long fd;
	CHECK(MKDIR("denied",0700) == 0);
	CHECK(LINK("missing","denied/link") == 0);
	CHECK(CALL(NR(105,146),65534,0,0) == 0);
	for (int r = 2; r <= 6; r += 2) {
		CHECK(open2(-100,"denied/link",PATH,r) == -EACCES);
		CHECK(open2(-100,"denied/missing",RDONLY,r) == -EACCES);
		fd = open2(-100,"/",PATH,r);
		CHECK(opened(fd));
	}
	return (0);
}
static int
race(void)
{
	long pid, fd;
	int status;
	char b[8];
	CHECK(setup() == 0);
	fd = OPEN("bad",CREAT|RDWR|EXCL);
	CHECK(fd >= 0 && WRITE(fd,"unsafe",6) == 6 && CLOSE(fd) == 0);
	pid = sc(NR(56,220),17,0,0,0,0,0); /* fork-like clone */
	CHECK(pid >= 0);
	if (pid == 0) {
		for (int n = 0; n < 1000; n++) {
			if (LINK("bad","replacement") != 0 || RENAME("replacement","flip") != 0)
				CALL(NR(231,94),2,0,0);
			fd = OPEN("replacement",CREAT|RDWR|EXCL);
			if (fd < 0 || WRITE(fd,"safe",4) != 4 || CLOSE(fd) != 0 || RENAME("replacement","flip") != 0)
				CALL(NR(231,94),3,0,0);
		}
		CALL(NR(231,94),0,0,0);
	}
	for (int n = 0; n < 4000; n++) {
		fd = open2(-100,"flip",RDONLY,NOSYM);
		if (fd < 0) {
			CHECK(fd == -ELOOP || fd == -ENOENT);
		} else {
			CHECK(READ(fd,b,sizeof(b)) == 4 && b[0] == 's' && b[3] == 'e');
			CHECK(CLOSE(fd) == 0);
		}
	}
	CHECK(sc(NR(61,260),pid,(long)&status,0,0,0,0) == pid && status == 0);
	/* Repeated failing lookups must not consume descriptors. */
	fd = OPEN("dir/file",RDONLY);
	CHECK(fd == 3 && CLOSE(fd) == 0);
	return (0);
}
/* FreeBSD filesystem variants: required in the guest, excluded from Linux oracle. */
static int
native_mounts(void)
{
	const char *roots[] = {"/tmp/resolve-fd-plain/", "/tmp/resolve-fd-rdlnk/",
	    "/tmp/resolve-fd-nodup/"};
	const char *procpaths[] = {"/tmp/resolve-procfs/curproc/file",
	    "/tmp/resolve-procfs/curproc/exe"};
	char p[128];
	long fd;
	CHECK(setup() == 0);
	fd = OPEN("dir/file",RDONLY);
	CHECK(fd >= 0);
	for (unsigned i = 0; i < sizeof(roots)/sizeof(roots[0]); i++) {
		fdpath(p,roots[i],fd,"");
		CHECK(opened(open2(-100,p,RDONLY,0)));
		for (int r = 2; r <= 6; r += 2) {
			CHECK(open2(-100,p,RDONLY,r) == -ELOOP);
			CHECK(open2(-100,p,PATH,r) == -ELOOP);
			if (i == 2) {
				/* nodup exposes the target directly; no link vnode to hold. */
				CHECK(open2(-100,p,PATH|NOFOLLOW,r) == -ELOOP);
			} else {
				CHECK(opened(open2(-100,p,PATH|NOFOLLOW,r)));
			}
		}
	}
	for (unsigned i = 0; i < sizeof(procpaths)/sizeof(procpaths[0]); i++) {
		CHECK(opened(open2(-100,procpaths[i],PATH,0)));
		CHECK(open2(-100,procpaths[i],PATH,NOMAGIC) == -ELOOP);
		CHECK(opened(open2(-100,procpaths[i],PATH|NOFOLLOW,NOMAGIC)));
	}
	CHECK(CLOSE(fd) == 0);
	fd = OPEN("/tmp/xdev-autofs",PATH|DIRECTORY);
	CHECK(fd >= 0);
	CHECK(opened(open2(fd,".",PATH,1)));
	/* No automount daemon: triggering would block and fail the timeout. */
	CHECK(open2(fd,"uncached",PATH,1) == -EXDEV);
	CHECK(CLOSE(fd) == 0);
	fd = OPEN("/tmp/xdev-union",PATH|DIRECTORY);
	CHECK(fd >= 0);
	CHECK(opened(open2(fd,"lower",RDONLY,0)));
	CHECK(opened(open2(fd,"upper",RDONLY,1)));
	CHECK(open2(fd,"lower",RDONLY,1) == -EXDEV);
	CHECK(opened(open2(fd,"upper",RDONLY,16)));
	CHECK(open2(fd,"lower",RDONLY,16) == -EXDEV);
	CHECK(CLOSE(fd) == 0);
	return (0);
}
static int
xdev_basic(void)
{
	long fd, dfd;
	CHECK(setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (int n = 0; n < 64; n++) {
		CHECK(opened(open2(dfd,"file",RDONLY,1)));
		CHECK(opened(open2(dfd,"link",RDONLY,1)));
		CHECK(opened(open2(dfd,"../dir/file",RDONLY,1)));
		CHECK(open2(dfd,"link",RDONLY,1|NOSYM) == -ELOOP);
		CHECK(opened(open2(dfd,"link",RDONLY,1|NOMAGIC)));
	}
	CHECK(opened(open2(9999,"/",PATH|DIRECTORY,1)));
	CHECK(open2(9999,"relative",PATH,1) == -EBADF);
	CHECK(open2(dfd,"missing",RDONLY,1) == -ENOENT);
	CHECK(open2(dfd,"file/",PATH,1) == -ENOTDIR);
	CHECK(open2(dfd,"link",RDONLY|NOFOLLOW,1) == -ELOOP);
	CHECK(opened(open2(dfd,"link",PATH|NOFOLLOW,1|NOSYM)));
	fd = open2(dfd,"new",RDWR|CREAT|EXCL,1|NOSYM|NOMAGIC|BENEATH);
	CHECK(fd >= 0 && CLOSE(fd) == 0);
	CHECK(CLOSE(dfd) == 0);
	return (0);
}
static int
xdev_mount(void)
{
	long base, mnt, sub;
	const long flags[] = { RDONLY, PATH, PATH|NOFOLLOW, RDONLY|DIRECTORY };
	const char *paths[] = {"mnt", "mnt/", "mnt/../file", "bind", "bind/"};
	base = OPEN("/tmp/xdev-base",PATH|DIRECTORY);
	mnt = OPEN("/tmp/xdev-base/mnt",PATH|DIRECTORY);
	sub = OPEN("/tmp/xdev-base/mnt/sub",PATH|DIRECTORY);
	CHECK(base >= 0 && mnt >= 0 && sub >= 0);
	for (unsigned i = 0; i < sizeof(flags)/sizeof(flags[0]); i++) {
		for (unsigned j = 0; j < sizeof(paths)/sizeof(paths[0]); j++)
			CHECK(open2(base,paths[j],flags[i],1) == -EXDEV);
		CHECK(opened(open2(mnt,".",flags[i],1)));
		CHECK(opened(open2(sub,"..",flags[i],1)));
		CHECK(open2(mnt,"..",flags[i],1) == -EXDEV);
		CHECK(open2(sub,"../..",flags[i],1) == -EXDEV);
		CHECK(open2(mnt,"nested",flags[i],1) == -EXDEV);
	}
	for (int r = 1; r < 16; r += 2) {
		CHECK(opened(open2(base,"file",RDONLY,r)));
		CHECK(opened(open2(mnt,"file",RDONLY,r)));
		CHECK(opened(open2(mnt,"sub/../file",RDONLY,r)));
		CHECK(open2(base,"mnt/file",RDONLY,r) == -EXDEV);
		CHECK(open2(base,"bind/file",RDONLY,r) == -EXDEV);
		CHECK(open2(mnt,"nested/file",RDONLY,r) == -EXDEV);
		CHECK(open2(base,"mnt/not-created",RDWR|CREAT|EXCL,r) == -EXDEV);
		CHECK(open2(mnt,"not-created",RDONLY,0) == -ENOENT);
	}
	/* Following an absolute symlink from tmpfs jumps to another mount. */
	CHECK(open2(mnt,"abs",PATH,1) == -EXDEV);
	CHECK(open2(mnt,"up/file",RDONLY,1) == -EXDEV);
	CHECK(open2(mnt,"abs",PATH,1|NOSYM) == -ELOOP);
	CHECK(opened(open2(mnt,"abs",PATH|NOFOLLOW,1|NOSYM)));
	CHECK(opened(open2(base,"mnt/file",RDONLY,0)));
	CHECK(opened(open2(base,"bind/file",RDONLY,0)));
	CHECK(CLOSE(base) == 0 && CLOSE(mnt) == 0 && CLOSE(sub) == 0);
	return (0);
}
static int
xdev_magic(void)
{
	long fd, dfd, procfd, lfd;
	char p[80], b[512];
	CHECK(setup() == 0);
	fd = OPEN("dir/file",RDONLY);
	dfd = OPEN("dir",PATH|DIRECTORY);
	/* Resolve the directory before applying constraints to its entries. */
	procfd = OPEN("/proc/self/fd",PATH|DIRECTORY);
	CHECK(fd >= 0 && dfd >= 0 && procfd >= 0);
	fdpath(p,"",fd,"");
	CHECK(open2(procfd,p,RDONLY,1) == -EXDEV);
	CHECK(open2(procfd,p,PATH,1) == -EXDEV);
	CHECK(open2(procfd,p,RDONLY|NOFOLLOW,1) == -ELOOP);
	CHECK(open2(procfd,p,RDWR|CREAT|EXCL,1) == -EEXIST);
	for (int r = 1; r <= 7; r += 2) {
		lfd = open2(procfd,p,PATH|NOFOLLOW,r);
		CHECK(lfd >= 0);
		CHECK(sc(NR(267,78),lfd,(long)"",(long)b,sizeof(b),0,0) > 0);
		CHECK(CLOSE(lfd) == 0);
		if (r != 1) CHECK(open2(procfd,p,RDONLY,r) == -ELOOP);
	}
	fdpath(p,"",dfd,"/file");
	CHECK(open2(procfd,p,RDONLY,1) == -EXDEV);
	CHECK(open2(procfd,p,RDONLY,1|NOMAGIC) == -ELOOP);
	fdpath(p,"",dfd,"/");
	CHECK(open2(procfd,p,PATH|NOFOLLOW,1) == -EXDEV);
	CHECK(CLOSE(procfd) == 0 && CLOSE(fd) == 0 && CLOSE(dfd) == 0);
	return (0);
}
static int
xdev_churn(void)
{
	long fd, dfd;
	CHECK(MKDIR("held",0700) == 0);
	dfd = OPEN("held",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (int n = 0; n < 256; n++) {
		CHECK(RENAME("held","moved") == 0);
		CHECK(opened(open2(dfd,".",PATH|DIRECTORY,1)));
		CHECK(opened(open2(dfd,"..",PATH|DIRECTORY,1)));
		CHECK(open2(-100,"/tmp/xdev-base/mnt/file",RDONLY,1) == -EXDEV);
		CHECK(RENAME("moved","held") == 0);
	}
	CHECK(CLOSE(dfd) == 0);
	fd = OPEN("/tmp/xdev-base/file",RDONLY);
	CHECK(fd == 3 && CLOSE(fd) == 0);
	return (0);
}
static int
xdev_mount_race(void)
{
	char path[512], b[8];
	int ready[2], ack[2], status;
	long pid, fd, result;
	unsigned len;
	CHECK(MKDIR("cross",0700) == 0);
	fd = OPEN("cross/file",CREAT|RDWR|EXCL);
	CHECK(fd >= 0 && WRITE(fd,"safe",4) == 4 && CLOSE(fd) == 0);
	CHECK(CALL(NR(79,17),path,sizeof(path)-8,0) > 0);
	for (len = 0; path[len]; len++) ;
	for (unsigned i = 0; i < sizeof("/cross"); i++) path[len+i] = "/cross"[i];
	CHECK(CALL(NR(293,59),ready,0,0) == 0);
	CHECK(CALL(NR(293,59),ack,0,0) == 0);
	pid = sc(NR(56,220),17,0,0,0,0,0);
	CHECK(pid >= 0);
	if (pid == 0) {
		CHECK(CLOSE(ready[0]) == 0 && CLOSE(ack[1]) == 0);
		for (int n = 0; n < 32; n++) {
			CHECK(sc(NR(165,40),(long)"tmpfs",(long)path,(long)"tmpfs",0,0,0) == 0);
			fd = OPEN("cross/file",CREAT|RDWR|EXCL);
			CHECK(fd >= 0 && WRITE(fd,"evil",4) == 4 && CLOSE(fd) == 0);
			if (n == 0) {
				CHECK(WRITE(ready[1],"r",1) == 1 && READ(ack[0],b,1) == 1);
			}
			for (int retry = 0; ; retry++) {
				result = CALL(NR(166,39),path,0,0);
				if (result == 0) break;
				CHECK(result == -16 && retry < 10000); /* EBUSY: transient lookup */
				CALL(NR(24,124),0,0,0);
			}
		}
		CALL(NR(231,94),0,0,0);
	}
	CHECK(CLOSE(ready[1]) == 0 && CLOSE(ack[0]) == 0);
	CHECK(READ(ready[0],b,1) == 1);
	CHECK(open2(-100,"cross/file",RDONLY,1) == -EXDEV);
	CHECK(WRITE(ack[1],"a",1) == 1);
	CHECK(CLOSE(ready[0]) == 0 && CLOSE(ack[1]) == 0);
	for (int n = 0; n < 10000; n++) {
		fd = open2(-100,"cross/file",RDONLY,1);
		if (fd < 0) {
			CHECK(fd == -EXDEV || fd == -ENOENT);
		} else {
			CHECK(READ(fd,b,sizeof(b)) == 4 && b[0] == 's' && b[3] == 'e');
			CHECK(CLOSE(fd) == 0);
		}
	}
	CHECK(sc(NR(61,260),pid,(long)&status,0,0,0,0) == pid && status == 0);
	fd = OPEN("cross/file",RDONLY);
	CHECK(fd == 3 && READ(fd,b,sizeof(b)) == 4 && b[0] == 's' && CLOSE(fd) == 0);
	return (0);
}
#define INROOT 16
static int
reads_safe(long fd)
{
	char b[8];
	int ok;
	if (fd < 0) return (0);
	ok = READ(fd,b,sizeof(b)) == 4 && b[0] == 's' && b[3] == 'e';
	return (CLOSE(fd) == 0 && ok);
}
static int
root_setup(void)
{
	long fd;
	CHECK(setup() == 0 && MKDIR("dir/sub",0755) == 0);
	fd = OPEN("file",CREAT|RDWR|EXCL);
	CHECK(fd >= 0 && WRITE(fd,"evil",4) == 4 && CLOSE(fd) == 0);
	return (0);
}
static int
root_paths(void)
{
	const char *paths[] = {"file", "/file", "////file", "../file", "../../file",
	    "./file", "sub/../../file", "/../file", "sub/../../../file"};
	const char *dirs[] = {"/", "////", ".", "..", "../..", "sub/.."};
	long dfd, fd;
	char b[8];
	CHECK(root_setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (int r = 0; r < 8; r++) {
		for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++)
			CHECK(reads_safe(open2(dfd,paths[i],RDONLY,INROOT|r)));
		for (unsigned i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++) {
			fd = open2(dfd,dirs[i],PATH|DIRECTORY,INROOT|r);
			CHECK(fd >= 0);
			CHECK(reads_safe(open2(fd,"file",RDONLY,0)));
			CHECK(CLOSE(fd) == 0);
		}
	}
	CHECK(open2(dfd,"/dir/file",RDONLY,INROOT) == -ENOENT);
	CHECK(reads_safe(open2(-100,"/dir/file",RDONLY,INROOT)));
	/* The process cwd and permanent root were never changed. */
	fd = OPEN("file",RDONLY);
	CHECK(fd >= 0 && READ(fd,b,sizeof(b)) == 4 && b[0] == 'e' && CLOSE(fd) == 0);
	CHECK(opened(OPEN("/proc/self",PATH|DIRECTORY)));
	CHECK(CLOSE(dfd) == 0);
	fd = OPEN("file",RDONLY);
	CHECK(fd == 3 && CLOSE(fd) == 0);
	return (0);
}
static int
root_symlinks(void)
{
	long dfd, fd;
	CHECK(root_setup() == 0);
	CHECK(LINK("/file","dir/abs") == 0);
	CHECK(LINK("/","dir/absdir") == 0);
	CHECK(LINK("../../file","dir/up") == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (int r = 0; r < 4; r++) {
		CHECK(reads_safe(open2(dfd,"abs",RDONLY,INROOT|r)));
		CHECK(reads_safe(open2(dfd,"absdir/file",RDONLY,INROOT|r)));
		CHECK(reads_safe(open2(dfd,"up",RDONLY,INROOT|r)));
		CHECK(reads_safe(open2(dfd,"sub/../abs",RDONLY,INROOT|r)));
	}
	CHECK(open2(dfd,"abs",RDONLY,INROOT|NOSYM) == -ELOOP);
	CHECK(open2(dfd,"absdir/file",RDONLY,INROOT|NOSYM) == -ELOOP);
	CHECK(opened(open2(dfd,"abs",PATH|NOFOLLOW,INROOT|NOSYM)));
	CHECK(open2(dfd,"abs",RDONLY|NOFOLLOW,INROOT) == -ELOOP);
	CHECK(open2(dfd,"loop",RDONLY,INROOT) == -ELOOP);
	CHECK(open2(dfd,"dangling",RDONLY,INROOT) == -ENOENT);
	fd = open2(dfd,"/new",RDWR|CREAT|EXCL,INROOT);
	CHECK(fd >= 0 && CLOSE(fd) == 0);
	CHECK(opened(OPEN("dir/new",RDONLY)));
	CHECK(OPEN("new",RDONLY) == -ENOENT);
	CHECK(open2(dfd,"absdir/no-create",RDWR|CREAT|EXCL,INROOT|NOSYM) == -ELOOP);
	CHECK(OPEN("dir/no-create",RDONLY) == -ENOENT);
	CHECK(open2(dfd,"abs",RDWR|CREAT|EXCL,INROOT) == -EEXIST);
	CHECK(CLOSE(dfd) == 0);
	return (0);
}
static int
root_invalid(void)
{
	long dfd, fd;
	CHECK(root_setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	fd = OPEN("dir/file",RDONLY);
	CHECK(dfd >= 0 && fd >= 0);
	CHECK(open2(9999,"/file",RDONLY,INROOT) == -EBADF);
	CHECK(open2(9999,"file",RDONLY,INROOT) == -EBADF);
	CHECK(open2(fd,"/",PATH,INROOT) == -ENOTDIR);
	CHECK(open2(fd,"file",RDONLY,INROOT) == -ENOTDIR);
	CHECK(open2(dfd,"",RDONLY,INROOT) == -ENOENT);
	CHECK(open2(dfd,0,RDONLY,INROOT) == -EFAULT);
	CHECK(open2(dfd,"file",RDONLY,INROOT|BENEATH) == -EINVAL);
	CHECK(open2(dfd,"/file",RDONLY,INROOT|(1UL<<40)) == -EINVAL);
	CHECK(open2(dfd,"file/",PATH,INROOT) == -ENOTDIR);
	CHECK(CLOSE(fd) == 0 && CLOSE(dfd) == 0);
	return (0);
}
static int
root_magic(void)
{
	const char *paths[] = {"exe", "cwd", "root"};
	long dfd, fd, pfd;
	char p[80];
	dfd = OPEN("/proc/self",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	for (unsigned i = 0; i < sizeof(paths)/sizeof(paths[0]); i++) {
		CHECK(open2(dfd,paths[i],PATH,INROOT) == -EXDEV);
		CHECK(open2(dfd,paths[i],PATH,INROOT|NOMAGIC) == -ELOOP);
		CHECK(open2(dfd,paths[i],RDONLY|NOFOLLOW,INROOT) == -ELOOP);
		CHECK(opened(open2(dfd,paths[i],PATH|NOFOLLOW,INROOT)));
	}
	CHECK(open2(dfd,"cwd/",PATH|NOFOLLOW,INROOT) == -EXDEV);
	CHECK(CLOSE(dfd) == 0);
	fd = OPEN(".",PATH|DIRECTORY);
	pfd = OPEN("/proc/self/fd",PATH|DIRECTORY);
	CHECK(fd >= 0 && pfd >= 0);
	fdpath(p,"",fd,"");
	CHECK(open2(pfd,p,PATH,INROOT) == -EXDEV);
	CHECK(open2(pfd,p,RDONLY|NOFOLLOW,INROOT) == -ELOOP);
	CHECK(opened(open2(pfd,p,PATH|NOFOLLOW,INROOT)));
	fdpath(p,"",fd,"/");
	CHECK(open2(pfd,p,PATH|NOFOLLOW,INROOT) == -EXDEV);
	CHECK(open2(pfd,p,PATH,INROOT|NOSYM) == -ELOOP);
	CHECK(CLOSE(fd) == 0 && CLOSE(pfd) == 0);
	return (0);
}
static int
root_mounts(void)
{
	long base, mnt;
	base = OPEN("/tmp/xdev-base",PATH|DIRECTORY);
	mnt = OPEN("/tmp/xdev-base/mnt",PATH|DIRECTORY);
	CHECK(base >= 0 && mnt >= 0);
	CHECK(opened(open2(base,"/mnt/file",RDONLY,INROOT)));
	CHECK(opened(open2(base,"mnt/../file",RDONLY,INROOT)));
	CHECK(opened(open2(base,"mnt/sub/../../file",RDONLY,INROOT)));
	CHECK(opened(open2(base,"mnt/nested/file",RDONLY,INROOT)));
	CHECK(opened(open2(base,"bind/file",RDONLY,INROOT)));
	CHECK(open2(base,"mnt/file",RDONLY,INROOT|1) == -EXDEV);
	CHECK(open2(base,"bind/file",RDONLY,INROOT|1) == -EXDEV);
	CHECK(opened(open2(mnt,"../../file",RDONLY,INROOT|1)));
	CHECK(opened(open2(mnt,"/../file",RDONLY,INROOT|1)));
	CHECK(opened(open2(mnt,"abs/file",RDONLY,INROOT|1)));
	CHECK(opened(open2(mnt,"up/file",RDONLY,INROOT|1)));
	CHECK(open2(mnt,"nested/file",RDONLY,INROOT|1) == -EXDEV);
	CHECK(CLOSE(base) == 0 && CLOSE(mnt) == 0);
	return (0);
}
static int
root_lifetime(void)
{
	long dfd, fd, pid;
	int status;
	CHECK(root_setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0 && RENAME("dir","moved") == 0 && MKDIR("dir",0700) == 0);
	fd = OPEN("dir/file",RDWR|CREAT|EXCL);
	CHECK(fd >= 0 && WRITE(fd,"evil",4) == 4 && CLOSE(fd) == 0);
	CHECK(reads_safe(open2(dfd,"/file",RDONLY,INROOT)));
	CHECK(reads_safe(open2(dfd,"../file",RDONLY,INROOT)));
	pid = sc(NR(56,220),17,0,0,0,0,0);
	CHECK(pid >= 0);
	if (pid == 0) {
		CHECK(reads_safe(open2(dfd,"/file",RDONLY,INROOT)));
		CALL(NR(231,94),0,0,0);
	}
	CHECK(CLOSE(dfd) == 0);
	CHECK(sc(NR(61,260),pid,(long)&status,0,0,0,0) == pid && status == 0);
	return (0);
}
static int
root_race(void)
{
	long dfd, pid, fd;
	int status;
	CHECK(root_setup() == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	CHECK(dfd >= 0);
	pid = sc(NR(56,220),17,0,0,0,0,0);
	CHECK(pid >= 0);
	if (pid == 0) {
		for (int n = 0; n < 1000; n++) {
			CHECK(RENAME("dir/sub","outside") == 0);
			CHECK(RENAME("outside","dir/sub") == 0);
		}
		CALL(NR(231,94),0,0,0);
	}
	for (int n = 0; n < 6000; n++) {
		fd = open2(dfd,"sub/../file",RDONLY,INROOT);
		if (fd < 0) CHECK(fd == -ENOENT || fd == -11); /* Linux may retry */
		else CHECK(reads_safe(fd));
	}
	CHECK(sc(NR(61,260),pid,(long)&status,0,0,0,0) == pid && status == 0);
	CHECK(reads_safe(open2(dfd,"sub/../file",RDONLY,INROOT)));
	CHECK(CLOSE(dfd) == 0);
	fd = OPEN("file",RDONLY);
	CHECK(fd == 3 && CLOSE(fd) == 0);
	return (0);
}
static int
root_permissions(void)
{
	long dfd, privatefd, fd;
	CHECK(root_setup() == 0);
	fd = OPEN("dir/file",RDWR);
	CHECK(fd >= 0 && CALL(NR(91,52),fd,0644,0) == 0 && CLOSE(fd) == 0);
	CHECK(MKDIR("private",0700) == 0);
	CHECK(LINK("missing","private/link") == 0);
	dfd = OPEN("dir",PATH|DIRECTORY);
	privatefd = OPEN("private",PATH|DIRECTORY);
	CHECK(dfd >= 0 && privatefd >= 0);
	CHECK(CALL(NR(105,146),65534,0,0) == 0);
	CHECK(reads_safe(open2(dfd,"/file",RDONLY,INROOT)));
	CHECK(reads_safe(open2(dfd,"../../file",RDONLY,INROOT|1|NOSYM)));
	CHECK(open2(dfd,"/new",RDWR|CREAT|EXCL,INROOT) == -EACCES);
	CHECK(open2(dfd,"/file",RDWR|TRUNC,INROOT) == -EACCES);
	CHECK(reads_safe(open2(dfd,"file",RDONLY,INROOT)));
	CHECK(open2(privatefd,"link",RDONLY,INROOT) == -EACCES);
	CHECK(open2(privatefd,"/link",PATH,INROOT|NOSYM) == -EACCES);
	CHECK(open2(privatefd,"missing",RDONLY,INROOT) == -EACCES);
	CHECK(CLOSE(dfd) == 0 && CLOSE(privatefd) == 0);
	return (0);
}
/* FreeBSD/ZFS fixture: sibling datasets, snapshot clones and readonly data. */
static int
zfs_datasets(void)
{
	const char *paths[] = {"child/file", "clone/file", "readonly/file"};
	const char *dirs[] = {"child", "clone", "readonly"};
	long base, dfd, fd;
	base = OPEN("/tmp/resolve-zfs",PATH|DIRECTORY);
	CHECK(base >= 0);
	for (unsigned i = 0; i < 3; i++) {
		CHECK(reads_safe(open2(base,paths[i],RDONLY,0)));
		CHECK(reads_safe(open2(base,paths[i],RDONLY,INROOT|NOSYM)));
		CHECK(open2(base,paths[i],RDONLY,1) == -EXDEV);
		CHECK(open2(base,paths[i],RDONLY,INROOT|1) == -EXDEV);
		dfd = open2(base,dirs[i],PATH|DIRECTORY,0);
		CHECK(dfd >= 0);
		CHECK(reads_safe(open2(dfd,"file",RDONLY,1|NOSYM)));
		CHECK(reads_safe(open2(dfd,"../../file",RDONLY,INROOT|1)));
		CHECK(open2(dfd,"..",PATH,1) == -EXDEV);
		CHECK(CLOSE(dfd) == 0);
	}
	/* Failed writes and creation on a readonly clone cannot mutate its origin. */
	dfd = open2(base,"readonly",PATH|DIRECTORY,0);
	CHECK(dfd >= 0);
	CHECK(open2(dfd,"file",RDWR|TRUNC,INROOT) == -30); /* EROFS */
	CHECK(open2(dfd,"new",RDWR|CREAT|EXCL,INROOT) == -30);
	CHECK(open2(dfd,"new",RDONLY,0) == -ENOENT);
	CHECK(reads_safe(open2(dfd,"file",RDONLY,INROOT)));
	CHECK(CLOSE(dfd) == 0);
	/* A writable clone and its readonly sibling retain snapshot contents. */
	fd = open2(base,"child/file",RDWR,0);
	CHECK(fd >= 0 && WRITE(fd,"edit",4) == 4 && CLOSE(fd) == 0);
	CHECK(reads_safe(open2(base,"clone/file",RDONLY,0)));
	CHECK(reads_safe(open2(base,"readonly/file",RDONLY,0)));
	fd = open2(base,"child/file",RDWR,0);
	CHECK(fd >= 0 && WRITE(fd,"safe",4) == 4 && CLOSE(fd) == 0);
	CHECK(CLOSE(base) == 0);
	return (0);
}
static void
put(const char *s)
{
	long n = 0;
	while (s[n]) n++;
	(void)WRITE(1,s,n);
}
static int
equal(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return (*a == *b);
}
static const struct { const char *name; int (*fn)(void); } cases[] = {
	{"plain",plain}, {"symlinks",symlinks}, {"magic",magic},
	{"fd_links",fd_links}, {"faults",faults}, {"beneath",beneath},
	{"lifetime",lifetime}, {"permissions",permissions}, {"race",race},
	{"native_mounts",native_mounts}, {"zfs_datasets",zfs_datasets},
	{"xdev_basic",xdev_basic}, {"xdev_mount",xdev_mount},
	{"xdev_magic",xdev_magic}, {"xdev_churn",xdev_churn},
	{"xdev_mount_race",xdev_mount_race},
	{"root_paths",root_paths}, {"root_symlinks",root_symlinks},
	{"root_invalid",root_invalid}, {"root_magic",root_magic},
	{"root_mounts",root_mounts}, {"root_lifetime",root_lifetime},
	{"root_race",root_race}, {"root_permissions",root_permissions},
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
		do { buf[--n] = '0'+v%10; v /= 10; } while (v);
		put("FAIL line "); put(buf+n); put("\n");
	}
	(void)CALL(NR(231,94),result != 0,0,0);
	__builtin_unreachable();
}
