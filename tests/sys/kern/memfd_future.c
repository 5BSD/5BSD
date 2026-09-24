/* SPDX-License-Identifier: BSD-2-Clause */
/* Shared native and Linux tests for future-write sealing. */
#ifdef LINUX_ABI
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
#define EPERM 1
#define EACCES 13
#define EINVAL 22
#define EBUSY 16
#define EBADF 9
#define EFAULT 14
#define ESPIPE 29
#define RANGE_OVERFLOW 27 /* EFBIG */
#define F_ADD_SEALS 1033
#define F_GET_SEALS 1034
#define MAP_SHARED 1
#define MAP_PRIVATE 2
static long newfd(int flags) { return CALL(NR(319,279),"future",flags,0); }
static long ctl(int fd,int cmd,long arg) { return CALL(NR(72,25),fd,cmd,arg); }
static long closefd(int fd) { return CALL(NR(3,57),fd,0,0); }
static long dupfd(int fd) { return ctl(fd,0,0); }
static long resize(int fd,long n) { return CALL(NR(77,46),fd,n,0); }
static long mapping(int fd,int prot,int flags) { return sc(NR(9,222),0,4096,prot,flags,fd,0); }
static long protect(long addr,int prot) { return CALL(NR(10,226),addr,4096,prot); }
static long unmap(long addr) { return CALL(NR(11,215),addr,4096,0); }
static long writefd(int fd,const void *p,long n) { return CALL(NR(1,64),fd,p,n); }
static long readfd(int fd,void *p,long n) { return CALL(NR(0,63),fd,p,n); }
static long pwritefd(int fd,const void *p,long n) { return sc(NR(18,68),fd,(long)p,n,0,0,0); }
static long pread_at(int fd,void *p,long n,long off) { return sc(NR(17,67),fd,(long)p,n,off,0,0); }
static long writevec(int fd)
{
	struct { void *p; unsigned long n; } iov = {(void *)"v",1};
	return CALL(NR(20,66),fd,&iov,1);
}
static long punch_at(int fd,long off,long len) { return sc(NR(285,47),fd,3,off,len,0,0); }
static long allocate(int fd,long off,long len) { return sc(NR(285,47),fd,0,off,len,0,0); }
static long forkproc(void) { return sc(NR(56,220),17,0,0,0,0,0); }
static long waitproc(int pid,int *s) { return sc(NR(61,260),pid,(long)s,0,0,0,0); }
static long pipefd(int *p) { return CALL(NR(293,59),p,0,0); }
static void finish(int rc) { CALL(NR(231,94),rc,0,0); __builtin_unreachable(); }
#else
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define RANGE_OVERFLOW EINVAL
static void put(const char *s) { fputs(s,stdout); }
static int equal(const char *a,const char *b) { return strcmp(a,b) == 0; }
static long result(long r) { return r == -1 ? -errno : r; }
static long newfd(int flags) { return result(memfd_create("future",flags)); }
static long ctl(int fd,int cmd,long arg) { return result(fcntl(fd,cmd,arg)); }
static long closefd(int fd) { return result(close(fd)); }
static long dupfd(int fd) { return result(dup(fd)); }
static long resize(int fd,long n) { return result(ftruncate(fd,n)); }
static long mapping(int fd,int prot,int flags) { return result((long)mmap(0,4096,prot,flags,fd,0)); }
static long protect(long addr,int prot) { return result(mprotect((void *)addr,4096,prot)); }
static long unmap(long addr) { return result(munmap((void *)addr,4096)); }
static long writefd(int fd,const void *p,long n) { return result(write(fd,p,n)); }
static long readfd(int fd,void *p,long n) { return result(read(fd,p,n)); }
static long pwritefd(int fd,const void *p,long n) { return result(pwrite(fd,p,n,0)); }
static long pread_at(int fd,void *p,long n,long off) { return result(pread(fd,p,n,off)); }
static long writevec(int fd) { struct iovec iov = {(void *)"v",1}; return result(writev(fd,&iov,1)); }
static long punch_at(int fd,long off,long len) { struct spacectl_range r = {off,len}; return result(fspacectl(fd,SPACECTL_DEALLOC,&r,0,0)); }
static long allocate(int fd,long off,long len) { return -posix_fallocate(fd,off,len); }
static long forkproc(void) { return result(fork()); }
static long waitproc(int pid,int *s) { return result(waitpid(pid,s,0)); }
static long pipefd(int *p) { return result(pipe(p)); }
static void finish(int rc) { _exit(rc); }
#endif
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
#define FUTURE 16
#define punch(fd) punch_at(fd,0,4096)
static int mappings(void)
{
	long fd = newfd(2), rw, ro, after, none, priv;
	CHECK(fd >= 0 && resize(fd,4096) == 0);
	rw = mapping(fd,3,MAP_SHARED); ro = mapping(fd,1,MAP_SHARED);
	CHECK(rw > 0 && ro > 0);
	*(volatile char *)rw = 'a';
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0 && ctl(fd,F_GET_SEALS,0) == FUTURE);
	CHECK(writefd(fd,"x",1) == -EPERM && pwritefd(fd,"x",1) == -EPERM);
	CHECK(writevec(fd) == -EPERM);
	CHECK(punch(fd) == -EPERM);
	CHECK(*(volatile char *)ro == 'a');
	*(volatile char *)rw = 'b';
	CHECK(*(volatile char *)ro == 'b');
	CHECK(protect(ro,3) == 0); /* A pre-seal mapping retains its maximum rights. */
	*(volatile char *)ro = 'c';
	CHECK(mapping(fd,3,MAP_SHARED) == -EPERM);
	after = mapping(fd,1,MAP_SHARED); none = mapping(fd,0,MAP_SHARED);
	CHECK(after > 0 && none > 0);
	CHECK(protect(after,3) == -EACCES && protect(none,3) == -EACCES);
	priv = mapping(fd,3,MAP_PRIVATE); CHECK(priv > 0);
	*(volatile char *)priv = 'p'; CHECK(*(volatile char *)rw == 'c');
	CHECK(ctl(fd,F_ADD_SEALS,8) == -EBUSY && ctl(fd,F_GET_SEALS,0) == FUTURE);
	CHECK(unmap(rw) == 0 && unmap(ro) == 0);
	CHECK(ctl(fd,F_ADD_SEALS,8) == 0 && ctl(fd,F_GET_SEALS,0) == (FUTURE|8));
	CHECK(unmap(after) == 0 && unmap(none) == 0 && unmap(priv) == 0);
	CHECK(closefd(fd) == 0);
	return 0;
}
static int invalid(void)
{
	long fd = newfd(2), map;
	CHECK(fd >= 0 && resize(fd,4096) == 0);
	CHECK(ctl(-1,F_ADD_SEALS,FUTURE) == -EBADF && ctl(-1,F_GET_SEALS,0) == -EBADF);
	for (unsigned bit = 6; bit < 32; bit++) {
		CHECK(ctl(fd,F_ADD_SEALS,(1U << bit)|FUTURE) == -EINVAL);
		CHECK(ctl(fd,F_GET_SEALS,0) == 0);
	}
	map = mapping(fd,3,MAP_SHARED); CHECK(map > 0);
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE|8|1) == -EBUSY);
	CHECK(ctl(fd,F_GET_SEALS,0) == 0 && pwritefd(fd,"x",1) == 1);
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0);
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0 && ctl(fd,F_ADD_SEALS,0) == 0);
	CHECK(ctl(fd,F_ADD_SEALS,1) == 0);
	CHECK(ctl(fd,F_ADD_SEALS,0) == -EPERM && ctl(fd,F_ADD_SEALS,FUTURE) == -EPERM);
	CHECK(ctl(fd,F_GET_SEALS,0) == (FUTURE|1));
	CHECK(unmap(map) == 0 && closefd(fd) == 0);
	fd = newfd(0); CHECK(fd >= 0 && ctl(fd,F_ADD_SEALS,FUTURE) == -EPERM);
	CHECK(closefd(fd) == 0);
	return 0;
}
static int lifetime(void)
{
	long fd = newfd(2), dup, map; int p[2], status;
	CHECK(fd >= 0 && resize(fd,4096) == 0);
	map = mapping(fd,3,MAP_SHARED); dup = dupfd(fd);
	CHECK(map > 0 && dup >= 0 && pipefd(p) == 0);
	long pid = forkproc(); CHECK(pid >= 0);
	if (pid == 0) {
		char c;
		if (readfd(p[0],&c,1) != 1 || ctl(dup,F_GET_SEALS,0) != FUTURE ||
		    pwritefd(dup,"x",1) != -EPERM || mapping(dup,3,MAP_SHARED) != -EPERM)
			finish(1);
		*(volatile char *)map = 'f';
		finish(0);
	}
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0 && closefd(fd) == 0);
	CHECK(writefd(p[1],"s",1) == 1 && waitproc(pid,&status) == pid && status == 0);
	char c; CHECK(pread_at(dup,&c,1,0) == 1 && c == 'f');
	CHECK(unmap(map) == 0 && ctl(dup,F_ADD_SEALS,8) == 0);
	CHECK(closefd(dup) == 0);
	return 0;
}
static int resizing(void)
{
	long fd = newfd(2); CHECK(fd >= 0 && allocate(fd,0,4096) == 0);
	CHECK(allocate(fd,0,0) == -EINVAL && allocate(fd,-1,1) == -EINVAL);
	CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0);
	CHECK(allocate(fd,0,8192) == 0);
	CHECK(resize(fd,8192) == 0 && resize(fd,4096) == 0);
	CHECK(ctl(fd,F_ADD_SEALS,2|4) == 0);
	CHECK(resize(fd,8192) == -EPERM && resize(fd,0) == -EPERM);
	CHECK(allocate(fd,0,8192) == -EPERM);
	CHECK(resize(fd,4096) == 0);
	CHECK(ctl(fd,F_GET_SEALS,0) == (FUTURE|2|4) && closefd(fd) == 0);
	return 0;
}
static int churn(void)
{
	for (int i = 0; i < 256; i++) {
		long fd = newfd(2); CHECK(fd >= 0 && resize(fd,4096) == 0);
		long map = mapping(fd,3,MAP_SHARED); CHECK(map > 0);
		CHECK(ctl(fd,F_ADD_SEALS,FUTURE) == 0);
		CHECK(mapping(fd,3,MAP_SHARED) == -EPERM);
		CHECK(closefd(fd) == 0);
		*(volatile char *)map = 'z';
		CHECK(unmap(map) == 0);
	}
	return 0;
}
static int io_contract(void)
{
	long fd = newfd(2); char buf[4]; int p[2];
	CHECK(fd >= 0 && resize(fd,4096) == 0);
	CHECK(pwritefd(fd,"abc",3) == 3);
	CHECK(pread_at(fd,buf,3,0) == 3 && buf[0] == 'a' && buf[2] == 'c');
	CHECK(pread_at(fd,buf,1,1) == 1 && buf[0] == 'b');
	CHECK(pread_at(fd,buf,1,4096) == 0);
	CHECK(pread_at(fd,0,0,0) == 0);
	CHECK(pread_at(fd,0,1,0) == -EFAULT);
	CHECK(pread_at(fd,buf,1,-1) == -EINVAL);
	CHECK(pread_at(-1,buf,1,0) == -EBADF && punch(-1) == -EBADF);
	CHECK(pipefd(p) == 0 && pread_at(p[0],buf,1,0) == -ESPIPE);
	CHECK(closefd(p[0]) == 0 && closefd(p[1]) == 0);
	CHECK(punch_at(fd,8192,4096) == 0);
	CHECK(punch_at(fd,0,0) == -EINVAL && punch_at(fd,-1,1) == -EINVAL);
	CHECK(punch_at(fd,0x7fffffffffffffffL,1) == -RANGE_OVERFLOW);
	CHECK(punch(fd) == 0);
	CHECK(pread_at(fd,buf,3,0) == 3 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0);
	CHECK(pwritefd(fd,"xyz",3) == 3 && ctl(fd,F_ADD_SEALS,FUTURE) == 0);
	CHECK(punch(fd) == -EPERM && pwritefd(fd,"bad",3) == -EPERM);
	CHECK(pread_at(fd,buf,3,0) == 3 && buf[0] == 'x' && buf[2] == 'z');
	CHECK(closefd(fd) == 0);
	return 0;
}
#ifndef LINUX_ABI
static int readonly(void)
{
	char name[80];
	snprintf(name,sizeof(name),"/future-seal-%ld",(long)getpid());
	int rw = syscall(SYS_shm_open2,name,O_CREAT|O_EXCL|O_RDWR,0600,SHM_ALLOW_SEALING,NULL);
	CHECK(rw >= 0);
	int ro = syscall(SYS_shm_open2,name,O_RDONLY,0,SHM_ALLOW_SEALING,NULL);
	CHECK(shm_unlink(name) == 0 && ro >= 0);
	CHECK(ctl(ro,F_ADD_SEALS,FUTURE) == -EPERM);
	CHECK(ctl(ro,F_ADD_SEALS,0) == -EPERM);
	CHECK(ctl(rw,F_GET_SEALS,0) == 0);
	CHECK(ctl(rw,F_ADD_SEALS,FUTURE) == 0 && ctl(ro,F_GET_SEALS,0) == FUTURE);
	CHECK(closefd(ro) == 0 && closefd(rw) == 0);
	return 0;
}
#endif
static const struct { const char *name; int (*fn)(void); } cases[] = {
	{"mappings",mappings}, {"invalid",invalid}, {"lifetime",lifetime},
	{"resizing",resizing}, {"churn",churn}, {"io_contract",io_contract},
#ifndef LINUX_ABI
	{"readonly",readonly},
#endif
};
static int run(int argc,char **argv)
{
	int r = 111;
	if (argc == 2) for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		if (equal(argv[1],"-l")) { put(cases[i].name); put("\n"); r = 0; }
		else if (equal(argv[1],cases[i].name)) { r = cases[i].fn(); break; }
	}
	if (r != 0) {
		char buf[16]; unsigned n = sizeof(buf)-1,v = r; buf[n] = 0;
		do { buf[--n] = '0'+v%10; v /= 10; } while (v);
		put("FAIL line "); put(buf+n); put("\n");
	}
	return r != 0;
}
#ifdef LINUX_ABI
void start_c(long *sp) { finish(run(sp[0],(char **)(sp+1))); }
#else
int main(int argc,char **argv) { return run(argc,argv); }
#endif
