/* SPDX-License-Identifier: BSD-2-Clause */
/* The same cases exercise native fcntl and both 64-bit Linux ABIs. */
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
#define EINVAL 22
#define EBADF 9
#define EFAULT 14
#define EAGAIN 11
#define EINTR 4
#define EOVERFLOW 75
#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2
#define F_GETLK 5
#define F_SETLK 6
#define F_OFD_GETLK 36
#define F_OFD_SETLK 37
#define F_OFD_SETLKW 38
#define O_RDWR 2
#define O_RDONLY 0
#define O_WRONLY 1
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_PATH 010000000
#define SIGUSR1 10
#define SIGKILL 9
struct flock { short l_type, l_whence; long l_start, l_len; int l_pid; };
static long op_open(int flags) { return sc(NR(257,56),-100,(long)"file",flags,0600,0,0); }
static long op_close(int fd) { return CALL(NR(3,57),fd,0,0); }
static long op_fcntl(int fd, int cmd, void *p) { return CALL(NR(72,25),fd,cmd,p); }
static long op_dup(int fd) { return op_fcntl(fd,0,0); }
static long op_fork(void) { return sc(NR(56,220),17,0,0,0,0,0); }
static long op_wait(int pid, int *st) { return sc(NR(61,260),pid,(long)st,0,0,0,0); }
static long op_pipe(int *p) { return CALL(NR(293,59),p,0,0); }
static long op_read(int fd, void *p, long n) { return CALL(NR(0,63),fd,p,n); }
static long op_write(int fd, const void *p, long n) { return CALL(NR(1,64),fd,p,n); }
static long op_seek(int fd, long n) { return CALL(NR(8,62),fd,n,0); }
static long op_flock(int fd, int op) { return CALL(NR(73,32),fd,op,0); }
static long op_kill(int pid, int sig) { return CALL(NR(62,129),pid,sig,0); }
static long op_pid(void) { return CALL(NR(39,172),0,0,0); }
static long op_exec(const char *p,char **argv) { return CALL(NR(59,221),p,argv,0); }
static void op_exit(int rc) { CALL(NR(231,94),rc,0,0); __builtin_unreachable(); }
static long op_sleep(void) { long ts[2] = {0,100000000}; return CALL(NR(35,101),ts,0,0); }
static long op_ready(int fd, int ms)
{
	struct { int fd; short events, revents; } p = {fd,1,0};
	long ts[2] = {ms/1000,(ms%1000)*1000000L};
	return sc(NR(271,73),(long)&p,1,(long)ts,0,8,0);
}
static long op_map(void) { return sc(NR(9,222),0,8192,3,0x22,-1,0); }
static long op_protect(void *p,int prot) { return CALL(NR(10,226),p,4096,prot); }
static long op_unmap(void *p) { return CALL(NR(11,215),p,8192,0); }
static long op_pair(int *p) { return sc(NR(53,199),1,1,0,(long)p,0,0); }
static long op_pass(int sock,int fd,int receive)
{
	char byte = 0;
	struct { void *base; unsigned long len; } iov = {&byte,1};
	struct { unsigned long len; int level,type,fd,pad; } control = {20,1,1,fd,0};
	struct { void *name; unsigned namelen; void *iov; unsigned long iovlen;
	    void *control; unsigned long controllen; unsigned flags; }
	    msg = {0,0,&iov,1,&control,sizeof(control),0};
	long r = CALL(receive ? NR(47,212) : NR(46,211),sock,&msg,0);
	if (r != 1) return -1;
	if (receive && (control.len != 20 || control.level != 1 || control.type != 1)) return -1;
	return receive ? control.fd : 0;
}
extern void restorer(void);
#if defined(__x86_64__)
__asm__(".text\nrestorer:\nmov $15,%rax\nsyscall\n");
#else
__asm__(".text\nrestorer:\nmov x8,#139\nsvc #0\n");
#endif
static long op_handler(void (*fn)(int))
{
	struct { void (*fn)(int); unsigned long flags; void (*restorer)(void); unsigned long mask; }
	    sa = {fn,0x04000000,restorer,0};
	return sc(NR(13,134),SIGUSR1,(long)&sa,0,8,0,0);
}
#else
#include <sys/types.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
/* Allow building the test before installing the new userspace headers. */
#ifndef F_OFD_GETLK
#define F_OFD_GETLK 25
#define F_OFD_SETLK 26
#define F_OFD_SETLKW 27
#endif
static long result(long r) { return r == -1 ? -errno : r; }
static void put(const char *s) { fputs(s,stdout); }
static int equal(const char *a,const char *b) { return strcmp(a,b) == 0; }
static long op_open(int flags) { return result(open("file",flags,0600)); }
static long op_close(int fd) { return result(close(fd)); }
static long op_fcntl(int fd,int cmd,void *p) { return result(fcntl(fd,cmd,p)); }
static long op_dup(int fd) { return result(dup(fd)); }
static long op_fork(void) { return result(fork()); }
static long op_wait(int pid,int *st) { return result(waitpid(pid,st,0)); }
static long op_pipe(int *p) { return result(pipe(p)); }
static long op_read(int fd,void *p,long n) { return result(read(fd,p,n)); }
static long op_write(int fd,const void *p,long n) { return result(write(fd,p,n)); }
static long op_seek(int fd,long n) { return result(lseek(fd,n,SEEK_SET)); }
static long op_flock(int fd,int op) { return result(flock(fd,op)); }
static long op_kill(int pid,int sig) { return result(kill(pid,sig)); }
static long op_pid(void) { return getpid(); }
static long op_exec(const char *p,char **argv) { char *env[] = {NULL}; return result(execve(p,argv,env)); }
static void op_exit(int rc) { _exit(rc); }
static long op_sleep(void) { struct timespec ts = {0,100000000}; return result(nanosleep(&ts,0)); }
static long op_ready(int fd,int ms) { struct pollfd p = {fd,POLLIN,0}; return result(poll(&p,1,ms)); }
static long op_map(void) { return result((long)mmap(0,8192,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0)); }
static long op_protect(void *p,int prot) { return result(mprotect(p,4096,prot)); }
static long op_unmap(void *p) { return result(munmap(p,8192)); }
static long op_pair(int *p) { return result(socketpair(AF_UNIX,SOCK_STREAM,0,p)); }
static long op_pass(int sock,int fd,int receive)
{
	char byte = 0;
	struct iovec iov = {&byte,1};
	union { struct cmsghdr align; char data[CMSG_SPACE(sizeof(int))]; } control;
	struct msghdr msg = {0};
	memset(&control,0,sizeof(control));
	msg.msg_iov = &iov; msg.msg_iovlen = 1;
	msg.msg_control = &control; msg.msg_controllen = sizeof(control);
	struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
	c->cmsg_len = CMSG_LEN(sizeof(int)); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(c),&fd,sizeof(fd));
	long r = receive ? recvmsg(sock,&msg,0) : sendmsg(sock,&msg,0);
	if (r != 1) return -1;
	if (receive) {
		if (c->cmsg_len != CMSG_LEN(sizeof(int)) || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) return -1;
		memcpy(&fd,CMSG_DATA(c),sizeof(fd));
	}
	return receive ? fd : 0;
}
static long op_handler(void (*fn)(int))
{
	struct sigaction sa;
	memset(&sa,0,sizeof(sa)); sa.sa_handler = fn;
	return result(sigaction(SIGUSR1,&sa,0));
}
#endif
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
static struct flock lock(short type,long start,long len)
{
	struct flock fl = {0};
	fl.l_type = type; fl.l_start = start; fl.l_len = len;
	return fl;
}
static long set(int fd,short type,long start,long len)
{
	struct flock fl = lock(type,start,len);
	return op_fcntl(fd,F_OFD_SETLK,&fl);
}
static int query(int fd,long start,long len,short type,long owner,long first,long count)
{
	struct flock fl = lock(F_WRLCK,start,len);
	CHECK(op_fcntl(fd,F_OFD_GETLK,&fl) == 0);
	CHECK(fl.l_type == type);
	if (type != F_UNLCK)
		CHECK(fl.l_pid == owner && fl.l_start == first && fl.l_len == count && fl.l_whence == 0);
	return 0;
}
static int ranges(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR);
	CHECK(a >= 0 && b >= 0);
	CHECK(set(a,F_WRLCK,10,30) == 0);
	CHECK(query(b,0,100,F_WRLCK,-1,10,30) == 0);
	CHECK(set(a,F_UNLCK,20,10) == 0);
	CHECK(query(b,20,10,F_UNLCK,0,0,0) == 0);
	CHECK(query(b,10,10,F_WRLCK,-1,10,10) == 0);
	CHECK(query(b,30,10,F_WRLCK,-1,30,10) == 0);
	CHECK(set(a,F_RDLCK,10,30) == 0);
	CHECK(query(b,0,100,F_RDLCK,-1,10,30) == 0);
	CHECK(set(b,F_RDLCK,10,30) == 0);
	CHECK(set(a,F_WRLCK,10,30) == -EAGAIN);
	CHECK(set(b,F_UNLCK,0,0) == 0);
	CHECK(set(a,F_WRLCK,10,30) == 0);
	CHECK(set(a,F_UNLCK,0,0) == 0);
	CHECK(set(a,F_WRLCK,20,-10) == 0);
	CHECK(query(b,0,100,F_WRLCK,-1,10,10) == 0);
	CHECK(set(a,F_WRLCK,20,0) == 0);
	CHECK(query(b,100000,1,F_WRLCK,-1,10,0) == 0);
	CHECK(op_close(a) == 0);
	CHECK(query(b,0,0,F_UNLCK,0,0,0) == 0);
	CHECK(op_write(b,"0123456789",10) == 10);
	struct flock fl = lock(F_WRLCK,-2,2); fl.l_whence = 2;
	CHECK(op_fcntl(b,F_OFD_SETLK,&fl) == 0);
	a = op_open(O_RDWR);
	CHECK(query(a,0,0,F_WRLCK,-1,8,2) == 0);
	CHECK(op_seek(b,5) == 5);
	fl = lock(F_WRLCK,-3,3); fl.l_whence = 1;
	CHECK(op_fcntl(b,F_OFD_SETLK,&fl) == 0);
	CHECK(query(a,0,6,F_WRLCK,-1,2,3) == 0);
	CHECK(op_close(a) == 0 && op_close(b) == 0);
	return 0;
}
static int invalid(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC);
	CHECK(a >= 0);
	for (int i = 0; i < 3; i++) {
		int cmd = i == 0 ? F_OFD_GETLK : i == 1 ? F_OFD_SETLK : F_OFD_SETLKW;
		struct flock fl = lock(F_WRLCK,0,1);
		CHECK(op_fcntl(-1,cmd,&fl) == -EBADF);
		CHECK(op_fcntl(a,cmd,0) == -EFAULT);
		CHECK(op_fcntl(a,cmd,(void *)1) == -EFAULT);
		fl.l_pid = 1; CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl.l_pid = -1; CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl.l_pid = 0; fl.l_type = 99; CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl = lock(F_WRLCK,0,1); fl.l_whence = 99; CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl = lock(F_WRLCK,-1,1); CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl = lock(F_WRLCK,0,-1); CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl = lock(F_WRLCK,1,-2); CHECK(op_fcntl(a,cmd,&fl) == -EINVAL);
		fl = lock(F_WRLCK,0x7fffffffffffffffL,2); CHECK(op_fcntl(a,cmd,&fl) == -EOVERFLOW);
		fl = lock(F_WRLCK,0x7fffffffffffffffL,1); fl.l_whence = 1;
		CHECK(op_seek(a,1) == 1 && op_fcntl(a,cmd,&fl) == -EOVERFLOW);
	}
	struct flock fl = lock(F_UNLCK,0,0);
	CHECK(op_fcntl(a,F_OFD_GETLK,&fl) == 0 && fl.l_type == F_UNLCK);
	int rd = op_open(O_RDONLY), wr = op_open(O_WRONLY), path = op_open(O_PATH);
	CHECK(rd >= 0 && wr >= 0 && path >= 0);
	CHECK(set(rd,F_WRLCK,0,1) == -EBADF && set(wr,F_RDLCK,0,1) == -EBADF);
	CHECK(set(path,F_RDLCK,0,1) == -EBADF);
	CHECK(op_close(rd) == 0 && op_close(wr) == 0 && op_close(path) == 0);
	CHECK(query(a,0,0,F_UNLCK,0,0,0) == 0 && op_close(a) == 0);
	return 0;
}
static int ownership(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR), d = op_dup(a);
	CHECK(a >= 0 && b >= 0 && d >= 0);
	CHECK(set(a,F_WRLCK,0,0) == 0);
	CHECK(query(d,0,0,F_UNLCK,0,0,0) == 0);
	CHECK(set(b,F_WRLCK,0,1) == -EAGAIN);
	int c = op_open(O_RDWR); CHECK(c >= 0 && op_close(c) == 0);
	CHECK(set(b,F_WRLCK,0,1) == -EAGAIN);
	CHECK(op_close(a) == 0);
	CHECK(set(b,F_WRLCK,0,1) == -EAGAIN);
	CHECK(set(d,F_RDLCK,0,0) == 0 && set(b,F_RDLCK,0,0) == 0);
	CHECK(op_close(d) == 0 && set(b,F_WRLCK,0,0) == 0);
	CHECK(op_close(b) == 0);
	return 0;
}
static int posix(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR);
	CHECK(a >= 0 && b >= 0 && set(a,F_WRLCK,0,10) == 0);
	struct flock fl = lock(F_WRLCK,0,10);
	CHECK(op_fcntl(a,F_SETLK,&fl) == -EAGAIN);
	CHECK(op_fcntl(a,F_GETLK,&fl) == 0 && fl.l_pid == -1 && fl.l_type == F_WRLCK);
	CHECK(set(a,F_UNLCK,0,0) == 0);
	fl = lock(F_WRLCK,0,10);
	CHECK(op_fcntl(a,F_SETLK,&fl) == 0);
	CHECK(set(a,F_WRLCK,0,1) == -EAGAIN);
	CHECK(query(a,0,10,F_WRLCK,op_pid(),0,10) == 0);
	CHECK(op_close(b) == 0); /* Any close drops the POSIX lock. */
	CHECK(set(a,F_WRLCK,0,10) == 0 && op_close(a) == 0);
	return 0;
}
static int flock_independent(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR);
	CHECK(a >= 0 && b >= 0);
	CHECK(op_flock(a,2|4) == 0); /* LOCK_EX|LOCK_NB */
	CHECK(set(a,F_WRLCK,10,10) == 0 && set(b,F_WRLCK,30,10) == 0);
	CHECK(op_flock(a,8) == 0);
	CHECK(query(b,10,10,F_WRLCK,-1,10,10) == 0);
	CHECK(op_flock(b,2|4) == 0);
	CHECK(set(b,F_UNLCK,0,0) == 0);
	CHECK(op_flock(a,2|4) == -EAGAIN);
	CHECK(op_close(b) == 0 && op_flock(a,2|4) == 0);
	CHECK(op_close(a) == 0);
	return 0;
}
static int fork_lifetime(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR), p[2], q[2], status;
	CHECK(a >= 0 && b >= 0 && op_pipe(p) == 0 && op_pipe(q) == 0);
	CHECK(set(a,F_WRLCK,0,0) == 0);
	long pid = op_fork(); CHECK(pid >= 0);
	if (pid == 0) {
		char c;
		if (query(a,0,0,F_UNLCK,0,0,0) != 0 || op_write(p[1],"r",1) != 1 ||
		    op_read(q[0],&c,1) != 1) op_exit(1);
		op_exit(0); /* Drop last inherited reference on exit. */
	}
	char c;
	CHECK(op_read(p[0],&c,1) == 1 && op_close(a) == 0);
	CHECK(set(b,F_WRLCK,0,0) == -EAGAIN);
	CHECK(op_write(q[1],"x",1) == 1);
	CHECK(op_wait(pid,&status) == pid && status == 0);
	CHECK(set(b,F_WRLCK,0,0) == 0 && op_close(b) == 0);
	return 0;
}
static volatile int caught;
static void handler(int sig) { caught = sig; }
/* The child announces the call, then the parent verifies no completion. */
static int waiter(int mode)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), p[2], status;
	CHECK(a >= 0 && op_pipe(p) == 0 && set(a,F_WRLCK,0,0) == 0);
	long pid = op_fork(); CHECK(pid >= 0);
	if (pid == 0) {
		op_close(a);
		int b = op_open(O_RDWR);
		if (b < 0 || op_handler(handler) != 0) op_exit(1);
		struct flock fl = lock(F_WRLCK,0,0);
		if (op_write(p[1],"r",1) != 1) op_exit(2);
		long r = op_fcntl(b,F_OFD_SETLKW,&fl);
		if ((mode == 2 && (r != -EINTR || !caught)) || (mode != 2 && r != 0)) op_exit(3);
		if (op_write(p[1],"d",1) != 1 || op_close(b) != 0) op_exit(4);
		op_exit(0);
	}
	char c;
	CHECK(op_read(p[0],&c,1) == 1 && op_ready(p[0],200) == 0);
	if (mode == 0) CHECK(set(a,F_UNLCK,0,0) == 0);
	if (mode == 1) CHECK(op_close(a) == 0);
	if (mode == 2) {
		/* Repeated delivery avoids racing the child's entry to fcntl. */
		for (int i = 0; i < 30 && op_ready(p[0],0) == 0; i++) {
			CHECK(op_kill(pid,SIGUSR1) == 0); op_sleep();
		}
	}
	if (mode == 3) {
		CHECK(op_kill(pid,SIGKILL) == 0);
		CHECK(op_wait(pid,&status) == pid && (status & 127) == SIGKILL);
	} else {
		CHECK(op_ready(p[0],3000) == 1 && op_read(p[0],&c,1) == 1 && c == 'd');
		CHECK(op_wait(pid,&status) == pid && status == 0);
	}
	if (mode != 1) CHECK(op_close(a) == 0);
	int b = op_open(O_RDWR);
	CHECK(b >= 0 && set(b,F_WRLCK,0,0) == 0 && op_close(b) == 0);
	return 0;
}
static int wait_unlock(void) { return waiter(0); }
static int wait_close(void) { return waiter(1); }
static int interrupted(void) { return waiter(2); }
static int killed_waiter(void) { return waiter(3); }
static int churn(void)
{
	int b = op_open(O_CREAT|O_RDWR|O_TRUNC); CHECK(b >= 0);
	for (int i = 0; i < 512; i++) {
		int a = op_open(O_RDWR), d = op_dup(a);
		CHECK(a >= 0 && d >= 0 && set(a,F_WRLCK,i,1) == 0);
		CHECK(op_close(a) == 0 && set(b,F_WRLCK,i,1) == -EAGAIN);
		CHECK(op_close(d) == 0 && set(b,F_WRLCK,i,1) == 0);
		CHECK(set(b,F_UNLCK,0,0) == 0);
	}
	CHECK(op_close(b) == 0);
	return 0;
}
/* Two description owners form a cycle; OFD waits must not return EDEADLK. */
static int deadlock(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR), p[2], status;
	CHECK(a >= 0 && b >= 0 && op_pipe(p) == 0);
	CHECK(set(a,F_WRLCK,0,1) == 0 && set(b,F_WRLCK,1,1) == 0);
	long children[2];
	for (int i = 0; i < 2; i++) {
		children[i] = op_fork(); CHECK(children[i] >= 0);
		if (children[i] == 0) {
			if (op_handler(handler) != 0 || op_write(p[1],"r",1) != 1) op_exit(1);
			struct flock fl = lock(F_WRLCK,i == 0 ? 1 : 0,1);
			long r = op_fcntl(i == 0 ? a : b,F_OFD_SETLKW,&fl);
			if (op_write(p[1],"d",1) != 1) op_exit(2);
			op_exit(r == -EINTR ? 0 : 3);
		}
	}
	char c;
	CHECK(op_read(p[0],&c,1) == 1 && op_read(p[0],&c,1) == 1);
	CHECK(op_ready(p[0],300) == 0);
	for (int i = 0; i < 2; i++) {
		for (int j = 0; j < 30 && op_ready(p[0],0) == 0; j++) {
			CHECK(op_kill(children[i],SIGUSR1) == 0); op_sleep();
		}
		CHECK(op_ready(p[0],3000) == 1 && op_read(p[0],&c,1) == 1);
		CHECK(op_wait(children[i],&status) == children[i] && status == 0);
	}
	CHECK(op_close(a) == 0 && op_close(b) == 0);
	return 0;
}
static int faults(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR);
	long mapped = op_map(); CHECK(a >= 0 && b >= 0 && mapped > 0);
	char *p = (char *)mapped;
	struct flock *fl = (struct flock *)p;
	*fl = lock(F_WRLCK,0,0);
	CHECK(op_protect(p,1) == 0); /* Readable input, unwritable output. */
	CHECK(op_fcntl(a,F_OFD_SETLK,fl) == 0);
	CHECK(op_fcntl(b,F_OFD_GETLK,fl) == -EFAULT);
	CHECK(set(b,F_WRLCK,0,1) == -EAGAIN);
	CHECK(op_protect(p+4096,0) == 0);
	for (int i = 0; i < 3; i++) {
		int cmd = i == 0 ? F_OFD_GETLK : i == 1 ? F_OFD_SETLK : F_OFD_SETLKW;
		CHECK(op_fcntl(a,cmd,p+4096-sizeof(*fl)+1) == -EFAULT);
		CHECK(op_fcntl(a,cmd,p+4096) == -EFAULT);
	}
	CHECK(op_unmap(p) == 0 && op_close(a) == 0);
	CHECK(set(b,F_WRLCK,0,0) == 0 && op_close(b) == 0);
	return 0;
}
static int descriptor_passing(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR), s[2];
	CHECK(a >= 0 && b >= 0 && op_pair(s) == 0);
	CHECK(set(a,F_WRLCK,0,0) == 0 && op_pass(s[0],a,0) == 0);
	CHECK(op_close(a) == 0);
	CHECK(set(b,F_WRLCK,0,0) == -EAGAIN); /* Queued rights own a reference. */
	int d = op_pass(s[1],0,1); CHECK(d >= 0);
	CHECK(query(d,0,0,F_UNLCK,0,0,0) == 0);
	CHECK(set(b,F_WRLCK,0,0) == -EAGAIN);
	CHECK(op_close(d) == 0 && set(b,F_WRLCK,0,0) == 0);
	CHECK(op_close(b) == 0 && op_close(s[0]) == 0 && op_close(s[1]) == 0);
	return 0;
}
static const char *program;
static void number(char *buf,int n)
{
	int len = 0; do { buf[len++] = '0'+n%10; n /= 10; } while (n);
	buf[len] = 0;
	for (int i = 0; i < len/2; i++) { char c = buf[i]; buf[i] = buf[len-i-1]; buf[len-i-1] = c; }
}
static int parse(const char *p) { int n = 0; while (*p) n = n*10+*p++-'0'; return n; }
static int exec_child(char **argv)
{
	int a = parse(argv[2]), b = parse(argv[3]), d = parse(argv[4]);
	struct flock fl = lock(F_WRLCK,0,0);
	CHECK(op_fcntl(a,F_OFD_GETLK,&fl) == -EBADF);
	CHECK(query(d,0,0,F_UNLCK,0,0,0) == 0);
	CHECK(set(b,F_WRLCK,0,0) == -EAGAIN);
	CHECK(op_close(d) == 0 && set(b,F_WRLCK,0,0) == 0);
	CHECK(op_close(b) == 0);
	return 0;
}
static int exec_lifetime(void)
{
	int a = op_open(O_CREAT|O_RDWR|O_TRUNC), b = op_open(O_RDWR), d = op_dup(a), p[2], status;
	CHECK(a >= 0 && b >= 0 && d >= 0 && op_pipe(p) == 0);
	CHECK(set(a,F_WRLCK,0,0) == 0 && op_fcntl(a,2,(void *)1) == 0); /* FD_CLOEXEC */
	long pid = op_fork(); CHECK(pid >= 0);
	if (pid == 0) {
		char c, astr[16], bstr[16], dstr[16];
		if (op_read(p[0],&c,1) != 1) op_exit(1);
		number(astr,a); number(bstr,b); number(dstr,d);
		char *argv[] = {(char *)program,(char *)"exec_child",astr,bstr,dstr,0};
		op_exec(program,argv); op_exit(2);
	}
	CHECK(op_close(a) == 0 && op_close(b) == 0 && op_close(d) == 0);
	CHECK(op_write(p[1],"r",1) == 1);
	CHECK(op_wait(pid,&status) == pid && status == 0);
	return 0;
}
static const struct { const char *name; int (*fn)(void); } cases[] = {
	{"ranges",ranges}, {"invalid",invalid}, {"ownership",ownership},
	{"posix",posix}, {"flock_independent",flock_independent},
	{"fork_lifetime",fork_lifetime}, {"wait_unlock",wait_unlock},
	{"wait_close",wait_close}, {"interrupted",interrupted},
	{"killed_waiter",killed_waiter}, {"churn",churn}, {"deadlock",deadlock},
	{"faults",faults}, {"descriptor_passing",descriptor_passing},
	{"exec_lifetime",exec_lifetime},
};
static int run(int argc,char **argv)
{
	int r = 111;
	program = argv[0];
	if (argc == 5 && equal(argv[1],"exec_child")) return exec_child(argv) != 0;
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
void start_c(long *sp) { op_exit(run(sp[0],(char **)(sp+1))); }
#else
int main(int argc,char **argv) { return run(argc,argv); }
#endif
