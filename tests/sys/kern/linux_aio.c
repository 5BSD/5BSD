/* SPDX-License-Identifier: BSD-2-Clause */
/* Freestanding x86_64 Linux legacy AIO ABI regression. */
typedef unsigned long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef signed short s16;
typedef long s64;
struct iocb {
	u64 data;
	u32 key, rw_flags;
	u16 opcode;
	s16 reqprio;
	u32 fd;
	u64 buf, nbytes;
	s64 offset;
	u64 reserved2;
	u32 flags, resfd;
};
struct io_event { u64 data, obj; s64 res, res2; };
struct aio_ring {
	u32 id, nr, head, tail, magic, compat, incompat, header_length;
	struct io_event events[];
};
struct timespec { s64 sec, nsec; };
struct aio_sigset { const void *mask; u64 size; };
struct iovec { void *base; u64 len; };
struct pollfd { int fd; short events, revents; };
struct linux_sigaction { u64 handler, flags, restorer, mask; };
#define IO_SETUP 206
#define IO_DESTROY 207
#define IO_GETEVENTS 208
#define IO_SUBMIT 209
#define IO_CANCEL 210
#define IO_PGETEVENTS 333
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_POLL 7
#define SYS_PREAD64 17
#define SYS_RT_SIGPROCMASK 14
#define SYS_RT_SIGACTION 13
#define SYS_CLOSE 3
#define SYS_FORK 57
#define SYS_EXIT 60
#define SYS_WAIT4 61
#define SYS_SETUID 105
#define SYS_UNLINK 87
#define SYS_MMAP 9
#define SYS_MPROTECT 10
#define SYS_MUNMAP 11
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANON 0x20
#define SYS_OPENAT 257
#define SYS_EVENTFD2 290
#define SYS_PIPE2 293
#define SYS_SOCKETPAIR 53
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_APPEND 02000
#define EPERM 1
#define EINVAL 22
#define EFAULT 14
#define EAGAIN 11
#define EINPROGRESS 115
#define ECANCELED 125
#define EBADF 9
#define EPIPE 32
#define SIGPIPE 13
#define IOCB_PREAD 0
#define IOCB_PWRITE 1
#define IOCB_FSYNC 2
#define IOCB_FDSYNC 3
#define IOCB_POLL 5
#define POLLIN 1
#define POLLOUT 4
#define POLLHUP 16
#define IOCB_PREADV 7
#define IOCB_PWRITEV 8
#define IOCB_FLAG_RESFD 1
#define IOCB_FLAG_IOPRIO 2
#define IOPRIO_CLASS_RT 1
#define IOPRIO_CLASS_BE 2
#define IOPRIO_CLASS_IDLE 3
#define IOPRIO_CLASS_INVALID 7
#define IOPRIO_PRIO(c,l) ((s16)(((c)<<13)|(l)))
#define RWF_HIPRI 1
#define RWF_DSYNC 2
#define RWF_SYNC 4
#define RWF_APPEND 16
#define RWF_NOAPPEND 32
#define RWF_NOSIGNAL 256
static long
call(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b),
	    "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return (ret);
}
static long setup(u32 n, u64 *ctx) { return call(IO_SETUP,n,(long)ctx,0,0,0,0); }
static long destroy(u64 ctx) { return call(IO_DESTROY,ctx,0,0,0,0,0); }
static long submit(u64 ctx,long n,struct iocb **p) { return call(IO_SUBMIT,ctx,n,(long)p,0,0,0); }
static long getevents(u64 ctx,long min,long max,struct io_event *ev,
    struct timespec *ts) { return call(IO_GETEVENTS,ctx,min,max,(long)ev,(long)ts,0); }
static long pgetevents(u64 ctx,long min,long max,struct io_event *ev,
    struct timespec *ts,struct aio_sigset *sig) { return call(IO_PGETEVENTS,ctx,min,max,(long)ev,(long)ts,(long)sig); }
static long __attribute__((unused)) cancel(u64 ctx,struct iocb *cb,struct io_event *ev) {
	return call(IO_CANCEL,ctx,(long)cb,(long)ev,0,0,0);
}
static void zero(void *p,u64 n) { unsigned char *q=p; while(n--) *q++=0; }
void *memset(void *p,int c,u64 n) { unsigned char *q=p; while(n--) *q++=(unsigned char)c; return p; }
static long check_event(struct io_event *ev,struct iocb *cb,s64 result) {
	return ev->data==cb->data && ev->obj==(u64)cb && ev->res==result && ev->res2==0;
}
#ifdef AIO_NOSIGNAL_ONLY
static int
aio_nosignal_child(int kind, int vecop, int suppress)
{
	char byte = 'a';
	struct iovec vec = { &byte, 1 };
	struct iocb cb, *list = &cb;
	struct io_event ev;
	u64 ctx = 0;
	int fds[2];
	long ret;
	struct linux_sigaction sa = { 0 };

	if (call(SYS_RT_SIGACTION,SIGPIPE,(long)&sa,0,8,0,0) != 0)
		return 39;
	ret = kind == 0 ? call(SYS_PIPE2,(long)fds,0,0,0,0,0) :
	    call(SYS_SOCKETPAIR,1,1,0,(long)fds,0,0);
	if (ret != 0) return 40;
	call(SYS_CLOSE,kind == 0 ? fds[0] : fds[1],0,0,0,0,0);
	if (setup(4,&ctx) != 0) return 41;
	zero(&cb,sizeof(cb));cb.opcode=vecop?IOCB_PWRITEV:IOCB_PWRITE;
	cb.fd=fds[kind == 0 ? 1 : 0];cb.buf=(u64)(vecop?(void *)&vec:(void *)&byte);
	cb.nbytes=1;cb.rw_flags=suppress?RWF_NOSIGNAL:0;
	ret=submit(ctx,1,&list);
	if(ret!=1)return 42;
	ret=getevents(ctx,1,1,&ev,0);
	if(!suppress)return 43; /* Default SIGPIPE must terminate first. */
	if(ret!=1 || !check_event(&ev,&cb,-EPIPE))return 44;
	if(destroy(ctx)!=0)return 45;
	return 0;
}
#endif
static int
test(void)
{
	const char path[]="aio-test-file";
	char out[8]={0}, in[8]="abcde";
	struct iocb cb, *list[2];
#ifdef AIO_CAPACITY_ONLY
	struct iocb jobs[512];
	int accepted;
#endif
#ifdef AIO_POLL_ONLY
	int pipefd[2], pipefd2[2], pipefd3[2];
	struct iocb poll_cb, poll_cb2;
	struct timespec wait_ts = { 5, 0 };
#endif
#if defined(AIO_POLL_ONLY) || defined(AIO_FLAGS_ONLY)
	struct pollfd epfd;
#endif
#ifdef AIO_CANCEL_ONLY
	struct iocb cancel_jobs[32], *cancel_batch[32];
	struct io_event cancel_events[32];
	unsigned char seen[32] = { 0 }, cancelled[32] = { 0 };
	struct timespec wait_ts = { 5, 0 };
	int accepted, got, j;
#endif
	struct io_event ev[2];
	volatile struct aio_ring *ring;
	struct timespec zero_ts={0,0};
	struct aio_sigset sig;
	struct iovec vec[2];
	u64 ctx=0, second=0, counter=0;
	u64 blockedmask, oldmask, nowmask;
	long fd, eventfd, ret, pid, map;
	int i, status;

	if (setup(0,&ctx)!=-EINVAL) return 1;
	if (setup(1,(u64 *)0)!=-EFAULT) return 2;
	map=call(SYS_MMAP,0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
	if (map<0) return 42;
	if (call(SYS_MPROTECT,map,4096,PROT_READ,0,0,0)!=0) return 43;
	if (setup(1,(u64 *)map)!=-EFAULT) return 44;
	if (call(SYS_MPROTECT,map,4096,PROT_READ|PROT_WRITE,0,0,0)!=0)
		return 45;
	if (call(SYS_MUNMAP,map,4096,0,0,0,0)!=0) return 46;
	ctx=1;
	if (setup(1,&ctx)!=-EINVAL || ctx!=1) return 3;
	ctx=0;
	if (setup(8,&ctx)!=0 || ctx==0) return 4;
	ring=(volatile struct aio_ring *)(unsigned long)ctx;
	if (ring->magic!=0xa10a10a1 || ring->header_length!=32 ||
	    ring->nr<8 || ring->head!=0 || ring->tail!=0) return 49;
	if (setup(8,&second)!=0 || second==0 || second==ctx) return 5;
#ifdef AIO_NOSIGNAL_ONLY
	for (int kind=0;kind<2;kind++) for(int vecop=0;vecop<2;vecop++)
	    for(int suppress=0;suppress<2;suppress++) {
		pid=call(SYS_FORK,0,0,0,0,0,0);if(pid<0)return 210;
		if(pid==0)call(SYS_EXIT,aio_nosignal_child(kind,vecop,suppress),0,0,0,0,0);
		status=0;if(call(SYS_WAIT4,pid,(long)&status,0,0,0,0)!=pid)return 211;
		if(suppress) { if(status!=0)return 212; }
		else if((status&0x7f)!=SIGPIPE)return 213;
	}
	if(destroy(ctx)!=0 || destroy(second)!=0)return 214;
	return 0;
#endif
#ifdef AIO_CONTEXT_ONLY
	pid=call(SYS_FORK,0,0,0,0,0,0);
	if (pid<0) return 56;
	if (pid==0) {
		ret=destroy(ctx);
		call(SYS_EXIT,ret==-EINVAL ? 0 : 1,0,0,0,0,0);
	}
	status=0;
	if (call(SYS_WAIT4,pid,(long)&status,0,0,0,0)!=pid || status!=0)
		return 57;
	if (destroy(ctx)!=0) return 58;
	if (destroy(ctx)!=-EINVAL) return 59;
	if (destroy(second)!=0) return 60;
	return 0;
#endif
	if (getevents(0,0,1,ev,&zero_ts)!=-EINVAL) return 6;
	if (getevents(ctx,-1,1,ev,&zero_ts)!=-EINVAL) return 7;
	if (getevents(ctx,2,1,ev,&zero_ts)!=-EINVAL) return 8;
	if (getevents(ctx,0,1,ev,&zero_ts)!=0) return 9;
#ifndef AIO_RW_ONLY
	if (pgetevents(ctx,0,1,ev,&zero_ts,0)!=0) return 10;
#endif
	if (submit(0,0,list)!=-EINVAL) return 11;
	if (submit(ctx,-1,list)!=-EINVAL) return 12;
	if (submit(ctx,0,list)!=0) return 13;
	if (submit(ctx,1,(struct iocb **)0)!=-EFAULT) return 51;
	list[0]=0;
	if (submit(ctx,1,list)!=-EFAULT) return 52;
	if (destroy(0)!=-EINVAL) return 14;
#ifdef AIO_POLL_ONLY
	if (call(SYS_PIPE2,(long)pipefd,0,0,0,0,0)!=0) return 103;
	eventfd=call(SYS_EVENTFD2,0,0,0,0,0,0);
	if (eventfd<0) return 104;
	zero(&poll_cb,sizeof(poll_cb));
	poll_cb.opcode=IOCB_POLL;
	poll_cb.fd=pipefd[0];
	poll_cb.buf=POLLIN;
	poll_cb.data=0x1a10;
	/* Poll ignores reqprio and unknown flags, even with IOPRIO present. */
	poll_cb.flags=IOCB_FLAG_RESFD|IOCB_FLAG_IOPRIO|0x80000000U;
	poll_cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,0);
	poll_cb.resfd=eventfd;
	list[0]=&poll_cb;
	if (submit(ctx,1,list)!=1) return 105;
	if (getevents(ctx,0,1,ev,&zero_ts)!=0) return 106;
	if (call(SYS_WRITE,pipefd[1],(long)in,1,0,0,0)!=1) return 107;
	epfd.fd=eventfd; epfd.events=POLLIN; epfd.revents=0;
	if (call(SYS_POLL,(long)&epfd,1,5000,0,0,0)!=1 ||
	    (epfd.revents & POLLIN)==0 || ring->head==ring->tail)
		return 163;
	ret=getevents(ctx,1,1,ev,&wait_ts);
	if (ret!=1) return 108;
	if (ev->data!=poll_cb.data || ev->obj!=(u64)&poll_cb ||
	    ev->res2!=0) return 127;
	if ((ev->res & POLLIN)==0) return 128;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=1) return 109;
	if (call(SYS_READ,pipefd[0],(long)out,1,0,0,0)!=1) return 110;
	poll_cb.data++;
	if (submit(ctx,1,list)!=1) return 111;
	if (cancel(ctx,&poll_cb,ev)!=-EINPROGRESS) return 112;
	epfd.revents=0;
	if (call(SYS_POLL,(long)&epfd,1,5000,0,0,0)!=1 ||
	    (epfd.revents & POLLIN)==0 || ring->head==ring->tail)
		return 164;
	if (getevents(ctx,1,1,ev,&wait_ts)!=1 ||
	    !check_event(ev,&poll_cb,0)) return 113;
	counter=0;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=1) return 114;
	if (getevents(ctx,0,1,ev,&zero_ts)!=0 || ring->head!=ring->tail)
		return 115;
	/* Both subscribers must observe the same readiness edge exactly once. */
	zero(&poll_cb2,sizeof(poll_cb2));
	poll_cb2.opcode=IOCB_POLL; poll_cb2.fd=pipefd[0];
	poll_cb2.buf=POLLIN; poll_cb2.data=0x1a12;
	poll_cb2.flags=IOCB_FLAG_RESFD; poll_cb2.resfd=eventfd;
	list[0]=&poll_cb; list[1]=&poll_cb2;
	if (submit(ctx,2,list)!=2) return 140;
	if (call(SYS_WRITE,pipefd[1],(long)in,1,0,0,0)!=1) return 141;
	if (getevents(ctx,2,2,ev,&wait_ts)!=2) return 142;
	if (!((ev[0].obj==(u64)&poll_cb && ev[1].obj==(u64)&poll_cb2) ||
	    (ev[0].obj==(u64)&poll_cb2 && ev[1].obj==(u64)&poll_cb)))
		return 143;
	if ((ev[0].res & POLLIN)==0 || (ev[1].res & POLLIN)==0 ||
	    ev[0].res2!=0 || ev[1].res2!=0) return 144;
	counter=0;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=2) return 145;
	if (call(SYS_READ,pipefd[0],(long)out,1,0,0,0)!=1) return 146;
	/* The request keeps the original file, even after its fd is reused. */
	if (call(SYS_PIPE2,(long)pipefd2,0,0,0,0,0)!=0) return 147;
	poll_cb.fd=pipefd2[0]; poll_cb.data=0x1a13;
	list[0]=&poll_cb;
	if (submit(ctx,1,list)!=1) return 148;
	if (call(SYS_CLOSE,pipefd2[0],0,0,0,0,0)!=0 ||
	    call(SYS_PIPE2,(long)pipefd3,0,0,0,0,0)!=0) return 149;
	if (pipefd3[0]!=pipefd2[0]) return 150;
	if (call(SYS_WRITE,pipefd3[1],(long)in,1,0,0,0)!=1 ||
	    getevents(ctx,0,1,ev,&zero_ts)!=0) return 151;
	if (call(SYS_WRITE,pipefd2[1],(long)in,1,0,0,0)!=1 ||
	    getevents(ctx,1,1,ev,&wait_ts)!=1) return 152;
	if (ev->obj!=(u64)&poll_cb || ev->data!=poll_cb.data ||
	    (ev->res & POLLIN)==0 || ev->res2!=0) return 153;
	counter=0;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=1) return 154;
	call(SYS_CLOSE,pipefd2[1],0,0,0,0,0);
	call(SYS_CLOSE,pipefd3[0],0,0,0,0,0);
	call(SYS_CLOSE,pipefd3[1],0,0,0,0,0);
	/* Writable readiness completes immediately on a pipe with space. */
	poll_cb.fd=pipefd[1]; poll_cb.buf=POLLOUT; poll_cb.data=0x1a14;
	if (submit(ctx,1,list)!=1 ||
	    getevents(ctx,1,1,ev,&wait_ts)!=1) return 155;
	if (ev->obj!=(u64)&poll_cb || ev->data!=poll_cb.data ||
	    (ev->res & POLLOUT)==0 || ev->res2!=0) return 156;
	counter=0;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=1) return 157;
	/* Closing the peer completes an armed reader with POLLHUP. */
	if (call(SYS_PIPE2,(long)pipefd2,0,0,0,0,0)!=0) return 158;
	poll_cb.fd=pipefd2[0]; poll_cb.buf=POLLIN; poll_cb.data=0x1a15;
	if (submit(ctx,1,list)!=1 ||
	    call(SYS_CLOSE,pipefd2[1],0,0,0,0,0)!=0 ||
	    getevents(ctx,1,1,ev,&wait_ts)!=1) return 159;
	if (ev->obj!=(u64)&poll_cb || ev->data!=poll_cb.data ||
	    (ev->res & POLLHUP)==0 || ev->res2!=0) return 160;
	counter=0;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 ||
	    counter!=1) return 161;
	call(SYS_CLOSE,pipefd2[0],0,0,0,0,0);
	poll_cb.fd=9999; poll_cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EBADF || poll_cb.key!=0x12345678)
		return 162;
	poll_cb.fd=pipefd[0]; poll_cb.buf=POLLIN;
	poll_cb.nbytes=1;
	if (submit(ctx,1,list)!=-EINVAL) return 116;
	poll_cb.nbytes=0; poll_cb.offset=1;
	if (submit(ctx,1,list)!=-EINVAL) return 117;
	poll_cb.offset=0; poll_cb.buf=0x10000;
	if (submit(ctx,1,list)!=-EINVAL) return 118;
	poll_cb.buf=POLLIN; poll_cb.rw_flags=RWF_DSYNC;
	if (submit(ctx,1,list)!=-EINVAL) return 119;
	/* Destroy must drain an armed poll without waiting for readiness. */
	poll_cb.rw_flags=0; poll_cb.data=0x1a16;
	if (submit(ctx,1,list)!=1 || destroy(ctx)!=0) return 165;
	if (destroy(ctx)!=-EINVAL) return 166;
	/* Process exit must release a context with an outstanding poll. */
	pid=call(SYS_FORK,0,0,0,0,0,0);
	if (pid<0) return 167;
	if (pid==0) {
		second=0;
		ret=setup(2,&second);
		if (ret==0) {
			poll_cb.flags=0;
			ret=submit(second,1,list);
		}
		call(SYS_EXIT,ret==1 ? 0 : 1,0,0,0,0,0);
	}
	status=0;
	if (call(SYS_WAIT4,pid,(long)&status,0,0,0,0)!=pid || status!=0)
		return 168;
	if (destroy(second)!=0) return 120;
	call(SYS_CLOSE,eventfd,0,0,0,0,0);
	call(SYS_CLOSE,pipefd[0],0,0,0,0,0);
	call(SYS_CLOSE,pipefd[1],0,0,0,0,0);
	return 0;
#endif
	fd=call(SYS_OPENAT,AT_FDCWD,(long)path,O_RDWR|O_CREAT|O_TRUNC,0600,0,0);
	if (fd<0) return 15;
#ifdef AIO_CANCEL_ONLY
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=9999;
	cb.buf=(u64)in; cb.nbytes=1; cb.key=0x12345678; list[0]=&cb;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 136;
	cb.fd=fd; cb.reserved2=1;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0x12345678) return 137;
	cb.reserved2=0; cb.flags=IOCB_FLAG_RESFD; cb.resfd=9999;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 138;
	cb.flags=0; cb.opcode=0xffff;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 139;
	if (cancel(ctx,(struct iocb *)0,ev)!=-EFAULT) return 121;
	zero(&cb,sizeof(cb)); cb.key=1;
	if (cancel(ctx,&cb,ev)!=-EINVAL) return 122;
	map=call(SYS_MMAP,0,4096,PROT_READ|PROT_WRITE,
	    MAP_PRIVATE|MAP_ANON,-1,0);
	if (map<0) return 123;
	zero((void *)map,sizeof(struct iocb));
	((struct iocb *)map)->opcode=IOCB_PWRITE;
	((struct iocb *)map)->fd=fd;
	((struct iocb *)map)->buf=(u64)in;
	((struct iocb *)map)->nbytes=1;
	list[0]=(struct iocb *)map;
	if (call(SYS_MPROTECT,map,4096,PROT_READ,0,0,0)!=0 ||
	    submit(ctx,1,list)!=-EFAULT) return 124;
	if (call(SYS_MUNMAP,map,4096,0,0,0,0)!=0) return 125;
	for (i=0; i<32; i++) {
		zero(&cancel_jobs[i],sizeof(cancel_jobs[i]));
		cancel_jobs[i].opcode=IOCB_PWRITE;
		cancel_jobs[i].fd=fd;
		cancel_jobs[i].buf=(u64)in;
		cancel_jobs[i].nbytes=1;
		cancel_jobs[i].offset=i;
		cancel_jobs[i].data=0x5000+i;
		cancel_jobs[i].key=0x12345678;
		cancel_batch[i]=&cancel_jobs[i];
	}
	accepted=submit(ctx,32,cancel_batch);
	if (accepted<=0 || accepted>32) return 97;
	for (i=0; i<accepted; i++) {
		if (cancel_jobs[i].key!=0) return 126;
		ret=cancel(ctx,cancel_batch[i],ev);
		if (ret!=-EINPROGRESS && ret!=-EAGAIN && ret!=-EINVAL)
			return 98;
		cancelled[i]=(ret==-EINPROGRESS);
	}
	got=0;
	while (got<accepted) {
		ret=getevents(ctx,1,accepted-got,cancel_events+got,&wait_ts);
		if (ret<=0) return 99;
		got+=ret;
	}
	for (i=0; i<got; i++) {
		for (j=0; j<accepted; j++)
			if (cancel_events[i].obj==(u64)cancel_batch[j]) break;
		if (j==accepted) return 130;
		if (seen[j]++) return 131;
		if (cancel_events[i].data!=cancel_jobs[j].data) return 132;
		if (cancel_events[i].res2!=0) return 133;
		if (cancel_events[i].res!=1 &&
		    cancel_events[i].res!=-ECANCELED) {
			const char hex[]="0123456789abcdef";
			char msg[]="AIO_RES 0000000000000000\n";
			for (int k=0; k<16; k++)
				msg[8+k]=hex[((u64)cancel_events[i].res >>
				    ((15-k)*4)) & 15];
			call(SYS_WRITE,1,(long)msg,25,0,0,0);
			return 134;
		}
		if (cancelled[j] && cancel_events[i].res!=-ECANCELED)
			return 135;
	}
	if (getevents(ctx,0,1,ev,&zero_ts)!=0 || ring->head!=ring->tail)
		return 101;
	if (destroy(ctx)!=0 || destroy(second)!=0) return 102;
	call(SYS_CLOSE,fd,0,0,0,0,0);
	call(SYS_UNLINK,(long)path,0,0,0,0,0);
	return 0;
#endif
#ifdef AIO_FLAGS_ONLY
	if (call(SYS_WRITE,fd,(long)in,5,0,0,0)!=5) return 76;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=fd;
	cb.buf=(u64)in; cb.nbytes=1; cb.offset=0; list[0]=&cb;
	cb.rw_flags=RWF_APPEND;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 77;
	if (call(SYS_PREAD64,fd,(long)out,1,5,0,0)!=1 || out[0]!='a')
		return 78;
	cb.rw_flags=RWF_DSYNC;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 79;
	cb.rw_flags=RWF_SYNC;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 80;
	cb.rw_flags=0x80000000U;
	if (submit(ctx,1,list)!=-95) return 81; /* EOPNOTSUPP */
	cb.rw_flags=RWF_APPEND|RWF_NOAPPEND;
	if (submit(ctx,1,list)!=-EINVAL) return 87;
	cb.opcode=IOCB_PREAD; cb.rw_flags=RWF_DSYNC; cb.buf=(u64)out;
	if (submit(ctx,1,list)!=1) return 88;
	if (getevents(ctx,1,1,ev,0)!=1) return 89;
	if (!check_event(ev,&cb,1)) return 90;
	cb.rw_flags=RWF_SYNC;
	if (submit(ctx,1,list)!=1) return 91;
	if (getevents(ctx,1,1,ev,0)!=1) return 92;
	if (!check_event(ev,&cb,1)) return 93;
	cb.rw_flags=RWF_APPEND;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 94;
	cb.rw_flags=RWF_NOAPPEND;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 95;
	cb.rw_flags=RWF_HIPRI;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 96;
	/* aio_reqprio is ignored unless IOCB_FLAG_IOPRIO is present. */
	cb.rw_flags=0; cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,7);
	cb.flags=0; cb.key=0x12345678;
	if (submit(ctx,1,list)!=1 || cb.key!=0 ||
	    getevents(ctx,1,1,ev,0)!=1 || !check_event(ev,&cb,1)) return 170;
	/* Valid BE and IDLE priorities are advisory to the native backend. */
	cb.flags=IOCB_FLAG_IOPRIO;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_BE,4);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 171;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_IDLE,7);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 172;
	/* NONE with a level and invalid classes fail after aio_key publication. */
	cb.reqprio=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 173;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,0); cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 174;
	/* Unknown aio_flags are forward-compatible and do not enable reqprio. */
	cb.flags=0x80000000U; cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,0);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 175;
	cb.flags=0x80000000U|IOCB_FLAG_IOPRIO;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_BE,0);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 176;
	/* Vectored I/O shares the same priority validation. */
	vec[0].base=out; vec[0].len=1; cb.opcode=IOCB_PREADV;
	cb.buf=(u64)vec; cb.nbytes=1; cb.flags=IOCB_FLAG_IOPRIO;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_BE,3);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 177;
	vec[0].base=in; cb.opcode=IOCB_PWRITEV; cb.offset=1;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_IDLE,1);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 185;
	/* A privileged process may request the real-time class. */
	cb.opcode=IOCB_PREAD; cb.buf=(u64)out; cb.nbytes=1; cb.offset=0;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_RT,7);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 186;
	/* Sync operations ignore reqprio and unknown aio_flags. */
	cb.opcode=IOCB_FSYNC; cb.buf=0; cb.nbytes=0; cb.offset=0;
	cb.flags=IOCB_FLAG_IOPRIO|0x80000000U;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,0);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,0)) return 178;
	cb.opcode=IOCB_FDSYNC;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,0)) return 189;
	/* Linux requires every operation-specific sync field to be zero. */
	cb.opcode=IOCB_FSYNC; cb.flags=0; cb.reqprio=0; cb.buf=1;
	cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 190;
	cb.buf=0; cb.offset=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 191;
	cb.offset=0; cb.nbytes=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 192;
	cb.nbytes=0; cb.rw_flags=RWF_SYNC; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 193;
	cb.opcode=IOCB_FDSYNC; cb.rw_flags=0; cb.buf=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 194;
	cb.buf=0; cb.offset=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 195;
	cb.offset=0; cb.nbytes=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 196;
	cb.nbytes=0; cb.rw_flags=RWF_DSYNC; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 197;
	/* File and eventfd lookup precede operation validation and key writes. */
	cb.opcode=IOCB_PREAD; cb.buf=(u64)out; cb.nbytes=1; cb.offset=0;
	cb.rw_flags=0; cb.flags=IOCB_FLAG_IOPRIO; cb.fd=9999;
	cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 179;
	cb.fd=fd; cb.flags=IOCB_FLAG_IOPRIO|IOCB_FLAG_RESFD; cb.resfd=9999;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 180;
	cb.opcode=IOCB_FSYNC; cb.flags=0; cb.buf=1; cb.resfd=0;
	cb.fd=9999; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 198;
	cb.fd=fd; cb.flags=IOCB_FLAG_RESFD; cb.resfd=9999;
	if (submit(ctx,1,list)!=-EBADF || cb.key!=0x12345678) return 199;
	/* A valid eventfd is signalled once for an IOPRIO completion. */
	eventfd=call(SYS_EVENTFD2,0,0,0,0,0,0);
	if (eventfd<0) return 181;
	cb.fd=fd; cb.opcode=IOCB_FSYNC; cb.flags=IOCB_FLAG_RESFD|0x80000000U;
	cb.resfd=(u32)eventfd; cb.buf=1; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 200;
	epfd.fd=(int)eventfd; epfd.events=POLLIN; epfd.revents=0;
	if (call(SYS_POLL,(long)&epfd,1,0,0,0,0)!=0) return 201;
	cb.fd=eventfd; cb.flags=0x80000000U; cb.buf=0; cb.key=0x12345678;
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 202;
	cb.fd=fd; cb.opcode=IOCB_PREAD; cb.buf=(u64)out; cb.nbytes=1;
	cb.flags=IOCB_FLAG_IOPRIO|IOCB_FLAG_RESFD;
	cb.key=0x12345678; cb.resfd=(u32)eventfd;
	cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_INVALID,0);
	if (submit(ctx,1,list)!=-EINVAL || cb.key!=0) return 187;
	epfd.fd=(int)eventfd; epfd.events=POLLIN; epfd.revents=0;
	if (call(SYS_POLL,(long)&epfd,1,0,0,0,0)!=0) return 188;
	cb.resfd=(u32)eventfd; cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_BE,2);
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1) ||
	    call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 || counter!=1)
		return 182;
	call(SYS_CLOSE,eventfd,0,0,0,0,0);
	/* An unprivileged process cannot request the real-time class. */
	pid=call(SYS_FORK,0,0,0,0,0,0);
	if (pid<0) return 183;
	if (pid==0) {
		u64 childctx=0;
		ret=call(SYS_SETUID,65534,0,0,0,0,0);
		if (ret==0) ret=setup(2,&childctx);
		zero(&cb,sizeof(cb)); cb.opcode=IOCB_PREAD; cb.fd=fd;
		cb.buf=(u64)out; cb.nbytes=1; cb.flags=IOCB_FLAG_IOPRIO;
		cb.reqprio=IOPRIO_PRIO(IOPRIO_CLASS_RT,0); list[0]=&cb;
		if (ret==0) ret=submit(childctx,1,list);
		if (childctx!=0) (void)destroy(childctx);
		call(SYS_EXIT,ret==-EPERM ? 0 : 1,0,0,0,0,0);
	}
	status=0;
	if (call(SYS_WAIT4,pid,(long)&status,0,0,0,0)!=pid || status!=0)
		return 184;
	cb.opcode=IOCB_PWRITE; cb.flags=0; cb.reqprio=0; cb.resfd=0;
	if (call(SYS_CLOSE,fd,0,0,0,0,0)!=0) return 82;
	fd=call(SYS_OPENAT,AT_FDCWD,(long)path,O_RDWR|O_APPEND,0,0,0);
	if (fd<0) return 83;
	cb.fd=fd; cb.rw_flags=RWF_NOAPPEND; cb.buf=(u64)"z";
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,1)) return 84;
	if (call(SYS_PREAD64,fd,(long)out,1,0,0,0)!=1 || out[0]!='z')
		return 85;
	if (destroy(ctx)!=0 || destroy(second)!=0) return 86;
	call(SYS_CLOSE,fd,0,0,0,0,0);
	call(SYS_UNLINK,(long)path,0,0,0,0,0);
	return 0;
#endif
#ifdef AIO_CAPACITY_ONLY
	if (ring->nr > 512) return 62;
	accepted=0;
	for (i=0; i<512; i++) {
		zero(&jobs[i],sizeof(jobs[i]));
		jobs[i].opcode=IOCB_PWRITE; jobs[i].fd=fd;
		jobs[i].buf=(u64)in; jobs[i].nbytes=1; jobs[i].offset=i;
		list[0]=&jobs[i];
		ret=submit(ctx,1,list);
		if (ret==-11) break;
		if (ret!=1) return 63;
		accepted++;
	}
	if (accepted==0 || i==512 || accepted>=(int)ring->nr) return 64;
	for (i=0; i<accepted; i++)
		if (getevents(ctx,1,1,ev,0)!=1) return 65;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=fd;
	cb.buf=(u64)in; cb.nbytes=1; list[0]=&cb;
	if (submit(ctx,1,list)!=1) return 66;
	for (i=0; ring->head==ring->tail && i<10000000; i++)
		__asm__ volatile("pause");
	if (ring->head==ring->tail) return 67;
	ring->head=ring->tail;
	if (submit(ctx,1,list)!=1) return 68;
	if (getevents(ctx,1,1,ev,0)!=1) return 69;
	if (destroy(ctx)!=0 || destroy(second)!=0) return 70;
	call(SYS_CLOSE,fd,0,0,0,0,0);
	call(SYS_UNLINK,(long)path,0,0,0,0,0);
	return 0;
#endif
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=fd;
	cb.buf=(u64)in; cb.nbytes=5; cb.data=0x12345678;
	list[0]=&cb;
	if (submit(ctx,1,list)!=1) return 16;
	if (getevents(ctx,1,1,ev,0)!=1 || !check_event(ev,&cb,5)) return 17;
	if (ring->head!=ring->tail) return 50;
#ifndef AIO_RW_ONLY
	if (cancel(ctx,&cb,ev)!=-EINVAL) return 18;
#endif
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PREAD; cb.fd=fd;
	cb.buf=(u64)out; cb.nbytes=5; cb.data=0x87654321;
	if (submit(ctx,1,list)!=1) return 19;
	if (getevents(ctx,1,1,ev,0)!=1 || !check_event(ev,&cb,5)) return 20;
	for(i=0;i<5;i++) if(out[i]!=in[i]) return 21;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_FSYNC; cb.fd=fd;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,0)) return 22;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_FDSYNC; cb.fd=fd;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,0)) return 23;
	vec[0].base=in; vec[0].len=2; vec[1].base=in+2; vec[1].len=3;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITEV; cb.fd=fd;
	cb.buf=(u64)vec; cb.nbytes=2; cb.offset=5;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,5)) return 24;
	zero(out,sizeof(out)); vec[0].base=out; vec[1].base=out+2;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PREADV; cb.fd=fd;
	cb.buf=(u64)vec; cb.nbytes=2; cb.offset=5;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1 ||
	    !check_event(ev,&cb,5)) return 25;
	for(i=0;i<5;i++) if(out[i]!=in[i]) return 26;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=fd;
	cb.buf=(u64)in; cb.nbytes=1; cb.reserved2=1;
	if (submit(ctx,1,list)!=-EINVAL) return 27;
	cb.reserved2=0; cb.fd=9999;
	if (submit(ctx,1,list)!=-EBADF) return 28;
	cb.fd=fd; cb.opcode=0xffff;
	if (submit(ctx,1,list)!=-EINVAL) return 29;
	cb.opcode=IOCB_PWRITE; cb.buf=(u64)in; cb.nbytes=1;
	list[0]=&cb; list[1]=(struct iocb *)0;
	if (submit(ctx,2,list)!=1) return 30;
	if (getevents(ctx,1,1,ev,0)!=1 || !check_event(ev,&cb,1)) return 31;
	eventfd=call(SYS_EVENTFD2,0,0,0,0,0,0);
	if (eventfd<0) return 32;
	zero(&cb,sizeof(cb)); cb.opcode=IOCB_PWRITE; cb.fd=fd;
	cb.buf=(u64)in; cb.nbytes=1; cb.flags=IOCB_FLAG_RESFD; cb.resfd=eventfd;
	if (submit(ctx,1,list)!=1 || getevents(ctx,1,1,ev,0)!=1) return 33;
	if (call(SYS_READ,eventfd,(long)&counter,8,0,0,0)!=8 || counter!=1) return 34;
	call(SYS_CLOSE,eventfd,0,0,0,0,0);
#ifdef AIO_RW_ONLY
	if (destroy(ctx)!=0 || destroy(second)!=0) return 61;
	call(SYS_CLOSE,fd,0,0,0,0,0);
	call(SYS_UNLINK,(long)path,0,0,0,0,0);
	return 0;
#endif
	sig.mask=0; sig.size=0;
	if (pgetevents(ctx,0,1,ev,&zero_ts,&sig)!=0) return 35;
	sig.mask=&counter; sig.size=1;
	if (pgetevents(ctx,0,1,ev,&zero_ts,&sig)!=-EINVAL) return 36;
	sig.mask=0; sig.size=0;
	if (pgetevents(ctx,1,1,ev,&zero_ts,&sig)!=0) return 37;
	blockedmask=(u64)1 << 9; /* SIGUSR1 */
	if (call(SYS_RT_SIGPROCMASK,2,(long)&blockedmask,(long)&oldmask,
	    8,0,0)!=0) return 71;
	counter=0;
	sig.mask=&counter; sig.size=8;
	if (pgetevents(ctx,0,1,ev,&zero_ts,&sig)!=0) return 72;
	if (call(SYS_RT_SIGPROCMASK,2,0,(long)&nowmask,8,0,0)!=0 ||
	    nowmask!=blockedmask) return 73;
	if (call(SYS_RT_SIGPROCMASK,2,(long)&oldmask,0,8,0,0)!=0)
		return 74;
	sig.mask=(const void *)1;
	if (pgetevents(ctx,0,1,ev,&zero_ts,&sig)!=-EFAULT) return 75;
	pid=call(SYS_FORK,0,0,0,0,0,0);
	if (pid<0) return 47;
	if (pid==0) {
		ret=getevents(ctx,0,1,ev,&zero_ts);
		call(SYS_EXIT,ret==-EINVAL ? 0 : 1,0,0,0,0,0);
	}
	status=0;
	if (call(SYS_WAIT4,pid,(long)&status,0,0,0,0)!=pid || status!=0)
		return 48;
	if (destroy(ctx)!=0) return 38;
	if (destroy(ctx)!=-EINVAL) return 39;
	if (getevents(ctx,0,1,ev,&zero_ts)!=-EINVAL) return 40;
	if (destroy(second)!=0) return 41;
	call(SYS_CLOSE,fd,0,0,0,0,0);
	call(SYS_UNLINK,(long)path,0,0,0,0,0);
	ret=0;
	return (int)ret;
}
__attribute__((force_align_arg_pointer)) void _start(void) {
	call(SYS_EXIT,test(),0,0,0,0,0);
	__builtin_unreachable();
}
