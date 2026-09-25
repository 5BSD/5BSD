/* SPDX-License-Identifier: BSD-2-Clause */
/* Native/LP64 Linux ring-layout and request-validation contract tests. */
#ifdef LINUX_ABI
#if defined(__x86_64__)
#define NR(a,b) (a)
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
 register long r10 __asm__("r10")=d, r8 __asm__("r8")=e, r9 __asm__("r9")=f;
 long r;
 __asm__ volatile("syscall":"=a"(r):"a"(n),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
 return r;
}
__asm__(".text\n.globl _start\n_start:\nmov %rsp,%rdi\nand $-16,%rsp\ncall start_c\nud2\n");
#else
#define NR(a,b) (b)
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
 register long x8 __asm__("x8")=n, x0 __asm__("x0")=a, x1 __asm__("x1")=b;
 register long x2 __asm__("x2")=c, x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
 __asm__ volatile("svc #0":"+r"(x0):"r"(x8),"r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5):"memory","cc");
 return x0;
}
__asm__(".text\n.globl _start\n_start:\nmov x0,sp\nbl start_c\nbrk #0\n");
#endif
#define N_KILL NR(62,129)
#define N_SETUID NR(105,146)
#define N_REGISTER 427
#define N_MPROTECT NR(10,226)
#define ANON_FLAGS (2|0x20)
#define N_SETUP 425
#define N_ENTER 426
#define N_CLOSE NR(3,57)
#define N_MMAP NR(9,222)
#define N_MUNMAP NR(11,215)
#define N_OPENAT NR(257,56)
#define N_READ NR(0,63)
#define N_WRITE NR(1,64)
#define N_DUP NR(32,23)
#define N_WAIT NR(61,260)
#define N_EXIT NR(231,94)
#define N_YIELD NR(24,124)
#define N_EVENTFD2 NR(290,19)
#define N_PIPE2 NR(293,59)
#define N_PRCTL NR(157,167)
#define SIGPIPE_VALUE 13
#define OPENFLAGS (2|0100|0200)
#define CANCELED 125
#define BADMAP_ERROR 12
#define NOTSUP 95
#define OVERFLOW 75
#define AGAIN 11
#define NO_BUFS 105
#define MSGSIZE 90
#define ACCESS 13
static long fork_child(void) { return sc(NR(57,220),NR(0,17),0,0,0,0,0); }
static long make_eventfd(void) { return sc(N_EVENTFD2,0,0x800,0,0,0,0); }
#else
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
static long sc(long n,long a,long b,long c,long d,long e,long f)
{
 long r=__syscall(n,a,b,c,d,e,f);
 return r == -1 ? -errno : r;
}
#define N_KILL SYS_kill
#define N_SETUID SYS_setuid
#define N_REGISTER 638
#define N_MPROTECT SYS_mprotect
#define ANON_FLAGS (2|0x1000)
#define N_SETUP 636
#define N_ENTER 637
#define N_CLOSE SYS_close
#define N_MMAP SYS_mmap
#define N_MUNMAP SYS_munmap
#define N_OPENAT SYS_openat
#define N_READ SYS_read
#define N_WRITE SYS_write
#define N_DUP SYS_dup
#define N_WAIT SYS_wait4
#define N_EXIT SYS_exit
#define N_YIELD SYS_sched_yield
#define N_PIPE2 SYS_pipe2
#define SIGPIPE_VALUE SIGPIPE
#define OPENFLAGS (O_RDWR|O_CREAT|O_EXCL)
#define CANCELED ECANCELED
#define BADMAP_ERROR EINVAL
#define NOTSUP EOPNOTSUPP
#define OVERFLOW EOVERFLOW
#define AGAIN EAGAIN
#define NO_BUFS ENOBUFS
#define MSGSIZE EMSGSIZE
#define ACCESS EACCES
static long fork_child(void) { return sc(SYS_fork,0,0,0,0,0,0); }
static long make_eventfd(void) { return eventfd(0,EFD_NONBLOCK); }
#endif
#define CALL(n,a,b,c) sc(n,(long)(a),(long)(b),(long)(c),0,0,0)
#define CHECK(x) do { if (!(x)) return __LINE__; } while (0)
#define SSQPOLL (1U<<1)
#define SSQ_AFF (1U<<2)
#define SQ_WAKEUP (1U<<1)
#define SQ_WAIT (1U<<2)
#define SNOMMAP (1U<<14)
#define NOARRAY (1U<<16)
#define RECVSEND_BUNDLE (1U<<14)
#define RSRC_TAGS (1U<<10)
#define NO_IOWAIT_FEAT (1U<<17)
#define SCOOP (1U<<8)
#define STASKRUN (1U<<9)
#define SSQE128 (1U<<10)
#define SSQEMIXED (1U<<19)
#define SATTACHWQ (1U<<5)
#define SCQE32 (1U<<11)
#define SCQEMIXED (1U<<18)
#define CQE_SKIP (1U<<5)
#define CQE_F32 (1U<<15)
#define SDEFER (1U<<13)
#define SREWIND (1U<<20)
#define SQ_TASKRUN (1U<<2)
typedef unsigned int u32;
typedef unsigned long u64;
struct offsets { u32 head,tail,mask,entries,field4,field5,field6,resv; u64 addr; };
struct params { u32 sq,cq,flags,cpu,idle,features,wq,resv[3]; struct offsets so,co; };
struct sqe { unsigned char op,flags; unsigned short ioprio; int fd; u64 off,addr; u32 len,misc; u64 ud; unsigned short buf,personality; int fd2; u64 addr3,pad; };
struct cqe { u64 ud; int res; u32 flags; };
struct sbpf_insn { unsigned short code; unsigned char jt,jf; u32 k; };
struct sbpf_filter { u32 opcode,flags,filter_len; unsigned char pdu_size,resv[3]; u64 filter_ptr,resv2[5]; };
struct sbpf_reg { unsigned short cmd_type,cmd_flags; u32 resv; struct sbpf_filter filter; };
struct lsockaddr_in { unsigned short family,port; u32 addr; unsigned char zero[8]; };
struct lopen_how { u64 flags,mode,resolve; };
struct snapi { u32 busy_poll_to; unsigned char prefer_busy_poll,opcode,pad[2]; u32 op_param,resv; };
#define SBPF_DENY_REST 1U
#define SBPF_SZ_STRICT 2U
#define SBPF_LD_W_ABS 0x20
#define SBPF_LD_H_ABS 0x28
#define SBPF_ALU_AND_K 0x54
#define SBPF_ALU_DIV_K 0x34
#define SBPF_JMP_JEQ_K 0x15
#define SBPF_RET_K 0x06
struct viov { void *base; u64 len; };
_Static_assert(sizeof(struct params)==120,"params ABI");
_Static_assert(sizeof(struct sqe)==64,"SQE ABI");
_Static_assert(sizeof(struct sbpf_filter)==64,"BPF filter ABI");
_Static_assert(sizeof(struct sbpf_reg)==72,"BPF register ABI");
struct ring { long fd; struct params p; char *mem; struct sqe *sqes; u32 *array,*st,*sh,*sf,*ct,*ch,*cf; struct cqe *cqes; u32 si,ci; u64 rlen,slen; };
static void zero(void *v,u64 n) { unsigned char *p=v; while(n--) *p++=0; }
static int equal(const char *a,const char *b) { while(*a && *a==*b) {a++;b++;} return *a==*b; }
static void put(const char *p) { u64 n=0; while(p[n]) n++; (void)CALL(N_WRITE,1,p,n); }
static void putnum(long value)
{
 char b[24];int n=0;u64 v;
 if(value<0){put("-");v=(u64)(-(value+1))+1;}else v=value;
 do{b[n++]=(char)('0'+v%10);v/=10;}while(v);
 while(n)CALL(N_WRITE,1,&b[--n],1);
}
static int init_ex_wq_idle(struct ring *r,u32 flags,u32 entries,u32 cpu,u32 wqfd,u32 idle)
{
 long m;
 zero(r,sizeof(*r)); r->p.flags=flags;r->p.cpu=cpu;r->p.wq=wqfd;r->p.idle=idle; r->p.cq=entries*4;
 r->fd=CALL(N_SETUP,entries,&r->p,0); CHECK(r->fd>=0);
#ifdef LINUX_ABI
 CHECK((r->p.features & RECVSEND_BUNDLE) != 0);
#else
 CHECK((r->p.features & RECVSEND_BUNDLE) == 0);
#endif
 CHECK((r->p.features & RSRC_TAGS) != 0);
 CHECK((r->p.features & NO_IOWAIT_FEAT) != 0);
 CHECK(r->p.sq>=entries && (r->p.sq & (r->p.sq-1))==0);
 CHECK((flags & NOARRAY) ? r->p.so.field6==0 : r->p.so.field6!=0);
 r->rlen=r->p.co.field5+(u64)r->p.cq*sizeof(struct cqe)*((flags&SCQE32)?2:1);
 if (!(flags & NOARRAY) && r->rlen<r->p.so.field6+(u64)r->p.sq*4) r->rlen=r->p.so.field6+(u64)r->p.sq*4;
 r->slen=(u64)r->p.sq*sizeof(struct sqe)*((flags&SSQE128)?2:1);
 m=sc(N_MMAP,0,r->rlen,3,1,r->fd,0); CHECK(m>=0); r->mem=(char *)m;
 m=sc(N_MMAP,0,r->slen,3,1,r->fd,0x10000000); CHECK(m>=0); r->sqes=(struct sqe *)m;
 r->sh=(u32 *)(r->mem+r->p.so.head); r->sf=(u32 *)(r->mem+r->p.so.field4); r->st=(u32 *)(r->mem+r->p.so.tail);
 r->ct=(u32 *)(r->mem+r->p.co.tail); r->ch=(u32 *)(r->mem+r->p.co.head);
 r->cf=(u32 *)(r->mem+r->p.co.field6);
 r->cqes=(struct cqe *)(r->mem+r->p.co.field5);
 if (!(flags & NOARRAY)) r->array=(u32 *)(r->mem+r->p.so.field6);
 return 0;
}
static int init_ex_wq(struct ring *r,u32 flags,u32 entries,u32 cpu,u32 wqfd)
{
 return init_ex_wq_idle(r,flags,entries,cpu,wqfd,0);
}
static int init_ex(struct ring *r,u32 flags,u32 entries,u32 cpu)
{
 return init_ex_wq(r,flags,entries,cpu,0);
}
static int init(struct ring *r,u32 flags,u32 entries)
{
 return init_ex(r,flags,entries,0);
}
static void queue(struct ring *r,struct sqe q,int reverse)
{
 u32 slot=r->si & (r->p.sq-1);
 if (reverse) slot=r->p.sq-1-slot;
 r->sqes[slot*((r->p.flags&SSQE128)?2:1)]=q;
 if(r->array) r->array[r->si & (r->p.sq-1)]=slot;
 __atomic_store_n(r->st,++r->si,__ATOMIC_RELEASE);
}
static int flush(struct ring *r,u32 n) { CHECK(sc(N_ENTER,r->fd,n,n,1,0,0)==n); return 0; }
static int reap(struct ring *r,u64 ud,int result)
{
 struct cqe c;
 CHECK(__atomic_load_n(r->ct,__ATOMIC_ACQUIRE)>r->ci);
 c=r->cqes[(r->ci & (r->p.cq-1))*((r->p.flags&SCQE32)?2:1)]; CHECK(c.ud==ud && c.res==result && c.flags==0);
 __atomic_store_n(r->ch,++r->ci,__ATOMIC_RELEASE); return 0;
}
static int finish(struct ring *r)
{
 CHECK(CALL(N_CLOSE,r->fd,0,0)==0);
 CHECK(CALL(N_MUNMAP,r->mem,r->rlen,0)==0);
 CHECK(CALL(N_MUNMAP,r->sqes,r->slen,0)==0); return 0;
}
static int layout(void)
{
 struct ring r; struct sqe q; u32 flags[]={NOARRAY,NOARRAY|8,NOARRAY|16,NOARRAY|24};
 for(u32 i=0;i<4;i++) { CHECK(init(&r,flags[i],3)==0); zero(&q,sizeof(q)); q.ud=123;
  queue(&r,q,0); CHECK(flush(&r,1)==0 && reap(&r,123,0)==0); CHECK(*r.sh==1); CHECK(finish(&r)==0); }
 return 0;
}
static int wrap(void)
{
 struct ring r; struct sqe q; CHECK(init(&r,NOARRAY,8)==0);
 for(u32 n=0;n<256;n++) { for(u32 i=0;i<8;i++) {zero(&q,sizeof(q));q.ud=n*8+i;queue(&r,q,0);}
  CHECK(flush(&r,8)==0); for(u32 i=0;i<8;i++) CHECK(reap(&r,n*8+i,0)==0); }
 CHECK(*r.sh==2048); return finish(&r);
}
static int legacy(void)
{
 struct ring r; struct sqe q; CHECK(init(&r,0,8)==0);
 for(u32 i=0;i<8;i++) {zero(&q,sizeof(q));q.ud=i;queue(&r,q,1);}
 CHECK(flush(&r,8)==0); for(u32 i=0;i<8;i++) CHECK(reap(&r,i,0)==0);
 return finish(&r);
}
static int invalid(void)
{
 struct params p; struct ring r;
 zero(&p,sizeof(p));p.flags=NOARRAY;CHECK(CALL(N_SETUP,0,&p,0)==-22);
 p.flags=NOARRAY|0x80000000U;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 p.flags=NOARRAY;p.resv[2]=1;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 p.resv[2]=0;p.flags=NOARRAY|8;p.cq=1;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(CALL(N_SETUP,8,0,0)==-14);
 CHECK(init(&r,NOARRAY,8)==0);
 CHECK(sc(N_MMAP,0,4096,3,1,r.fd,0x18000000)==-BADMAP_ERROR);
#ifndef LINUX_ABI
 /* Native mappings reject oversized regions; Linux can leave a SIGBUS tail. */
 CHECK(sc(N_MMAP,0,1UL<<30,3,1,r.fd,0)==-22);
#endif
 return finish(&r);
}
static int io(void)
{
 struct ring r;struct sqe q;char b[4];long fd;
 CHECK(init(&r,NOARRAY,8)==0);fd=sc(N_OPENAT,-100,(long)"data",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 zero(&q,sizeof(q));q.op=23;q.fd=fd;q.addr=(u64)"safe";q.len=4;q.ud=1;
 queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,1,4)==0);
 q.op=22;q.addr=(u64)b;q.ud=2;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,2,4)==0);
 CHECK(b[0]=='s' && b[1]=='a' && b[2]=='f' && b[3]=='e');
 q.addr=0;q.ud=3;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,3,-14)==0);
 q.fd=-1;q.addr=(u64)b;q.ud=4;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,4,-9)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
/* ZFS deliberately has no VOP_ALLOCATE reservation contract. */
static int allocation_zfs(void)
{
 struct ring r; struct sqe q; char b[5]; long fd;
 CHECK(init(&r,NOARRAY,8)==0);
 fd=sc(N_OPENAT,-100,(long)"allocation",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 CHECK(CALL(N_WRITE,fd,"safe",4)==4);
 zero(&q,sizeof(q));q.op=17;q.fd=fd;q.addr=8192;q.ud=1;
 queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,1,-NOTSUP)==0);
 q.op=22;q.addr=(u64)b;q.len=5;q.ud=2;
 queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,2,4)==0);
 CHECK(b[0]=='s' && b[1]=='a' && b[2]=='f' && b[3]=='e');
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
static int validation(void)
{
 struct ring r;struct sqe q;long fd;char b;
 /* Check before issuing writes, before worker offload, and inside chains. */
 CHECK(init(&r,0,8)==0);fd=sc(N_OPENAT,-100,(long)"unchanged",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(u32 flags=0x80;flags<=0x90;flags+=0x10) {
  zero(&q,sizeof(q));q.op=23;q.flags=flags;q.fd=fd;q.addr=(u64)"bad";q.len=3;q.ud=flags;
  queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,flags,-22)==0);
 }
 CHECK(CALL(N_READ,fd,&b,1)==0);
 zero(&q,sizeof(q));q.personality=1;q.ud=3;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,3,-22)==0);
 zero(&q,sizeof(q));q.flags=0x80|4;q.ud=4;queue(&r,q,0);
 q.flags=0;q.ud=5;queue(&r,q,0);CHECK(flush(&r,2)==0);
 CHECK(reap(&r,4,-22)==0 && reap(&r,5,-CANCELED)==0);
 q.ud=6;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,6,0)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
static int lifetime(void)
{
 struct ring r;struct sqe q;long fd;
 for(u32 i=0;i<64;i++) {
  CHECK(init(&r,NOARRAY,8)==0);fd=CALL(N_DUP,r.fd,0,0);CHECK(fd>=0);CHECK(CALL(N_CLOSE,r.fd,0,0)==0);r.fd=fd;
  zero(&q,sizeof(q));q.ud=i;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,i,0)==0);CHECK(finish(&r)==0);
 }
 return 0;
}
/* A separate producer reuses slots as soon as the kernel releases them. */
static int concurrent(void)
{
 struct ring r; struct sqe q; long pid, n; int status=0;
 for (u32 mode=0;mode<2;mode++) {
  CHECK(init(&r,mode ? NOARRAY : 0,8)==0);
  pid=fork_child();CHECK(pid>=0);
  if(pid==0) {
   for(u32 i=0;i<4096;i++) {
    while(i-__atomic_load_n(r.sh,__ATOMIC_ACQUIRE)>=r.p.sq)
     CALL(N_YIELD,0,0,0);
    zero(&q,sizeof(q));q.ud=i;
    queue(&r,q,0);
   }
   CALL(N_EXIT,0,0,0);
  }
  while(r.ci<4096) {
   n=sc(N_ENTER,r.fd,8,0,0,0,0);CHECK(n>=0 && n<=8);
   while(__atomic_load_n(r.ct,__ATOMIC_ACQUIRE)!=r.ci)
    CHECK(reap(&r,r.ci,0)==0);
   CALL(N_YIELD,0,0,0);
  }
  CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid && status==0);
  CHECK(*r.sh==4096 && *r.st==4096);CHECK(finish(&r)==0);
 }
 return 0;
}
static int fork_lifetime(void)
{
 struct ring r;struct sqe q;long pid;int status=0;
 CHECK(init(&r,NOARRAY,8)==0);pid=fork_child();CHECK(pid>=0);
 if(pid==0) {zero(&q,sizeof(q));q.ud=45;queue(&r,q,0);int e=flush(&r,1);CALL(N_CLOSE,r.fd,0,0);CALL(N_EXIT,e!=0,0,0);}
 CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid && status==0);CHECK(reap(&r,45,0)==0);
 r.si=1;zero(&q,sizeof(q));q.ud=46;queue(&r,q,0);CHECK(flush(&r,1)==0 && reap(&r,46,0)==0);return finish(&r);
}

/* REGISTER_PROBE's header and entries are fixed LP64 wire structures. */
struct probe_op {
	unsigned char op, reserved;
	unsigned short flags;
	u32 reserved2;
};
struct probe {
	unsigned char last, count;
	unsigned short reserved;
	u32 reserved2[3];
	struct probe_op ops[256];
};
_Static_assert(sizeof(struct probe_op) == 8, "probe entry ABI");
_Static_assert(sizeof(struct probe) == 16 + 256 * 8, "probe ABI");

static long
query(long fd, void *p, u32 n)
{
	return (sc(N_REGISTER, fd, 8, (long)p, n, 0, 0));
}

static int
probe_layout(void)
{
	struct ring r;
	struct probe p;
	unsigned char *bytes = (void *)&p;
	u32 counts[] = {0, 1, 7, 64, 65, 128, 256};
	u32 last, size, count;

	CHECK(init(&r, 0, 8) == 0);
	zero(&p, sizeof(p));
	CHECK(query(r.fd, &p, 256) == 0);
	last = p.last;
	CHECK(last >= 55 && p.count == last + 1);
	for (u32 n = 0; n < sizeof(counts) / sizeof(counts[0]); n++) {
		count = counts[n] < last + 1 ? counts[n] : last + 1;
		size = 16 + count * 8;
		for (u32 i = 0; i < sizeof(p); i++) bytes[i] = 0xa5;
		zero(&p, size);
		CHECK(query(r.fd, &p, counts[n]) == 0);
		CHECK(p.last == last && p.count == count && p.reserved == 0);
		CHECK(p.reserved2[0] == 0 && p.reserved2[1] == 0 && p.reserved2[2] == 0);
		for (u32 i = 0; i < count; i++) {
			CHECK(p.ops[i].op == i && p.ops[i].reserved == 0);
			CHECK(p.ops[i].reserved2 == 0 && (p.ops[i].flags & ~1) == 0);
		}
		for (u32 i = size; i < sizeof(p); i++) CHECK(bytes[i] == 0xa5);
	}
	return (finish(&r));
}

static int
probe_invalid(void)
{
	struct ring r;
	struct probe p;
	unsigned char *bytes = (void *)&p;
	u32 size;

	CHECK(init(&r, NOARRAY, 8) == 0);
	zero(&p, sizeof(p));
	CHECK(query(r.fd, &p, 256) == 0);
	size = 16 + p.count * 8;
	/* Every nonzero input byte, not just explicitly named reserved fields. */
	for (u32 i = 0; i < size; i++) {
		zero(&p, sizeof(p)); bytes[i] = 1;
		CHECK(query(r.fd, &p, 256) == -22);
		for (u32 j = 0; j < sizeof(p); j++) CHECK(bytes[j] == (j == i));
	}
	zero(&p, sizeof(p));
	CHECK(query(r.fd, &p, 257) == -22);
	CHECK(query(r.fd, &p, 0xffffffffU) == -22);
	CHECK(query(r.fd, 0, 0) == -22 && query(r.fd, 0, 1) == -22);
	CHECK(query(r.fd, (void *)1, 257) == -22);
	CHECK(query(r.fd, (void *)1, 0) == -14);
	CHECK(query(-2, &p, 1) == -9);
	long file = sc(N_OPENAT, -100, (long)"probe-regular", OPENFLAGS, 0600, 0, 0);
	CHECK(file >= 0 && query(file, &p, 1) == -NOTSUP);
	CHECK(CALL(N_CLOSE, file, 0, 0) == 0);
	CHECK(query(r.fd, &p, 256) == 0);
	return (finish(&r));
}

static int
probe_faults(void)
{
	struct ring r;
	struct probe p;
	long map;
	char *mem;

	CHECK(init(&r, 0, 8) == 0);
	map = sc(N_MMAP, 0, 8192, 3, ANON_FLAGS, -1, 0);
	CHECK(map >= 0); mem = (char *)map;
	CHECK(CALL(N_MPROTECT, mem + 4096, 4096, 0) == 0);
	CHECK(query(r.fd, mem + 4096, 0) == -14);
	CHECK(query(r.fd, mem + 4096 - 8, 0) == -14);
	CHECK(query(r.fd, mem + 4096 - 16, 1) == -14);
	/* An exact header ending at the guard page must work at nr_args=0. */
	CHECK(query(r.fd, mem + 4096 - 16, 0) == 0);
	zero(mem, 4096);
	CHECK(CALL(N_MPROTECT, mem, 4096, 1) == 0);
	CHECK(query(r.fd, mem, 256) == -14); /* readable input, denied output */
	CHECK(CALL(N_MUNMAP, mem, 8192, 0) == 0);
	CHECK(query(r.fd, mem, 256) == -14);
	zero(&p, sizeof(p)); CHECK(query(r.fd, &p, 256) == 0);
	return (finish(&r));
}

/* This inventory qualifies these BSD front ends, not another Linux kernel. */
static int
probe_scope(void)
{
	static const unsigned char core[] = {
		0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 14, 15, 17, 19, 20,
		22, 23, 24, 31, 32, 40, 49, 54, 55, 60, 61, 63
	};
	struct ring r;
	struct probe p;
	struct sqe q;
	int expected;
	long fd;

	CHECK(init(&r, 0, 8) == 0);
	zero(&p, sizeof(p)); CHECK(query(r.fd, &p, 256) == 0);
	CHECK(p.count == 65 && p.last == 64);
	for (u32 op = 0; op < p.count; op++) {
#ifdef LINUX_ABI
		expected = 1;
#else
		expected = 0;
		for (u32 i = 0; i < sizeof(core); i++) if (core[i] == op) expected = 1;
#endif
		CHECK(p.ops[op].flags == expected);
#ifndef LINUX_ABI
		if (!expected) {
			zero(&q, sizeof(q)); q.op = op; q.fd = -1; q.ud = op;
			queue(&r, q, 0); CHECK(flush(&r, 1) == 0 && reap(&r, op, -22) == 0);
		}
#endif
	}
	(void)core;
	/* Native OPENAT must reject before creating the Linux-named path. */
	zero(&q, sizeof(q)); q.op = 18; q.fd = -100; q.addr = (u64)"probe-created";
	q.misc = 2 | 0100 | 0200; q.len = 0600; q.ud = 100;
	queue(&r, q, 0); CHECK(flush(&r, 1) == 0);
#ifdef LINUX_ABI
	CHECK(__atomic_load_n(r.ct, __ATOMIC_ACQUIRE) > r.ci);
	fd = r.cqes[r.ci & (r.p.cq - 1)].res; CHECK(fd >= 0);
	CHECK(reap(&r, 100, fd) == 0 && CALL(N_CLOSE, fd, 0, 0) == 0);
#else
	CHECK(reap(&r, 100, -22) == 0);
	fd = sc(N_OPENAT, -100, (long)"probe-created", 0, 0, 0, 0);
	CHECK(fd == -2);
#endif
	zero(&q, sizeof(q)); q.ud = 101; queue(&r, q, 0);
	CHECK(flush(&r, 1) == 0 && reap(&r, 101, 0) == 0);
	return (finish(&r));
}

static int
probe_repeat(long fd, u32 n)
{
	struct probe p;
	for (u32 i = 0; i < n; i++) {
		zero(&p, sizeof(p));
		CHECK(query(fd, &p, 256) == 0 && p.count == p.last + 1);
		CHECK(p.ops[0].flags == 1);
	}
	return (0);
}

static int
probe_lifetime(void)
{
	struct ring r;
	long fd, pid;
	int status = 0;

	CHECK(init(&r, NOARRAY, 8) == 0);
	fd = CALL(N_DUP, r.fd, 0, 0); CHECK(fd >= 0);
	CHECK(CALL(N_CLOSE, r.fd, 0, 0) == 0); r.fd = fd;
	pid = fork_child(); CHECK(pid >= 0);
	if (pid == 0) CALL(N_EXIT, probe_repeat(fd, 64) != 0, 0, 0);
	CHECK(sc(N_WAIT, pid, (long)&status, 0, 0, 0, 0) == pid && status == 0);
	CHECK(probe_repeat(fd, 64) == 0);
	CHECK(finish(&r) == 0);
	struct probe p; zero(&p, sizeof(p)); CHECK(query(fd, &p, 1) == -9);
	return (0);
}

/* A held ring permits read-only capability discovery after dropping privilege. */
static int
probe_permissions(void)
{
	struct ring r;
	struct probe p;

	CHECK(init(&r, NOARRAY, 8) == 0);
	CHECK(CALL(N_SETUID, 65534, 0, 0) == 0);
#ifndef LINUX_ABI
	CHECK(CALL(SYS_cap_enter, 0, 0, 0) == 0);
#endif
	CHECK(probe_repeat(r.fd, 32) == 0);
	zero(&p, sizeof(p)); p.reserved = 1;
	CHECK(query(r.fd, &p, 1) == -22);
	CHECK(query(r.fd, (void *)1, 1) == -14);
	return (finish(&r));
}

static int
probe_concurrent(void)
{
	struct ring r;
	struct sqe q;
	long pid;
	int status = 0;

	CHECK(init(&r, NOARRAY, 8) == 0);
	pid = fork_child(); CHECK(pid >= 0);
	if (pid == 0) CALL(N_EXIT, probe_repeat(r.fd, 512) != 0, 0, 0);
	for (u32 i = 0; i < 128; i++) {
		CHECK(probe_repeat(r.fd, 4) == 0);
		zero(&q, sizeof(q)); q.ud = i; queue(&r, q, 0);
		CHECK(flush(&r, 1) == 0 && reap(&r, i, 0) == 0);
	}
	CHECK(sc(N_WAIT, pid, (long)&status, 0, 0, 0, 0) == pid && status == 0);
	return (finish(&r));
}

/* The same buffers and assertions exercise native rings, Linux rings and v2. */
#ifdef LINUX_ABI
#define N_SEEK NR(8,62)
#define N_TRUNC NR(77,46)
#define N_FCNTL NR(72,25)
#define APPEND_FLAG 02000
#define N_PWRITEV2 NR(328,287)
#define N_PREADV2 NR(327,286)
#else
#define N_SEEK SYS_lseek
#define N_TRUNC SYS_ftruncate
#define N_FCNTL SYS_fcntl
#define APPEND_FLAG O_APPEND
#endif
struct rwvec { void *base; u64 len; };
struct rwstate { struct ring r; long fd; char *data; struct rwvec v[2]; };
static int rwinit(struct rwstate *s)
{
 CHECK(init(&s->r,0,8)==0);
 s->fd=sc(N_OPENAT,-100,(long)"rwf",OPENFLAGS,0600,0,0);CHECK(s->fd>=0);
 s->data=(char *)sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK((long)s->data>=0);
 s->v[0].base=s->data;s->v[0].len=4096;
 CHECK(sc(N_REGISTER,s->r.fd,0,(long)s->v,1,0,0)==0);
 return 0;
}
static int rwfinish(struct rwstate *s)
{
 CHECK(sc(N_REGISTER,s->r.fd,1,0,0,0,0)==0);
 CHECK(CALL(N_MUNMAP,s->data,4096,0)==0);
 CHECK(CALL(N_CLOSE,s->fd,0,0)==0);return finish(&s->r);
}
static int rwreset(struct rwstate *s)
{
 CHECK(CALL(N_TRUNC,s->fd,0,0)==0);CHECK(CALL(N_SEEK,s->fd,0,0)==0);
 CHECK(CALL(N_WRITE,s->fd,"seed",4)==4);CHECK(CALL(N_SEEK,s->fd,0,0)==0);
 for(int i=0;i<4;i++)s->data[i]="DATA"[i];return 0;
}
static int rwcheck(struct rwstate *s,const char *want,int len,long position)
{
 char buf[32];CHECK(CALL(N_SEEK,s->fd,0,1)==position);
 CHECK(CALL(N_SEEK,s->fd,0,0)==0);CHECK(CALL(N_READ,s->fd,buf,sizeof(buf))==len);
 for(int i=0;i<len;i++)CHECK(buf[i]==want[i]);return 0;
}
/* mode: flat, vector, registered flat, direct v2 (Linux only). */
static int rwop(struct rwstate *s,int mode,int writing,u32 flags,long off,int async,int expected)
{
 struct sqe q; long res;
 s->v[0].base=s->data;s->v[0].len=2;s->v[1].base=s->data+2;s->v[1].len=2;
 if(mode==3) {
#ifdef LINUX_ABI
  res=sc(writing?N_PWRITEV2:N_PREADV2,s->fd,(long)s->v,2,off,off<0?-1:0,flags);
#else
  return 0;
#endif
 } else {
  zero(&q,sizeof(q));q.op=mode==0?(writing?23:22):mode==1?(writing?2:1):(writing?5:4);
  q.fd=s->fd;q.addr=mode==1?(u64)s->v:(u64)s->data;q.len=mode==1?2:4;
  q.off=off;q.misc=flags;q.flags=async?16:0;q.ud=0x1234;
  queue(&s->r,q,0);CHECK(flush(&s->r,1)==0);
  CHECK(__atomic_load_n(s->r.ct,__ATOMIC_ACQUIRE)>s->r.ci);
  struct cqe c=s->r.cqes[s->r.ci & (s->r.p.cq-1)];
  CHECK(c.ud==q.ud && c.flags==0);res=c.res;
  __atomic_store_n(s->r.ch,++s->r.ci,__ATOMIC_RELEASE);
 }
 if(res!=expected){put("RWF mismatch mode/flags/result/expected ");putnum(mode);put(" ");putnum(flags);put(" ");putnum(res);put(" ");putnum(expected);put("\n");return __LINE__;}
 return 0;
}
static int rwf_sync(void)
{
 struct rwstate s;u32 flags[]={0,2,4,6,32,34,36,38};CHECK(rwinit(&s)==0);
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++)
 for(u32 f=0;f<sizeof(flags)/sizeof(flags[0]);f++) {
  CHECK(rwreset(&s)==0);CHECK(rwop(&s,mode,1,flags[f],0,async,4)==0);
#ifndef LINUX_ABI
  if(mode==3)continue;
#endif
  CHECK(rwcheck(&s,"DATA",4,0)==0);
  CHECK(CALL(N_SEEK,s.fd,0,0)==0);zero(s.data,4);
  CHECK(rwop(&s,mode,0,flags[f],-1,async,4)==0);
  for(int i=0;i<4;i++)CHECK(s.data[i]=="DATA"[i]);
  CHECK(CALL(N_SEEK,s.fd,0,1)==4);
 }
 return rwfinish(&s);
}
static int rwf_reject(void)
{
 struct rwstate s;u32 flags[25]={48,1};int n=2;
 for(int bit=9;bit<32;bit++)flags[n++]=1U<<bit;
 CHECK(rwinit(&s)==0);
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++)for(int wr=0;wr<2;wr++)
 for(int f=0;f<n;f++) {
  if(mode==3 && flags[f]==1)continue; /* HIPRI is accepted by direct I/O. */
  CHECK(rwreset(&s)==0);
  CHECK(rwop(&s,mode,wr,flags[f],0,async,flags[f]==48 || flags[f]==1?-22:-NOTSUP)==0);
  for(int i=0;i<4;i++)CHECK(s.data[i]=="DATA"[i]);
  CHECK(rwcheck(&s,"seed",4,0)==0);
 }
 return rwfinish(&s);
}
static int rwf_append(void)
{
 struct rwstate s;u32 flags[]={0,16,32,18,36};CHECK(rwinit(&s)==0);
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++)for(int append=0;append<2;append++)
 for(int cur=0;cur<2;cur++)for(u32 f=0;f<sizeof(flags)/sizeof(flags[0]);f++) {
  CHECK(CALL(N_FCNTL,s.fd,4,0)==0);CHECK(rwreset(&s)==0);
  CHECK(CALL(N_FCNTL,s.fd,4,append?APPEND_FLAG:0)==0);
  int app=(flags[f]&16)||(append && !(flags[f]&32));
  CHECK(rwop(&s,mode,1,flags[f],cur?-1:0,async,4)==0);
#ifndef LINUX_ABI
  if(mode==3)continue;
#endif
  CHECK((CALL(N_FCNTL,s.fd,3,0)&APPEND_FLAG)==(append?APPEND_FLAG:0));
  CHECK(rwcheck(&s,app?"seedDATA":"DATA",app?8:4,cur?(app?8:4):0)==0);
 }
 return rwfinish(&s);
}
static int rwf_faults(void)
{
 struct rwstate s;long fd;CHECK(rwinit(&s)==0);fd=s.fd;
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++) {
  CHECK(rwreset(&s)==0);
  CHECK(rwop(&s,mode,1,4,-2,async,-22)==0);
  s.fd=-2;CHECK(rwop(&s,mode,1,4,0,async,-9)==0);s.fd=fd;
  CHECK(rwcheck(&s,"seed",4,0)==0);
  s.fd=sc(N_OPENAT,-100,(long)"rwf",0,0,0,0);CHECK(s.fd>=0);
  CHECK(rwop(&s,mode,1,4,0,async,-9)==0);CHECK(CALL(N_CLOSE,s.fd,0,0)==0);s.fd=fd;
  CHECK(CALL(N_SEEK,s.fd,0,0)==0);CHECK(rwop(&s,mode,0,4,4,async,0)==0);
 }
 return rwfinish(&s);
}
static int rwf_links(void)
{
 struct rwstate s;struct sqe q;CHECK(rwinit(&s)==0);CHECK(rwreset(&s)==0);
 for(int async=0;async<2;async++) {
  zero(&q,sizeof(q));q.op=23;q.flags=4|(async?16:0);q.fd=s.fd;q.addr=(u64)s.data;
  q.len=4;q.misc=0x80000000;q.ud=1;queue(&s.r,q,0);
  q.flags=0;q.misc=4;q.ud=2;queue(&s.r,q,0);CHECK(flush(&s.r,2)==0);
  CHECK(reap(&s.r,1,-NOTSUP)==0 && reap(&s.r,2,-CANCELED)==0);
  CHECK(rwcheck(&s,"seed",4,0)==0);CHECK(CALL(N_SEEK,s.fd,0,0)==0);
 }
 return rwfinish(&s);
}
static int rwf_fixed_file(void)
{
 struct rwstate s;struct sqe q;int fd;CHECK(rwinit(&s)==0);CHECK(rwreset(&s)==0);fd=s.fd;
 CHECK(sc(N_REGISTER,s.r.fd,2,(long)&fd,1,0,0)==0);
 CHECK(CALL(N_CLOSE,s.fd,0,0)==0);s.fd=sc(N_OPENAT,-100,(long)"rwf",2,0,0,0);CHECK(s.fd>=0);
 struct rwvec v[2]={{s.data,2},{s.data+2,2}};
 for(int vec=0;vec<2;vec++)for(int async=0;async<2;async++) {
  zero(&q,sizeof(q));q.op=vec?61:5;q.flags=1|(async?16:0);q.fd=0;q.addr=vec?(u64)v:(u64)s.data;q.len=vec?2:4;q.misc=4;q.ud=1;
  queue(&s.r,q,0);CHECK(flush(&s.r,1)==0 && reap(&s.r,1,4)==0);
  CHECK(rwcheck(&s,"DATA",4,0)==0);CHECK(CALL(N_SEEK,s.fd,0,0)==0);
  q.misc=0x80000000;q.ud=2;queue(&s.r,q,0);CHECK(flush(&s.r,1)==0 && reap(&s.r,2,-NOTSUP)==0);
 }
 CHECK(sc(N_REGISTER,s.r.fd,3,0,0,0,0)==0);return rwfinish(&s);
}
/* Two independent rings append through distinct descriptions of the same file. */
static int rwf_append_worker(int child)
{
 struct rwstate s;zero(&s,sizeof(s));CHECK(init(&s.r,0,8)==0);
 s.fd=sc(N_OPENAT,-100,(long)"rwf",2,0,0,0);CHECK(s.fd>=0);
 char buf[4];for(int i=0;i<4;i++)buf[i]=child?'C':'P';s.data=buf;
 for(int i=0;i<64;i++)CHECK(rwop(&s,0,1,16|4,0,1,4)==0);
 CHECK(CALL(N_CLOSE,s.fd,0,0)==0);return finish(&s.r);
}
static int rwf_concurrent(void)
{
 long fd,pid;int status;char buf[513];int child=0,parent=0;
 fd=sc(N_OPENAT,-100,(long)"rwf",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 pid=fork_child();CHECK(pid>=0);
 if(pid==0)CALL(N_EXIT,rwf_append_worker(1)!=0,0,0);
 CHECK(rwf_append_worker(0)==0);
 CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid && status==0);
 CHECK(CALL(N_READ,fd,buf,sizeof(buf))==512);
 for(int i=0;i<512;i+=4) {
  CHECK(buf[i]=='C'||buf[i]=='P');for(int j=1;j<4;j++)CHECK(buf[i+j]==buf[i]);
  if(buf[i]=='C')child++;else parent++;
 }
 CHECK(child==64&&parent==64);CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;
}

static int rwf_nosignal_child(int vec,int async,int suppress)
{
 struct ring r;struct sqe q;struct viov v;int p[2];char c='n';
 CHECK(sc(N_PIPE2,(long)p,0,0,0,0,0)==0);CHECK(CALL(N_CLOSE,p[0],0,0)==0);
 CHECK(init(&r,0,8)==0);v.base=&c;v.len=1;zero(&q,sizeof(q));
 q.op=vec?2:23;q.flags=async?16:0;q.fd=p[1];q.off=(u64)-1;
 q.addr=(u64)(vec?(void *)&v:(void *)&c);q.len=1;q.misc=suppress?256:0;q.ud=1;
 queue(&r,q,0);CHECK(flush(&r,1)==0);
 CHECK(reap(&r,1,-32)==0);CHECK(CALL(N_CLOSE,p[1],0,0)==0);return finish(&r);
}
static int rwf_nosignal(void)
{
 long pid;int status;
 for(int vec=0;vec<2;vec++)for(int async=0;async<2;async++)for(int suppress=0;suppress<2;suppress++) {
  pid=fork_child();CHECK(pid>=0);
  if(pid==0)CALL(N_EXIT,rwf_nosignal_child(vec,async,suppress)!=0,0,0);
  status=0;CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid);
  if(!async&&!suppress)CHECK((status&0x7f)==SIGPIPE_VALUE);else CHECK(status==0);
 }
 return 0;
}

static int rwf_unsupported(void)
{
 struct rwstate s;u32 flags[]={8,64,128};CHECK(rwinit(&s)==0);
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++)for(int wr=0;wr<2;wr++)
 for(u32 f=0;f<sizeof(flags)/sizeof(flags[0]);f++) {
  CHECK(rwreset(&s)==0);CHECK(rwop(&s,mode,wr,flags[f],0,async,-NOTSUP)==0);
  for(int i=0;i<4;i++)CHECK(s.data[i]=="DATA"[i]);CHECK(rwcheck(&s,"seed",4,0)==0);
 }
 return rwfinish(&s);
}
static int rwf_memory_faults(void)
{
 struct rwstate s;struct sqe q;struct rwvec v={0,4};CHECK(rwinit(&s)==0);
 for(int async=0;async<2;async++)for(int wr=0;wr<2;wr++)for(int mode=0;mode<3;mode++) {
  CHECK(rwreset(&s)==0);zero(&q,sizeof(q));q.op=mode==0?(wr?23:22):mode==1?(wr?2:1):(wr?5:4);
  q.fd=s.fd;q.flags=async?16:0;q.addr=mode==1?(u64)&v:0;q.len=mode==1?1:4;q.misc=4;q.ud=1;
  queue(&s.r,q,0);CHECK(flush(&s.r,1)==0&&reap(&s.r,1,-14)==0);
  CHECK(rwcheck(&s,"seed",4,0)==0);CHECK(CALL(N_SEEK,s.fd,0,0)==0);
  if(mode==1) {
   q.addr=0;q.ud=2;queue(&s.r,q,0);CHECK(flush(&s.r,1)==0&&reap(&s.r,2,-14)==0);
   q.addr=(u64)&v;q.len=1025;q.ud=3;queue(&s.r,q,0);CHECK(flush(&s.r,1)==0&&reap(&s.r,3,-22)==0);
  }
 }
#ifdef LINUX_ABI
 for(int wr=0;wr<2;wr++) {
  CHECK(sc(wr?N_PWRITEV2:N_PREADV2,s.fd,(long)&v,1,0,0,4)==-14);
  CHECK(sc(wr?N_PWRITEV2:N_PREADV2,s.fd,0,1,0,0,4)==-14);
  CHECK(sc(wr?N_PWRITEV2:N_PREADV2,s.fd,(long)&v,1025,0,0,4)==-22);
 }
#endif
 return rwfinish(&s);
}
static int rwf_fd_reuse(void)
{
 struct rwstate s;struct sqe q;long original,reused;char b[33];CHECK(rwinit(&s)==0);
 original=CALL(N_DUP,s.fd,0,0);CHECK(original>=0);
 for(int round=0;round<32;round++) {
  CHECK(rwreset(&s)==0);
  for(int i=0;i<8;i++) {
   zero(&q,sizeof(q));q.op=23;q.flags=16;q.fd=s.fd;q.addr=(u64)s.data;q.len=4;
   q.off=i*4;q.misc=i&1?2:4;q.ud=i;queue(&s.r,q,0);
  }
  CHECK(sc(N_ENTER,s.r.fd,8,0,0,0,0)==8);
  long old=s.fd;CHECK(CALL(N_CLOSE,s.fd,0,0)==0);
  reused=sc(N_OPENAT,-100,(long)"replacement",round==0?OPENFLAGS:2,0600,0,0);
  /* O_EXCL has different values; use a fresh file only in round zero. */
  if(reused<0)reused=sc(N_OPENAT,-100,(long)"replacement",2,0,0,0);
  CHECK(reused==old);CHECK(CALL(N_TRUNC,reused,0,0)==0);
  CHECK(CALL(N_WRITE,reused,"safe",4)==4);
  CHECK(sc(N_ENTER,s.r.fd,0,8,1,0,0)==0);
  unsigned seen=0;
  for(int i=0;i<8;i++) {
   CHECK(__atomic_load_n(s.r.ct,__ATOMIC_ACQUIRE)>s.r.ci);
   struct cqe c=s.r.cqes[s.r.ci&(s.r.p.cq-1)];
   if(c.ud>=8||c.res!=4||c.flags!=0){put("RWF reuse completion ");putnum(c.ud);put(" ");putnum(c.res);put(" ");putnum(c.flags);put("\n");return __LINE__;}
   CHECK(!(seen&(1U<<c.ud)));seen|=1U<<c.ud;__atomic_store_n(s.r.ch,++s.r.ci,__ATOMIC_RELEASE);
  }
  CHECK(seen==255);CHECK(CALL(N_SEEK,reused,0,0)==0);CHECK(CALL(N_READ,reused,b,33)==4);
  for(int i=0;i<4;i++)CHECK(b[i]=="safe"[i]);CHECK(CALL(N_CLOSE,reused,0,0)==0);
  CHECK(CALL(N_SEEK,original,0,0)==0);CHECK(CALL(N_READ,original,b,33)==32);
  for(int i=0;i<32;i++)CHECK(b[i]=="DATA"[i%4]);
  s.fd=CALL(N_DUP,original,0,0);CHECK(s.fd>=0);
 }
 CHECK(CALL(N_CLOSE,original,0,0)==0);return rwfinish(&s);
}

static int rwf_memfd(void)
{
 struct rwstate s;long fd;int addseals;CHECK(rwinit(&s)==0);CHECK(CALL(N_CLOSE,s.fd,0,0)==0);
#ifdef LINUX_ABI
 fd=CALL(NR(319,279),"rwf",2,0);addseals=1033;
#else
 fd=memfd_create("rwf",2);addseals=19;
#endif
 CHECK(fd>=0);s.fd=fd;
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++) {
  CHECK(CALL(N_FCNTL,fd,4,0)==0);CHECK(rwreset(&s)==0);
  CHECK(rwop(&s,mode,1,16|4,0,async,4)==0);
#ifndef LINUX_ABI
  if(mode==3)continue;
#endif
  CHECK(rwcheck(&s,"seedDATA",8,0)==0);CHECK(CALL(N_SEEK,fd,0,0)==0);
  CHECK(CALL(N_FCNTL,fd,4,APPEND_FLAG)==0);
  CHECK(rwop(&s,mode,1,32|2,-1,async,4)==0);
  CHECK(rwcheck(&s,"DATADATA",8,4)==0);
 }
 CHECK(CALL(N_FCNTL,fd,4,0)==0);CHECK(rwreset(&s)==0);
 CHECK(CALL(N_FCNTL,fd,addseals,4)==0); /* F_SEAL_GROW */
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++) {
  CHECK(CALL(N_SEEK,fd,0,0)==0);CHECK(rwop(&s,mode,1,16|4,-1,async,-1)==0);
  CHECK(rwcheck(&s,"seed",4,0)==0);
 }
 CHECK(CALL(N_FCNTL,fd,addseals,8)==0); /* F_SEAL_WRITE */
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++) {
  CHECK(CALL(N_SEEK,fd,0,0)==0);CHECK(rwop(&s,mode,1,32|4,0,async,-1)==0);
  CHECK(rwcheck(&s,"seed",4,0)==0);
 }
 return rwfinish(&s);
}

/* Invoked separately by the crash/reboot gate, outside the ordinary inventory. */
static int rwf_durable(int action)
{
 struct ring r;struct sqe q;char data[4096],readback[4096];long fd;
 struct rwvec v={data,sizeof(data)};
 CHECK(init(&r,0,8)==0);
 for(int mode=0;mode<4;mode++)for(int async=0;async<2;async++)for(int sync=0;sync<2;sync++) {
#ifndef LINUX_ABI
  if(mode==3)continue;
#endif
  char path[]="durable-000";path[8]+=(char)mode;path[9]+=(char)async;path[10]+=(char)sync;
  fd=sc(N_OPENAT,-100,(long)path,action==0?OPENFLAGS:2,0600,0,0);CHECK(fd>=0);
  for(u32 i=0;i<sizeof(data);i++)data[i]=(char)('A'+(mode*4+async*2+sync+i)%26);
  if(action==0){CHECK(CALL(N_TRUNC,fd,sizeof(data),0)==0);CHECK(CALL(N_CLOSE,fd,0,0)==0);continue;}
  if(action==2) {
   CHECK(CALL(N_READ,fd,readback,sizeof(readback))==sizeof(readback));
   for(u32 i=0;i<sizeof(data);i++)CHECK(readback[i]==data[i]);
  } else {
   if(mode==3) {
#ifdef LINUX_ABI
    CHECK(sc(N_PWRITEV2,fd,(long)&v,1,0,0,sync?4:2)==sizeof(data));
#endif
   } else {
    if(mode==2)CHECK(sc(N_REGISTER,r.fd,0,(long)&v,1,0,0)==0);
    zero(&q,sizeof(q));q.op=mode==0?23:mode==1?2:5;q.fd=fd;
    q.addr=mode==1?(u64)&v:(u64)data;q.len=mode==1?1:sizeof(data);
    q.misc=sync?4:2;q.flags=async?16:0;q.ud=1;
    queue(&r,q,0);CHECK(flush(&r,1)==0&&reap(&r,1,sizeof(data))==0);
    if(mode==2)CHECK(sc(N_REGISTER,r.fd,1,0,0,0,0)==0);
   }
  }
  CHECK(CALL(N_CLOSE,fd,0,0)==0);
 }
 return finish(&r);
}

static int rwf_retry(void)
{
 struct ring r;struct sqe q;char data[4];struct rwvec v={data,4};int fds[2];
 u32 flags[]={0,2,4,32,36};CHECK(init(&r,0,8)==0);
#ifdef LINUX_ABI
 CHECK(CALL(NR(293,59),fds,04000,0)==0);
#else
 CHECK(CALL(SYS_pipe2,fds,O_NONBLOCK,0)==0);
#endif
 for(int vec=0;vec<2;vec++)for(u32 i=0;i<sizeof(flags)/sizeof(flags[0]);i++) {
  zero(&q,sizeof(q));q.op=vec?1:22;q.fd=fds[0];q.off=(u64)-1;
  q.addr=vec?(u64)&v:(u64)data;q.len=vec?1:4;q.misc=flags[i];q.ud=i;
  queue(&r,q,0);CHECK(sc(N_ENTER,r.fd,1,0,0,0,0)==1);
  CHECK(__atomic_load_n(r.ct,__ATOMIC_ACQUIRE)==r.ci);
  CHECK(CALL(N_WRITE,fds[1],"DATA",4)==4);
  CHECK(sc(N_ENTER,r.fd,0,1,1,0,0)==0);CHECK(reap(&r,i,4)==0);
  for(int j=0;j<4;j++)CHECK(data[j]=="DATA"[j]);
 }
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);return finish(&r);
}

/* Registered pages must survive changes to userspace mappings and tables. */
static long breg(struct ring *r,struct rwvec *v,u32 n) {return sc(N_REGISTER,r->fd,0,(long)v,n,0,0);}
static long bunreg(struct ring *r) {return sc(N_REGISTER,r->fd,1,0,0,0,0);}
static char *bmap(int shared) {
 return (char *)sc(N_MMAP,0,12288,3,shared?((ANON_FLAGS&~2)|1):ANON_FLAGS,-1,0);
}
static int bpipe(int *fds,int nonblock) {
#ifdef LINUX_ABI
 return CALL(NR(293,59),fds,nonblock?04000:0,0);
#else
 return CALL(SYS_pipe2,fds,nonblock?O_NONBLOCK:0,0);
#endif
}
static int bcheck(long fd,const char *s,int n) {
 char data[32];CHECK(CALL(N_SEEK,fd,0,0)==0);CHECK(CALL(N_READ,fd,data,sizeof(data))==n);
 for(int i=0;i<n;i++)if(data[i]!=s[i]){put("BUFFER_DATA byte ");putnum(i);put(" expected ");putnum(s[i]);put(" got ");putnum(data[i]);put("\n");return __LINE__;}return 0;
}
static int bop(struct ring *r,long fd,int wr,int vec,int async,void *addr,u32 len,int idx,int expect) {
 struct sqe q;zero(&q,sizeof(q));q.op=vec?(wr?61:60):(wr?5:4);q.fd=fd;q.flags=async?16:0;
 q.addr=(u64)addr;q.len=len;q.buf=idx;q.ud=r->si+1;queue(r,q,0);
 CHECK(flush(r,1)==0);if(reap(r,q.ud,expect)!=0){put("BUFFER_CQE expected ");putnum(expect);put(" got ");putnum(r->cqes[r->ci&(r->p.cq-1)].res);put("\n");return __LINE__;}return 0;
}
static int buffers_register(void) {
 struct ring r;char *p=bmap(0);struct rwvec v[3];CHECK((long)p>=0&&init(&r,0,8)==0);
 CHECK(bunreg(&r)==-6);CHECK(breg(&r,(void *)1,0)==-22);CHECK(breg(&r,(void *)1,1)==-14);
 CHECK(breg(&r,0,2)==-14);zero(v,sizeof(v));CHECK(breg(&r,v,2)==0);CHECK(breg(&r,v,1)==-16);CHECK(bunreg(&r)==0);
 v[0]=(struct rwvec){0,0};v[1]=(struct rwvec){p+4093,8};v[2]=(struct rwvec){p+8191,1};
 CHECK(breg(&r,v,3)==0);CHECK(sc(N_REGISTER,r.fd,1,1,0,0,0)==-22);
 CHECK(sc(N_REGISTER,r.fd,1,0,1,0,0)==-22);CHECK(bunreg(&r)==0);
 for(int i=0;i<32;i++){CHECK(breg(&r,v,3)==0);CHECK(bunreg(&r)==0);}
 CHECK(CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}
static int buffers_faults(void) {
 struct ring r;char *p=bmap(0);struct rwvec v[2];CHECK((long)p>=0&&init(&r,0,8)==0);
 struct rwvec bad[]={{0,1},{p,0},{p,(1UL<<30)+1},{(void *)1,1},{(void *)(~0UL-1023),4096},{p+4095,2}};
 CHECK(CALL(N_MPROTECT,p+4096,4096,0)==0);
 for(u32 n=0;n<sizeof(bad)/sizeof(bad[0]);n++) {
  v[0]=(struct rwvec){p,8};v[1]=bad[n];long result=breg(&r,v,2);
#ifdef LINUX_ABI
  CHECK(result==(n==4?-75:-14));
#else
  CHECK(result==(n==4?-EOVERFLOW:-14));
#endif
  CHECK(bunreg(&r)==-6);CHECK(breg(&r,v,1)==0);CHECK(bunreg(&r)==0);
 }
 CHECK(CALL(N_MPROTECT,p+4096,4096,1)==0);v[0]=(struct rwvec){p+4096,1};CHECK(breg(&r,v,1)==-14);
 CHECK(CALL(N_MPROTECT,p+4096,4096,3)==0);CHECK(breg(&r,v,1)==0);CHECK(bunreg(&r)==0);
 CHECK(CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}
static int buffers_ranges(void) {
 struct ring r;char *p=bmap(0);struct rwvec reg[2],v[2];long fd;
 CHECK((long)p>=0&&init(&r,0,8)==0);fd=sc(N_OPENAT,-100,(long)"buffer-ranges",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 reg[0]=(struct rwvec){p+4093,8};reg[1]=(struct rwvec){p+8192,8};
 CHECK(CALL(N_WRITE,fd,"ABCDEFGH",8)==8);CHECK(breg(&r,reg,2)==0);for(int i=0;i<8;i++)p[4093+i]="ABCDEFGH"[i];
 for(int a=0;a<2;a++)for(int wr=0;wr<2;wr++) {
  CHECK(bop(&r,fd,wr,0,a,p+4093,8,0,8)==0);
  CHECK(bop(&r,fd,wr,0,a,p+4092,1,0,-14)==0);CHECK(bop(&r,fd,wr,0,a,p+4100,2,0,-14)==0);
  CHECK(bop(&r,fd,wr,0,a,(void *)(~0UL-1),4,0,-14)==0);CHECK(bop(&r,fd,wr,0,a,p+4093,1,2,-14)==0);
  CHECK(bop(&r,fd,wr,0,a,p+8192,1,0,-14)==0);CHECK(bop(&r,fd,wr,0,a,p+4101,0,0,0)==0);
  v[0]=(struct rwvec){p+4093,4};v[1]=(struct rwvec){p+8192,4};
  CHECK(bop(&r,fd,wr,1,a,v,2,0,-14)==0);v[1]=(struct rwvec){p+4097,0};CHECK(bop(&r,fd,wr,1,a,v,2,0,-14)==0);
  CHECK(bop(&r,fd,wr,1,a,(void *)1,1,0,-14)==0);CHECK(bop(&r,fd,wr,1,a,v,1025,0,-22)==0);
 }
 CHECK(bunreg(&r)==0);CHECK(bop(&r,fd,1,0,0,p+4093,1,0,-14)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0&&CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}
static int buffers_vectors(void) {
 struct ring r;char *p=bmap(0);struct rwvec reg={p+4093,16},v[3];long fd;
 CHECK((long)p>=0&&init(&r,0,8)==0);fd=sc(N_OPENAT,-100,(long)"buffer-vectors",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 CHECK(breg(&r,&reg,1)==0);
 for(int a=0;a<2;a++) {
  for(int i=0;i<16;i++)p[4093+i]="ABCDEFGHIJKLMNOP"[i];
  v[0]=(struct rwvec){p+4105,4};v[1]=(struct rwvec){p+4093,4};v[2]=(struct rwvec){p+4097,4};
  CHECK(bop(&r,fd,1,1,a,v,3,0,12)==0);CHECK(bcheck(fd,"MNOPABCDEFGH",12)==0);
  zero(p+4093,16);v[0]=(struct rwvec){p+4093,3};v[1]=(struct rwvec){p+4096,9};
  CHECK(bop(&r,fd,0,1,a,v,2,0,12)==0);for(int i=0;i<12;i++)CHECK(p[4093+i]=="MNOPABCDEFGH"[i]);
 }
 CHECK(bunreg(&r)==0);CHECK(CALL(N_CLOSE,fd,0,0)==0&&CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}
static int buffers_remap(void) {
 struct ring r;CHECK(init(&r,0,8)==0);long fd=sc(N_OPENAT,-100,(long)"buffer-remap",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(int vec=0;vec<2;vec++)for(int a=0;a<2;a++) {
  char *p=bmap(0);CHECK((long)p>=0);struct rwvec reg={p+4093,8},v[2]={{p+4093,2},{p+4095,2}};
  for(int i=0;i<4;i++)p[4093+i]="OLD!"[i];CHECK(breg(&r,&reg,1)==0);
  CHECK(CALL(N_MUNMAP,p,12288,0)==0);CHECK(sc(N_MMAP,(long)p,12288,3,ANON_FLAGS|16,-1,0)==(long)p);
  for(int i=0;i<4;i++)p[4093+i]='Y';CHECK(CALL(N_TRUNC,fd,0,0)==0);
  CHECK(bop(&r,fd,1,vec,a,vec?(void *)v:p+4093,vec?2:4,0,4)==0);CHECK(bcheck(fd,"OLD!",4)==0);
  CHECK(CALL(N_SEEK,fd,0,0)==0&&CALL(N_WRITE,fd,"NEW!",4)==4);
  CHECK(bop(&r,fd,0,vec,a,vec?(void *)v:p+4093,vec?2:4,0,4)==0);
  for(int i=0;i<4;i++)CHECK(p[4093+i]=='Y');CHECK(CALL(N_TRUNC,fd,0,0)==0);
  CHECK(bop(&r,fd,1,vec,a,vec?(void *)v:p+4093,vec?2:4,0,4)==0);CHECK(bcheck(fd,"NEW!",4)==0);
  CHECK(bunreg(&r)==0&&CALL(N_MUNMAP,p,12288,0)==0);
 }
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
static int buffers_protect(void) {
 struct ring r;char *p=bmap(0);struct rwvec reg={p,8192};CHECK((long)p>=0&&init(&r,0,8)==0);
 long fd=sc(N_OPENAT,-100,(long)"buffer-protect",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 p[4095]='A';p[4096]='B';CHECK(breg(&r,&reg,1)==0);CHECK(CALL(N_MPROTECT,p,8192,0)==0);
 for(int a=0;a<2;a++){CHECK(bop(&r,fd,1,0,a,p+4095,2,0,2)==0);CHECK(bcheck(fd,"AB",2)==0);CHECK(bop(&r,fd,0,0,a,p+4095,2,0,2)==0);}
 CHECK(bunreg(&r)==0);CHECK(CALL(N_MPROTECT,p,8192,3)==0);CHECK(p[4095]=='A'&&p[4096]=='B');
 CHECK(CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
/* Nonblocking retry must keep the detached generation and vector snapshot. */
static int buffers_retry(void) {
 struct ring r;char *p=bmap(1);char *newp=bmap(1);int fds[2];struct sqe q;
 CHECK((long)p>=0&&(long)newp>=0&&init(&r,0,8)==0&&bpipe(fds,1)==0);
 for(int vec=0;vec<2;vec++) {
  struct rwvec reg={p,8},newreg={newp,8},v[2]={{p,2},{p+2,2}};zero(p,8);zero(newp,8);
  CHECK(breg(&r,&reg,1)==0);zero(&q,sizeof(q));q.op=vec?60:4;q.fd=fds[0];q.off=~0UL;q.addr=vec?(u64)v:(u64)p;q.len=vec?2:4;q.ud=vec;
  queue(&r,q,0);CHECK(sc(N_ENTER,r.fd,1,0,0,0,0)==1);CHECK(__atomic_load_n(r.ct,__ATOMIC_ACQUIRE)==r.ci);
  CHECK(bunreg(&r)==0&&breg(&r,&newreg,1)==0);v[0].base=(void *)1;
  CHECK(CALL(N_WRITE,fds[1],"HELD",4)==4);CHECK(sc(N_ENTER,r.fd,0,1,1,0,0)==0&&reap(&r,vec,4)==0);
  for(int i=0;i<4;i++)CHECK(p[i]=="HELD"[i]&&newp[i]==0);CHECK(bunreg(&r)==0);
 }
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_MUNMAP,newp,12288,0)==0);return finish(&r);
}
static int buffers_async(void) {
 for(int vec=0;vec<2;vec++)for(int closing=0;closing<2;closing++) {
  struct ring r;char *p=bmap(1);char *newp=bmap(1);int fds[2];struct sqe q;struct rwvec reg={p,8},v[2]={{p,2},{p+2,2}};
  CHECK((long)p>=0&&(long)newp>=0&&init(&r,0,8)==0&&bpipe(fds,0)==0);CHECK(breg(&r,&reg,1)==0);
  zero(&q,sizeof(q));q.op=vec?60:4;q.flags=16;q.fd=fds[0];q.off=~0UL;q.addr=vec?(u64)v:(u64)p;q.len=vec?2:4;q.ud=1;
  queue(&r,q,0);CHECK(sc(N_ENTER,r.fd,1,0,0,0,0)==1);CHECK(bunreg(&r)==0);reg.base=newp;CHECK(breg(&r,&reg,1)==0);
  long alias=-1;if(closing){alias=CALL(N_DUP,r.fd,0,0);CHECK(alias>=0);}
  v[0].base=(void *)1;if(closing)CHECK(CALL(N_CLOSE,r.fd,0,0)==0);
  CHECK(CALL(N_WRITE,fds[1],"LIVE",4)==4);
  if(!closing)CHECK(sc(N_ENTER,r.fd,0,1,1,0,0)==0&&reap(&r,1,4)==0);
  else {for(u32 n=0;n<1000000&&__atomic_load_n(p+3,__ATOMIC_ACQUIRE)!='E';n++)CALL(N_YIELD,0,0,0);CHECK(__atomic_load_n(p+3,__ATOMIC_ACQUIRE)=='E');}
  for(int i=0;i<4;i++)CHECK(p[i]=="LIVE"[i]&&newp[i]==0);
  if(!closing)CHECK(finish(&r)==0);else CHECK(CALL(N_CLOSE,alias,0,0)==0&&CALL(N_MUNMAP,r.mem,r.rlen,0)==0&&CALL(N_MUNMAP,r.sqes,r.slen,0)==0);
  CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);CHECK(CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_MUNMAP,newp,12288,0)==0);
 }
 return 0;
}
static int buffers_fork(void) {
 struct ring r;char *p=bmap(1);struct rwvec reg={p,8};int status;CHECK((long)p>=0&&init(&r,0,8)==0);
 long fd=sc(N_OPENAT,-100,(long)"buffer-fork",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(int i=0;i<4;i++)p[i]="PINS"[i];CHECK(breg(&r,&reg,1)==0);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){int rc=0;if(CALL(N_MUNMAP,p,12288,0)!=0)rc=1;
  if(!rc)rc=bop(&r,fd,1,0,1,p,4,0,4);if(!rc)rc=bcheck(fd,"PINS",4);CALL(N_EXIT,rc!=0,0,0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);r.si=*r.st;r.ci=*r.ch;CHECK(bunreg(&r)==0);
 /* Register in child; the shared ring must retain pages after child exit. */
 pid=fork_child();CHECK(pid>=0);if(pid==0){char *child=bmap(0);int rc=(long)child<0;struct rwvec cv={child,4};
  if(!rc){for(int i=0;i<4;i++)child[i]="EXIT"[i];*(u64 *)(p+4096)=(u64)child;rc=breg(&r,&cv,1)!=0;}CALL(N_EXIT,rc,0,0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 CHECK(bop(&r,fd,1,0,1,(void *)*(u64 *)(p+4096),4,0,4)==0&&bcheck(fd,"EXIT",4)==0);
 CHECK(bunreg(&r)==0);CHECK(CALL(N_CLOSE,fd,0,0)==0&&CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}
static int buffers_cow_once(int prot) {
 struct ring r,overlap;char *p=bmap(0);struct rwvec reg={p+4096,4096};int tochild[2],fromchild[2],status;char sig;
 CHECK((long)p>=0&&init(&r,0,8)==0&&bpipe(tochild,0)==0&&bpipe(fromchild,0)==0);
 char path[]="buffer-cow-0";path[11]+=(char)prot;long fd=sc(N_OPENAT,-100,(long)path,OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(int i=0;i<4;i++)p[4096+i]="ORIG"[i];CHECK(breg(&r,&reg,1)==0);
 CHECK(init(&overlap,0,8)==0);struct rwvec both={p,8192};CHECK(breg(&overlap,&both,1)==0);
 CHECK(bunreg(&overlap)==0&&finish(&overlap)==0);CHECK(CALL(N_MPROTECT,p+4096,4096,prot)==0);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){int rc=0;
  if(CALL(N_WRITE,fromchild[1],"R",1)!=1||CALL(N_READ,tochild[0],&sig,1)!=1)rc=1;
  if(CALL(N_MPROTECT,p+4096,4096,3)!=0)rc=3;for(int i=0;i<4;i++)if(p[4096+i]!="ORIG"[i])rc=2;CALL(N_EXIT,rc,0,0);}
 CHECK(CALL(N_READ,fromchild[0],&sig,1)==1);
 CHECK(CALL(N_MPROTECT,p+4096,4096,3)==0);for(int i=0;i<4;i++)p[4096+i]="COW!"[i];CHECK(bop(&r,fd,1,0,1,p+4096,4,0,4)==0);CHECK(bcheck(fd,"COW!",4)==0);
 CHECK(CALL(N_SEEK,fd,0,0)==0&&CALL(N_WRITE,fd,"READ",4)==4);CHECK(bop(&r,fd,0,0,0,p+4096,4,0,4)==0);
 for(int i=0;i<4;i++)CHECK(p[4096+i]=="READ"[i]);CHECK(CALL(N_WRITE,tochild[1],"D",1)==1);
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);CHECK(bunreg(&r)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0&&CALL(N_MUNMAP,p,12288,0)==0);
 CHECK(CALL(N_CLOSE,tochild[0],0,0)==0&&CALL(N_CLOSE,tochild[1],0,0)==0&&CALL(N_CLOSE,fromchild[0],0,0)==0&&CALL(N_CLOSE,fromchild[1],0,0)==0);
 return finish(&r);
}
static int buffers_cow(void) {
 CHECK(buffers_cow_once(3)==0);CHECK(buffers_cow_once(1)==0);return buffers_cow_once(0);
}
static int buffers_mapped_file(void) {
 struct ring r;CHECK(init(&r,0,8)==0);
 long backing=sc(N_OPENAT,-100,(long)"buffer-backing",OPENFLAGS,0600,0,0);
 long source=sc(N_OPENAT,-100,(long)"buffer-source",OPENFLAGS,0600,0,0);CHECK(backing>=0&&source>=0);
 CHECK(CALL(N_TRUNC,backing,8192,0)==0&&CALL(N_WRITE,source,"FILE",4)==4);
 char *p=(char *)sc(N_MMAP,0,8192,3,1,backing,0);CHECK((long)p>=0);struct rwvec reg={p,8192};
 CHECK(breg(&r,&reg,1)==0);CHECK(bop(&r,source,0,0,1,p+4094,4,0,4)==0);
#ifdef LINUX_ABI
 CHECK(CALL(NR(26,227),p,8192,4)==0);
#else
 CHECK(CALL(SYS_msync,p,8192,0)==0);
#endif
 char data[4];CHECK(CALL(N_SEEK,backing,4094,0)==4094&&CALL(N_READ,backing,data,4)==4);
 for(int i=0;i<4;i++)CHECK(data[i]=="FILE"[i]);
 CHECK(CALL(N_CLOSE,backing,0,0)==0&&CALL(N_MUNMAP,p,8192,0)==0);
 CHECK(bop(&r,source,1,0,1,p+4094,4,0,4)==0&&bcheck(source,"FILE",4)==0);
 CHECK(bunreg(&r)==0&&CALL(N_CLOSE,source,0,0)==0);return finish(&r);
}
static int buffers_limits(void) {
 struct ring a,b;char *p=(char *)sc(N_MMAP,0,49152,3,ANON_FLAGS,-1,0);struct rwvec v={p,36864};struct {u64 cur,max;} lim={65536,65536};
 CHECK((long)p>=0);
#ifdef LINUX_ABI
 CHECK(sc(NR(302,261),0,8,(long)&lim,0,0,0)==0);
#else
 CHECK(CALL(SYS_setrlimit,6,&lim,0)==0);
#endif
 CHECK(CALL(N_SETUID,65534,0,0)==0);CHECK(init(&a,0,8)==0&&init(&b,0,8)==0);CHECK(breg(&a,&v,1)==0);CHECK(breg(&b,&v,1)==-12);
 CHECK(bunreg(&a)==0&&breg(&b,&v,1)==0&&bunreg(&b)==0);
 /* A failed multi-entry registration must return every charged page. */
 struct rwvec invalid[2]={{p,4096},{(void *)1,1}};
 for(int n=0;n<64;n++){CHECK(breg(&a,invalid,2)==-14);CHECK(breg(&b,&v,1)==0&&bunreg(&b)==0);}
 CHECK(CALL(N_MUNMAP,p,49152,0)==0&&finish(&a)==0);return finish(&b);
}
static int buffers_links(void) {
 struct ring r;char *p=bmap(0);struct rwvec reg={p,8},v[2]={{p,4},{p+8,4}};struct sqe q;
 CHECK((long)p>=0&&init(&r,0,8)==0);long fd=sc(N_OPENAT,-100,(long)"buffer-links",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 CHECK(CALL(N_WRITE,fd,"SAFE",4)==4&&breg(&r,&reg,1)==0);
 for(int a=0;a<2;a++)for(int wr=0;wr<2;wr++) {
  zero(&q,sizeof(q));q.op=wr?61:60;q.flags=4|(a?16:0);q.fd=fd;q.addr=(u64)v;q.len=2;q.ud=1;queue(&r,q,0);
  q.op=23;q.flags=0;q.addr=(u64)"BAD!";q.len=4;q.ud=2;queue(&r,q,0);
  CHECK(flush(&r,2)==0&&reap(&r,1,-14)==0&&reap(&r,2,-CANCELED)==0);CHECK(bcheck(fd,"SAFE",4)==0);
  for(int i=0;i<8;i++)CHECK(p[i]==0);
 }
 CHECK(bunreg(&r)==0&&CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}
static int buffers_churn(void) {
 /* Concurrent registrations on a shared ring, then cleanup/reuse. */
 struct ring r;char *p=bmap(1);struct rwvec reg={p,4096};int status;CHECK((long)p>=0&&init(&r,0,8)==0);
 long pid=fork_child();CHECK(pid>=0);
 for(int i=0;i<128;i++){long rc=breg(&r,&reg,1);CHECK(rc==0||rc==-16);rc=bunreg(&r);CHECK(rc==0||rc==-6);}
 if(pid==0)CALL(N_EXIT,0,0,0);
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);long rc=bunreg(&r);CHECK(rc==0||rc==-6);
 CHECK(breg(&r,&reg,1)==0&&bunreg(&r)==0);CHECK(CALL(N_MUNMAP,p,12288,0)==0);return finish(&r);
}

/* A separate stack permits concurrent VM operations without sharing C frames. */
#ifdef LINUX_ABI
extern long bclone(unsigned long,void *);
#if defined(__x86_64__)
__asm__(".text\n.globl bclone\nbclone:\nmov $56,%eax\nxor %edx,%edx\nxor %r10d,%r10d\nxor %r8d,%r8d\nsyscall\ntest %rax,%rax\njnz 1f\npop %rax\npop %rdi\ncall *%rax\nmov %eax,%edi\nmov $60,%eax\nsyscall\nud2\n1: ret\n");
#else
__asm__(".text\n.globl bclone\nbclone:\nmov x8,#220\nmov x2,#0\nmov x3,#0\nmov x4,#0\nsvc #0\ncbnz x0,1f\nldp x9,x0,[sp],#16\nblr x9\nmov x8,#93\nsvc #0\nbrk #0\n1: ret\n");
#endif
static long bspawn(int (*fn)(void *),void *arg,void *top) {
 u64 *sp=(u64 *)top-2;sp[0]=(u64)fn;sp[1]=(u64)arg;return bclone(0x100|17,sp);
}
static long bspawn_files(int (*fn)(void *),void *arg,void *top) {
 u64 *sp=(u64 *)top-2;sp[0]=(u64)fn;sp[1]=(u64)arg;
 return bclone(0x100|0x400|17,sp);
}
#elif defined(__aarch64__)
/* The generic arm64 libc rfork_thread cannot switch to a supplied stack. */
extern long bclone_bsd(unsigned long,void *);
__asm__(".text\n.globl bclone_bsd\nbclone_bsd:\nmov x9,x1\nmov x8,#251\nsvc #0\nb.cs 2f\ncbnz x0,1f\nmov sp,x9\nldp x10,x0,[sp],#16\nblr x10\nmov x8,#1\nsvc #0\nbrk #0\n1: ret\n2: neg x0,x0\nret\n");
static long bspawn(int (*fn)(void *),void *arg,void *top) {
 u64 *sp=(u64 *)top-2;sp[0]=(u64)fn;sp[1]=(u64)arg;return bclone_bsd(RFPROC|RFMEM|RFFDG,sp);
}
static long bspawn_files(int (*fn)(void *),void *arg,void *top) {
 u64 *sp=(u64 *)top-2;sp[0]=(u64)fn;sp[1]=(u64)arg;
 return bclone_bsd(RFPROC|RFMEM,sp);
}
#else
static long bspawn(int (*fn)(void *),void *arg,void *top) {
 long p=rfork_thread(RFPROC|RFMEM|RFFDG,top,fn,arg);return p<0?-errno:p;
}
static long bspawn_files(int (*fn)(void *),void *arg,void *top) {
 long p=rfork_thread(RFPROC|RFMEM,top,fn,arg);return p<0?-errno:p;
}
#endif
struct bvmrace {char *p;u32 go;};
static int bvmworker(void *arg) {
 struct bvmrace *s=arg;int status;
 while(!__atomic_load_n(&s->go,__ATOMIC_ACQUIRE))CALL(N_YIELD,0,0,0);
 for(int n=0;n<32;n++) {
  if(CALL(N_MPROTECT,s->p,4096,1)!=0)return 1;
  if((n&3)==0){long pid=fork_child();if(pid<0)return 2;if(pid==0)CALL(N_EXIT,0,0,0);
   if(CALL(N_WAIT,pid,&status,0)!=pid||status!=0)return 3;}
  if(CALL(N_MPROTECT,s->p,4096,3)!=0)return 4;
 }
 return 0;
}
static int buffers_vm_race(void) {
 struct ring r;char *p=bmap(0);CHECK((long)p>=0&&init(&r,0,8)==0);
 char *stack=(char *)sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);CHECK((long)stack>=0);
 long fd=sc(N_OPENAT,-100,(long)"buffer-vm-race",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(int n=0;n<8;n++) {
  struct bvmrace state={p+4096,0};struct rwvec reg={state.p,4096};int status;
  long pid=bspawn(bvmworker,&state,stack+65536);CHECK(pid>=0);__atomic_store_n(&state.go,1,__ATOMIC_RELEASE);
  long rc;int tries=0;do {rc=breg(&r,&reg,1);CHECK(rc==0||rc==-14);if(rc)CALL(N_YIELD,0,0,0);}while(rc&&++tries<10000);
  CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);CHECK(rc==0);
  for(int i=0;i<4;i++)p[4096+i]="RACE"[i];CHECK(bop(&r,fd,1,0,n&1,p+4096,4,0,4)==0&&bcheck(fd,"RACE",4)==0);
  CHECK(bunreg(&r)==0);
 }
 CHECK(CALL(N_MUNMAP,stack,65536,0)==0&&CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_CLOSE,fd,0,0)==0);return finish(&r);
}

/* Linked deadlines and cancellation: completion order is intentionally free. */
struct ltime { long sec,nsec; };
struct lsync_cancel {
 u64 addr; int fd; u32 flags; struct ltime timeout;
 unsigned char opcode,pad[7]; u64 pad2[3];
};
struct lfile_range { u32 off,len;u64 resv; };
static void lsync_init(struct lsync_cancel *c) { zero(c,sizeof(*c));c->timeout.sec=-1;c->timeout.nsec=-1; }

#ifdef LINUX_ABI
#define LTIME 62
#define LALREADY 114
#define LCLOCK NR(228,113)
#define LSLEEP NR(35,101)
#define LMONO 1
#define REG_CLOCK_MONOTONIC 1
#define REG_CLOCK_BOOTTIME 7
#else
#define LTIME ETIMEDOUT
#define LALREADY EALREADY
#define LCLOCK SYS_clock_gettime
#define LSLEEP SYS_nanosleep
#define LMONO 4
#define REG_CLOCK_MONOTONIC 5
#define REG_CLOCK_BOOTTIME 4
#endif
static void lpause(long ns) { struct ltime t={ns/1000000000,ns%1000000000};(void)CALL(LSLEEP,&t,0,0); }
static int lwait(struct ring *r,u32 n) {
 struct ltime end,now,t;struct {u64 sig;u32 sz,min;u64 ts;} a={0,0,0,(u64)&t};
 CHECK(CALL(LCLOCK,LMONO,&end,0)==0);end.sec+=2;
 while(__atomic_load_n(r->ct,__ATOMIC_ACQUIRE)-r->ci<n){
  CHECK(CALL(LCLOCK,LMONO,&now,0)==0);t.sec=end.sec-now.sec;t.nsec=end.nsec-now.nsec;if(t.nsec<0){t.sec--;t.nsec+=1000000000;}
  if(t.sec<0){put("completion wait expired\n");return __LINE__;}
  long ret=sc(N_ENTER,r->fd,0,n,1|8,(long)&a,sizeof(a));
  if(ret!=0&&ret!=-4&&ret!=-LTIME){put("wait=");putnum(ret);put("\n");return __LINE__;}
 }
 return 0;
}
static int lget(struct ring *r,struct cqe *c,u32 n) {
 CHECK(lwait(r,n)==0);for(u32 i=0;i<n;i++){c[i]=r->cqes[(r->ci&(r->p.cq-1))*((r->p.flags&SCQE32)?2:1)];CHECK(c[i].flags==0);__atomic_store_n(r->ch,++r->ci,__ATOMIC_RELEASE);}
 return 0;
}
static int lget_any(struct ring *r,struct cqe *c,u32 n) {
 CHECK(lwait(r,n)==0);for(u32 i=0;i<n;i++){c[i]=r->cqes[(r->ci&(r->p.cq-1))*((r->p.flags&SCQE32)?2:1)];__atomic_store_n(r->ch,++r->ci,__ATOMIC_RELEASE);}
 return 0;
}
static int lresult(struct cqe *c,u32 n,u64 key,int expect) {
 int found=0;for(u32 i=0;i<n;i++)if(c[i].ud==key){found++;if(c[i].res!=expect){put("key=");putnum(key);put(" got=");putnum(c[i].res);put(" expected=");putnum(expect);put("\n");return __LINE__;}}CHECK(found==1);return 0;
}
static void lq(struct ring *r,int op,int flags,int fd,u64 addr,u32 len,u32 misc,u64 key) {
 struct sqe q;zero(&q,sizeof(q));q.op=op;q.flags=flags;q.fd=fd;q.addr=addr;q.len=len;q.misc=misc;q.ud=key;if(op==22||op==4)q.off=~0UL;queue(r,q,0);
}
static int lsubmit(struct ring *r,u32 n) { CHECK(sc(N_ENTER,r->fd,n,0,0,0,0)==n);return 0; }
static int lhealth(struct ring *r) { struct cqe c;lq(r,0,0,-1,0,0,0,999);CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==999&&c.res==0);CHECK(*r->ct==r->ci);return 0; }
static int links_success(void) {
 for(int hard=0;hard<2;hard++) {struct ring r;struct ltime t={1,0};struct cqe c[3];CHECK(init(&r,0,8)==0);
 lq(&r,0,hard?8:4,-1,0,0,0,1);lq(&r,15,4,-1,(u64)&t,1,0,2);lq(&r,0,0,-1,0,0,0,3);
 CHECK(lsubmit(&r,3)==0&&lget(&r,c,3)==0);CHECK(lresult(c,3,1,0)==0&&lresult(c,3,2,-CANCELED)==0&&lresult(c,3,3,0)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int links_expire(void) {
 for(int success=0;success<2;success++){struct ring r;struct ltime t={0,20000000};struct cqe c[3];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,4,fd[0],0,0,1,1);lq(&r,15,4,-1,(u64)&t,1,success?32:0,2);lq(&r,0,0,-1,0,0,0,3);
 CHECK(lsubmit(&r,3)==0&&lget(&r,c,3)==0);CHECK(lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-LTIME)==0&&lresult(c,3,3,-CANCELED)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_absolute(void) {
 for(int clock=0;clock<3;clock++){struct ring r;struct ltime t;struct cqe c[2];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 CHECK(CALL(LCLOCK,clock==2?0:LMONO,&t,0)==0); /* Already expired absolute time. */
 lq(&r,6,4,fd[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,1|(clock==1?4:clock==2?8:0),2);
 CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0);CHECK(lresult(c,2,1,-CANCELED)==0&&lresult(c,2,2,-LTIME)==0);CHECK(finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_invalid(void) {
 for(int mode=0;mode<18;mode++){struct ring r;struct ltime t={1,0};struct cqe c[2];struct sqe q;CHECK(init(&r,0,8)==0);
 if(mode!=0)lq(&r,0,4,-1,0,0,0,1);
 zero(&q,sizeof(q));q.op=15;q.fd=-1;q.addr=(u64)&t;q.len=1;q.ud=2;
 int want=22;if(mode==1)q.addr=0,want=14;if(mode==2)q.addr=1,want=14;
 if(mode==3)q.len=0;if(mode==4)q.len=2;if(mode==5)q.off=1;if(mode==6)q.buf=1;if(mode==7)q.fd2=1;
 if(mode==8)q.misc=12;if(mode==9)q.misc=0x80000000;if(mode==10)t.sec=-1;if(mode==11)t.nsec=-1;
 if(mode==12)q.flags=1;if(mode==13)q.personality=1;if(mode==14)q.misc=64;
 if(mode==15)q.misc=65;if(mode==16)t.nsec=1000000000;if(mode==17)t.sec=0x7fffffffffffffffL;
 queue(&r,q,0);u32 n=mode==0?1:2;CHECK(lsubmit(&r,n)==0&&lget(&r,c,n)==0);
 if(mode==12||mode==14||mode==16||mode==17){CHECK(lresult(c,n,1,0)==0&&lresult(c,n,2,-CANCELED)==0);}
 else {CHECK(lresult(c,n,2,-want)==0);if(mode!=0)CHECK(lresult(c,n,1,-CANCELED)==0);}
 CHECK(lhealth(&r)==0&&finish(&r)==0);}
 /* Fault across the timespec boundary, reject every unsupported flag
  * bit, and accept a timespec in read-only user memory. */
 for(int mode=0;mode<4;mode++){struct ring r;struct cqe c[2];CHECK(init(&r,0,8)==0);long mem=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(mem>0);struct ltime *t=(struct ltime *)(mem+(mode==0?4088:0));t->sec=1;t->nsec=0;
 if(mode==0)CHECK(CALL(N_MPROTECT,mem+4096,4096,0)==0);
 if(mode==1)CHECK(CALL(N_MPROTECT,mem,8192,0)==0);
 if(mode==2)CHECK(CALL(N_MPROTECT,mem,8192,1)==0);
 if(mode==3)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);
 lq(&r,0,4,-1,0,0,0,1);lq(&r,15,0,-1,(u64)t,1,0,2);
 CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0&&lresult(c,2,1,mode==2?0:-CANCELED)==0&&lresult(c,2,2,mode==2?-CANCELED:-14)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);if(mode!=3)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);}
 for(int bit=0;bit<32;bit++){u32 flag=1U<<bit;if(flag&(1|4|8|32|64|128))continue;struct ring r;struct cqe c[2];struct ltime t={1,0};CHECK(init(&r,0,8)==0);
 lq(&r,0,4,-1,0,0,0,1);lq(&r,15,0,-1,(u64)&t,1,flag,2);CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0&&lresult(c,2,1,-CANCELED)==0&&lresult(c,2,2,-22)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int links_cancel_target(void) {
 for(int poll=0;poll<2;poll++){struct ring r;struct ltime t={1,0},longt={30,0};struct cqe c[3];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,poll?6:11,4,poll?fd[0]:-1,poll?0:(u64)&longt,poll?0:1,poll?1:0,1);lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,2)==0);
 lq(&r,14,0,-1,1,0,0,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,3)==0);CHECK(lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-CANCELED)==0&&lresult(c,3,3,0)==0);
 lq(&r,14,0,-1,1,0,0,4);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].res==-2);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_cancel_timer(void) {
 for(int op=12;op<=14;op+=2){struct ring r;struct ltime t={1,0};struct cqe c[3];int fd[2];char x;CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,4,fd[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,2)==0);
 lq(&r,op,0,-1,2,0,0,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0);CHECK(lresult(c,1,3,-2)==0);
 lpause(40000000);CHECK(CALL(N_WRITE,fd[1],"X",1)==1);CHECK(lget(&r,c,2)==0&&lresult(c,2,1,1)==0&&lresult(c,2,2,-CANCELED)==0);CHECK(CALL(N_READ,fd[0],&x,1)==1&&x=='X');CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_remove_scope(void) {
 struct ring r;int fd[2];struct cqe c[3];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,0,fd[0],0,0,1,1);CHECK(lsubmit(&r,1)==0);lq(&r,12,0,-1,1,0,0,2);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].res==-2);
 for(int op=12;op<=14;op+=2){lq(&r,op,0,-1,1,0,0x80000000,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].res==-22);}
 lq(&r,14,0,-1,1,0,0,4);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,1,-CANCELED)==0&&lresult(c,2,4,0)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);return 0;
}
static int links_duplicates(void) {
 struct ring r;struct ltime t={0,10000000};struct cqe c[4];int a[2],b[2];CHECK(init(&r,0,8)==0&&bpipe(a,0)==0&&bpipe(b,0)==0);
 /* A different request deliberately has the same key as the deadline target. */
 lq(&r,6,0,a[0],0,0,1,1);lq(&r,6,4,b[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);
 CHECK(lsubmit(&r,3)==0&&lget(&r,c,2)==0);CHECK(lresult(c,2,1,-CANCELED)==0&&lresult(c,2,2,-LTIME)==0);
 CHECK(CALL(N_WRITE,a[1],"A",1)==1);CHECK(lget(&r,c,1)==0&&c[0].ud==1&&(c[0].res&1));CHECK(lhealth(&r)==0&&finish(&r)==0);
 CALL(N_CLOSE,a[0],0,0);CALL(N_CLOSE,a[1],0,0);CALL(N_CLOSE,b[0],0,0);CALL(N_CLOSE,b[1],0,0);return 0;
}
static int links_cancel_all(void) {
 struct ring r;struct cqe c[5];struct ltime t={30,0};int a[2],b[2];CHECK(init(&r,0,8)==0&&bpipe(a,0)==0&&bpipe(b,0)==0);
 lq(&r,6,0,a[0],0,0,1,1);lq(&r,6,0,b[0],0,0,1,1);lq(&r,11,0,-1,(u64)&t,1,0,1);CHECK(lsubmit(&r,3)==0);
 lq(&r,14,0,-1,1,0,1,2);CHECK(lsubmit(&r,1)==0&&lget(&r,c,4)==0);CHECK(lresult(c,4,2,3)==0);int count=0;for(int i=0;i<4;i++)if(c[i].ud==1&&c[i].res==-CANCELED)count++;CHECK(count==3);
 lq(&r,14,0,-1,1,0,1,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].res==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,a[0],0,0);CALL(N_CLOSE,a[1],0,0);CALL(N_CLOSE,b[0],0,0);CALL(N_CLOSE,b[1],0,0);return 0;
}
static int cancel_modes_shared(void) {
 /* FD matching is by file identity: a dup selects both requests, but not a
  * request on another pipe. */
 {struct ring r;struct cqe c[5];int a[2],b[2];CHECK(init(&r,0,8)==0&&bpipe(a,0)==0&&bpipe(b,0)==0);long d=CALL(N_DUP,a[0],0,0);CHECK(d>=0);
  lq(&r,6,0,a[0],0,0,1,11);lq(&r,6,0,d,0,0,1,12);lq(&r,6,0,b[0],0,0,1,13);CHECK(lsubmit(&r,3)==0);
  lq(&r,14,0,d,0,0,1|2,20);CHECK(lsubmit(&r,1)==0&&lget(&r,c,3)==0&&lresult(c,3,20,2)==0);int cc=0;for(int i=0;i<3;i++)if((c[i].ud==11||c[i].ud==12)&&c[i].res==-CANCELED)cc++;CHECK(cc==2);
  lq(&r,14,0,-1,0,0,4,21);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,21,1)==0&&lresult(c,2,13,-CANCELED)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);
  CALL(N_CLOSE,d,0,0);CALL(N_CLOSE,a[0],0,0);CALL(N_CLOSE,a[1],0,0);CALL(N_CLOSE,b[0],0,0);CALL(N_CLOSE,b[1],0,0);}
 /* Opcode selection and explicit user-data selection compose. */
 {struct ring r;struct cqe c[5];struct ltime t={30,0};int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
  lq(&r,11,0,-1,(u64)&t,1,0,31);lq(&r,11,0,-1,(u64)&t,1,0,32);lq(&r,6,0,fd[0],0,0,1,31);CHECK(lsubmit(&r,3)==0);
  lq(&r,14,0,-1,31,11,32|16,40);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,40,0)==0&&lresult(c,2,31,-CANCELED)==0);
  lq(&r,14,0,-1,0,11,32|1,41);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,41,1)==0&&lresult(c,2,32,-CANCELED)==0);
  lq(&r,14,0,-1,0,0,4,42);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,42,1)==0&&lresult(c,2,31,-CANCELED)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 /* FD_FIXED resolves a registered slot, then matches a normal-fd request
  * referring to the same open file. */
 {struct ring r;struct cqe c[2];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);CHECK(sc(N_REGISTER,r.fd,2,(long)&fd[0],1,0,0)==0);
  lq(&r,6,0,fd[0],0,0,1,51);CHECK(lsubmit(&r,1)==0);lq(&r,14,0,0,0,0,2|8,52);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,52,0)==0&&lresult(c,2,51,-CANCELED)==0);
  CHECK(sc(N_REGISTER,r.fd,3,0,0,0,0)==0&&lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}

static int file_alloc_range_shared(void) {
 struct ring r;struct lfile_range x={0,1,0};int fds[4]={-1,-1,-1,-1};CHECK(init(&r,0,8)==0);
 CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==-6); /* no file table */
 CHECK(sc(N_REGISTER,r.fd,25,0,0,0,0)==-22&&sc(N_REGISTER,r.fd,25,(long)&x,1,0,0)==-22&&sc(N_REGISTER,r.fd,25,1,0,0,0)==-14);
 CHECK(sc(N_REGISTER,r.fd,2,(long)fds,4,0,0)==0);x.off=1;x.len=2;CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==0);
 x.off=0xffffffffU;x.len=2;CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==-OVERFLOW);x.off=3;x.len=2;CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==-22);
 x.off=0;x.len=4;x.resv=1;CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==-22);x.off=2;x.len=0;x.resv=0;CHECK(sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==0);
 CHECK(sc(N_REGISTER,r.fd,3,0,0,0,0)==0&&sc(N_REGISTER,r.fd,25,(long)&x,0,0,0)==-6&&lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int sync_cancel_shared(void) {
 /* User-data and ALL return semantics, including target CQEs. */
 {struct ring r;struct cqe c[3];struct ltime t={30,0};struct lsync_cancel x;CHECK(init(&r,0,8)==0);
  lq(&r,11,0,-1,(u64)&t,1,0,11);CHECK(lsubmit(&r,1)==0);lsync_init(&x);x.addr=11;
  CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==0&&lget(&r,c,1)==0&&lresult(c,1,11,-CANCELED)==0);
  lq(&r,11,0,-1,(u64)&t,1,0,12);lq(&r,11,0,-1,(u64)&t,1,0,12);CHECK(lsubmit(&r,2)==0);
  lsync_init(&x);x.addr=12;x.flags=1;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==2&&lget(&r,c,2)==0);
  int cc=0;for(int i=0;i<2;i++)if(c[i].ud==12&&c[i].res==-CANCELED)cc++;CHECK(cc==2);
  lsync_init(&x);x.flags=4;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==0&&lhealth(&r)==0&&finish(&r)==0);}
 /* FD identity, opcode, and fixed-file lookup share the asynchronous matcher. */
 {struct ring r;struct cqe c[3];struct ltime t={30,0};struct lsync_cancel x;int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
  lq(&r,6,0,fd[0],0,0,1,21);lq(&r,11,0,-1,(u64)&t,1,0,22);CHECK(lsubmit(&r,2)==0);
  lsync_init(&x);x.fd=fd[0];x.flags=2;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==0);
  lsync_init(&x);x.opcode=11;x.flags=32|1;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==1);
  CHECK(lget(&r,c,2)==0&&lresult(c,2,21,-CANCELED)==0&&lresult(c,2,22,-CANCELED)==0);
  CHECK(sc(N_REGISTER,r.fd,2,(long)&fd[0],1,0,0)==0);lq(&r,6,0,fd[0],0,0,1,23);CHECK(lsubmit(&r,1)==0);
  lsync_init(&x);x.fd=0;x.flags=2|8;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==0&&lget(&r,c,1)==0&&lresult(c,1,23,-CANCELED)==0);
  CHECK(sc(N_REGISTER,r.fd,3,0,0,0,0)==0&&lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 /* Faults, reserved fields, unknown flags, descriptors, and missing keys must
  * fail before changing an unrelated armed request. */
 {struct ring r;struct cqe c;struct ltime t={30,0};struct lsync_cancel x;CHECK(init(&r,0,8)==0);lq(&r,11,0,-1,(u64)&t,1,0,31);CHECK(lsubmit(&r,1)==0);
  lsync_init(&x);x.addr=99;CHECK(sc(N_REGISTER,r.fd,24,0,1,0,0)==-22&&sc(N_REGISTER,r.fd,24,(long)&x,0,0,0)==-22&&sc(N_REGISTER,r.fd,24,(long)&x,2,0,0)==-22&&sc(N_REGISTER,r.fd,24,1,1,0,0)==-14&&sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-2);
  x.flags=0x80000000;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-22);lsync_init(&x);x.pad[6]=1;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-22);
  lsync_init(&x);x.pad2[0]=1;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-22);lsync_init(&x);x.fd=9999;x.flags=2;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-9);
  lsync_init(&x);x.fd=99;x.flags=2|8;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==-9);lsync_init(&x);x.addr=31;CHECK(sc(N_REGISTER,r.fd,24,(long)&x,1,0,0)==0&&lget(&r,&c,1)==0&&c.ud==31&&c.res==-CANCELED);
  CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}

static int poll_update_shared(void) {
 struct ring r;struct cqe c[4];struct sqe q;int fd[2];char x;
 CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 /* Replace user_data without completing the target. */
 lq(&r,6,0,fd[0],0,0,1,11);CHECK(lsubmit(&r,1)==0);
 zero(&q,sizeof(q));q.op=7;q.fd=-1;q.addr=11;q.off=12;q.len=4;q.ud=20;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,20,0)==0);
 CHECK(CALL(N_WRITE,fd[1],"A",1)==1&&lget(&r,c,1)==0&&c[0].ud==12&&(c[0].res&1));CHECK(CALL(N_READ,fd[0],&x,1)==1);
 /* Combined event/user_data update converts a single-shot poll to multishot. */
 lq(&r,6,0,fd[0],0,0,1,31);CHECK(lsubmit(&r,1)==0);
 zero(&q,sizeof(q));q.op=7;q.fd=-1;q.addr=31;q.off=32;q.len=1|2|4;q.misc=1;q.ud=40;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,40,0)==0);
 for(int n=0;n<2;n++){CHECK(CALL(N_WRITE,fd[1],"B",1)==1&&lget_any(&r,c,1)==0&&c[0].ud==32&&(c[0].res&1)&&(c[0].flags&2));CHECK(CALL(N_READ,fd[0],&x,1)==1);}
 lq(&r,7,0,-1,32,0,0,41);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,41,0)==0&&lresult(c,2,32,-CANCELED)==0);
 /* Invalid update flags do not disturb the original poll. */
 lq(&r,6,0,fd[0],0,0,1,51);CHECK(lsubmit(&r,1)==0);
 zero(&q,sizeof(q));q.op=7;q.fd=-1;q.addr=51;q.len=1;q.ud=52;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,52,-22)==0);
 zero(&q,sizeof(q));q.op=7;q.fd=-1;q.addr=51;q.off=99;q.ud=53;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,53,-22)==0);
 CHECK(CALL(N_WRITE,fd[1],"C",1)==1&&lget(&r,c,1)==0&&c[0].ud==51&&(c[0].res&1));
 CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);return 0;
}

static int poll_lifetime_shared(void) {
 for(int round=0;round<3;round++) {
  struct ring r;struct cqe c[2];int old[2],fresh[2];
  CHECK(init(&r,0,8)==0&&bpipe(old,0)==0);
  lq(&r,6,0,old[0],0,0,1,11);CHECK(lsubmit(&r,1)==0);
  CHECK(CALL(N_CLOSE,old[0],0,0)==0&&bpipe(fresh,0)==0&&fresh[0]==old[0]);
  CHECK(CALL(N_WRITE,fresh[1],"n",1)==1&&*r.ct==r.ci);
  CHECK(CALL(N_WRITE,old[1],"o",1)==1&&lget(&r,c,1)==0);
  CHECK(c[0].ud==11&&(c[0].res&1));
  CHECK(lhealth(&r)==0&&finish(&r)==0);
  CALL(N_CLOSE,old[1],0,0);CALL(N_CLOSE,fresh[0],0,0);CALL(N_CLOSE,fresh[1],0,0);
 }
 for(int round=0;round<3;round++) {
  struct ring r;struct cqe c[2];int old[2],fresh[2];
  CHECK(init(&r,0,8)==0&&bpipe(old,0)==0);
  lq(&r,6,0,old[0],0,0,1,21);CHECK(lsubmit(&r,1)==0);
  CHECK(CALL(N_CLOSE,old[0],0,0)==0&&bpipe(fresh,0)==0&&fresh[0]==old[0]);
  lq(&r,7,0,-1,21,0,0,22);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0);
  CHECK(lresult(c,2,22,0)==0&&lresult(c,2,21,-CANCELED)==0);
  CHECK(lhealth(&r)==0&&finish(&r)==0);
  CALL(N_CLOSE,old[1],0,0);CALL(N_CLOSE,fresh[0],0,0);CALL(N_CLOSE,fresh[1],0,0);
 }
 return 0;
}

/* Ring-target polls follow the ring context across fd reuse and last close. */
static int poll_ring_target_shared(void)
{
 struct ring source,target,fresh;struct cqe c;long dupfd,oldfd;
 struct ltime timeout={0,50000000};
 CHECK(init(&target,0,8)==0&&init(&source,0,8)==0);
 oldfd=target.fd;dupfd=CALL(N_DUP,target.fd,0,0);
 CHECK(dupfd>=0);
 lq(&source,6,0,target.fd,0,0,1,0x7650);
 CHECK(lsubmit(&source,1)==0&&CALL(N_CLOSE,target.fd,0,0)==0);
 target.fd=dupfd;
 CHECK(init(&fresh,0,8)==0&&fresh.fd==oldfd);
 CHECK(*source.ct==source.ci);
 lq(&target,0,0,-1,0,0,0,0x7651);
 CHECK(lsubmit(&target,1)==0&&lget(&source,&c,1)==0&&
     c.ud==0x7650&&(c.res&1)!=0);
 CHECK(lget(&target,&c,1)==0&&c.ud==0x7651&&c.res==0);
 CHECK(lhealth(&source)==0&&lhealth(&target)==0&&
     finish(&source)==0&&finish(&target)==0&&finish(&fresh)==0);

 CHECK(init(&target,0,8)==0&&init(&source,0,8)==0);
 lq(&source,6,0,target.fd,0,0,1,0x7652);
 CHECK(lsubmit(&source,1)==0);
 lq(&target,11,0,-1,(u64)&timeout,1,0,0x7653);
 CHECK(lsubmit(&target,1)==0&&CALL(N_CLOSE,target.fd,0,0)==0);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7652&&(c.res&1)!=0);
 CHECK(lhealth(&source)==0&&finish(&source)==0);
 CHECK(CALL(N_MUNMAP,target.mem,target.rlen,0)==0&&
     CALL(N_MUNMAP,target.sqes,target.slen,0)==0);
 return 0;
}

/* Closing a ring must release ring-target polls still behind links or drain. */
static int poll_ring_deferred_close_shared(void)
{
 struct ring r;struct ltime timeout={30,0};
 for(int mode=0;mode<3;mode++) {
  CHECK(init(&r,0,8)==0);
  if(mode==2) {
   lq(&r,11,0,-1,(u64)&timeout,1,0,0x7660);
   lq(&r,6,2,r.fd,0,0,1,0x7661);
  } else {
   lq(&r,11,mode==0?4:8,-1,(u64)&timeout,1,0,0x7660);
   lq(&r,6,0,r.fd,0,0,1,0x7661);
  }
  CHECK(lsubmit(&r,2)==0);
  CHECK(CALL(N_CLOSE,r.fd,0,0)==0);
  CHECK(CALL(N_MUNMAP,r.mem,r.rlen,0)==0&&
      CALL(N_MUNMAP,r.sqes,r.slen,0)==0);
 }
 /* An active worker may resolve after the last ring descriptor closes. */
 {struct ring worker;int fd[2];char data=0;
  CHECK(init(&worker,0,8)==0&&bpipe(fd,0)==0);
  lq(&worker,22,16|4,fd[0],(u64)&data,1,0,0x7662);
  lq(&worker,6,0,worker.fd,0,0,1,0x7663);
  CHECK(lsubmit(&worker,2)==0);
  lpause(50000000);
  CHECK(CALL(N_CLOSE,worker.fd,0,0)==0);
  CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0);
  CHECK(CALL(N_MUNMAP,worker.mem,worker.rlen,0)==0&&
      CALL(N_MUNMAP,worker.sqes,worker.slen,0)==0);
 }
 return 0;
}

/* A SQPOLL self-poll must not keep its ring alive after the last close. */
static int poll_ring_sqpoll_self_close_shared(void)
{
 struct ring r;
 CHECK(init(&r,SSQPOLL,8)==0);
 lq(&r,6,0,r.fd,0,0,1,0x7670);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 lpause(50000000);
 CHECK(CALL(N_CLOSE,r.fd,0,0)==0);
 CHECK(CALL(N_MUNMAP,r.mem,r.rlen,0)==0&&
     CALL(N_MUNMAP,r.sqes,r.slen,0)==0);
 return 0;
}

/* Linux 6.18 declares LEVEL but rejects it at POLL_ADD preparation. */
static int poll_level_rejected_shared(void) {
 struct ring r;struct cqe c;struct sqe q;int fd[2];char byte;
 CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 for(int i=0;i<3;i++){
  zero(&q,sizeof(q));q.op=6;q.fd=fd[0];q.misc=1;
  q.len=i==0?8:i==1?9:16;q.ud=10+i;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==q.ud&&c.res==-22);
 }
 /* Rejected update flags must not disarm an otherwise valid poll. */
 lq(&r,6,0,fd[0],0,0,1,21);CHECK(lsubmit(&r,1)==0);
 zero(&q,sizeof(q));q.op=7;q.fd=-1;q.addr=21;q.len=8|2;q.misc=1;q.ud=22;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==22&&c.res==-22);
 CHECK(CALL(N_WRITE,fd[1],"L",1)==1);
 CHECK(lget(&r,&c,1)==0&&c.ud==21&&(c.res&1));
 CHECK(CALL(N_READ,fd[0],&byte,1)==1&&byte=='L');
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0);
 return 0;
}
static int timeout_modes_shared(void) {
 /* A finite multishot timeout emits MORE on every nonterminal expiration. */
 {struct ring r;struct cqe c[4];struct ltime t={0,10000000};CHECK(init(&r,0,8)==0);lq(&r,11,0,-1,(u64)&t,1,64,3);r.sqes[(r.si-1)&(r.p.sq-1)].off=3;
  CHECK(lsubmit(&r,1)==0&&lget_any(&r,c,3)==0);int more=0,last=0;for(int i=0;i<3;i++){CHECK(c[i].ud==3&&c[i].res==-LTIME);if(c[i].flags&2)more++;else last++;}CHECK(more==2&&last==1&&lhealth(&r)==0&&finish(&r)==0);}
 /* Update a long timeout to a short relative deadline. */
 {struct ring r;struct cqe c[2];struct ltime a={30,0},b={0,10000000};struct sqe q;CHECK(init(&r,0,8)==0);lq(&r,11,0,-1,(u64)&a,1,0,11);CHECK(lsubmit(&r,1)==0);
  zero(&q,sizeof(q));q.op=12;q.fd=-1;q.addr=11;q.off=(u64)&b;q.misc=2;q.ud=12;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,12,0)==0);CHECK(lget(&r,c,1)==0&&lresult(c,1,11,-LTIME)==0&&lhealth(&r)==0&&finish(&r)==0);}
 /* A linked timeout can be updated independently of its predecessor. */
 {struct ring r;struct cqe c[3];struct ltime a={30,0},b={0,10000000};struct sqe q;int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);lq(&r,6,4,fd[0],0,0,1,21);lq(&r,15,0,-1,(u64)&a,1,0,22);CHECK(lsubmit(&r,2)==0);
  zero(&q,sizeof(q));q.op=12;q.fd=-1;q.addr=22;q.off=(u64)&b;q.misc=2|16;q.ud=23;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,3)==0&&lresult(c,3,23,0)==0&&lresult(c,3,21,-CANCELED)==0&&lresult(c,3,22,-LTIME)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 /* Bad update input and a missing key cannot alter the live timeout. */
 {struct ring r;struct cqe c[2];struct ltime a={30,0},bad={-1,0};struct sqe q;CHECK(init(&r,0,8)==0);lq(&r,11,0,-1,(u64)&a,1,0,31);CHECK(lsubmit(&r,1)==0);
  zero(&q,sizeof(q));q.op=12;q.fd=-1;q.addr=31;q.off=(u64)&bad;q.misc=2;q.ud=32;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,32,-22)==0);
  zero(&q,sizeof(q));q.op=12;q.fd=-1;q.addr=99;q.off=(u64)&a;q.misc=2;q.ud=33;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,33,-2)==0);
  lq(&r,12,0,-1,31,0,0,34);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,34,0)==0&&lresult(c,2,31,-CANCELED)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}

static int timeout_immediate_shared(void) {
 /* Both ABIs accept a nanosecond value directly and reject negative encoding. */
 {struct ring r;struct cqe c;CHECK(init(&r,0,8)==0);
  lq(&r,11,0,-1,20000000,1,128,1);
  CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==1&&c.res==-LTIME);
  lq(&r,11,0,-1,1ULL<<63,1,128,2);
  CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==2&&c.res==-22);
  CHECK(lhealth(&r)==0&&finish(&r)==0);}
 /* An immediate update must preserve the original request and key. */
 {struct ring r;struct cqe c[2];struct ltime longt={30,0};struct sqe q;
  CHECK(init(&r,0,8)==0);
  lq(&r,11,0,-1,(u64)&longt,1,0,11);CHECK(lsubmit(&r,1)==0);
  zero(&q,sizeof(q));q.op=12;q.fd=-1;q.addr=11;q.off=1ULL<<63;
  q.misc=2|128;q.ud=12;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,12,-22)==0);
  q.off=10000000;q.ud=13;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,13,0)==0);
  CHECK(lget(&r,c,1)==0&&lresult(c,1,11,-LTIME)==0);
  CHECK(lhealth(&r)==0&&finish(&r)==0);}
 /* The linked timeout cancels its predecessor; multishot has two MORE CQEs. */
 {struct ring r;struct cqe c[3];int fd[2];
  CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
  lq(&r,6,4,fd[0],0,0,1,21);
  lq(&r,15,0,-1,20000000,1,128,22);
  CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0);
  CHECK(lresult(c,2,21,-CANCELED)==0&&lresult(c,2,22,-LTIME)==0);
  lq(&r,11,0,-1,10000000,1,64|128,23);
  r.sqes[(r.si-1)&(r.p.sq-1)].off=3;
  CHECK(lsubmit(&r,1)==0&&lget_any(&r,c,3)==0);
  int more=0,last=0;
  for(int i=0;i<3;i++){CHECK(c[i].ud==23&&c[i].res==-LTIME);
   if(c[i].flags&2)more++;else last++;}
  CHECK(more==2&&last==1&&lhealth(&r)==0&&finish(&r)==0);
  CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0);}
 return 0;
}

static int timeout_reserved_shared(void) {
 struct ring r;struct cqe c[2];struct ltime t={1,0};struct sqe q;
 CHECK(init(&r,0,16)==0);
 /* TIMEOUT and TIMEOUT_REMOVE reserve both 64-bit extension slots.  For
  * updates the reserved-field error also precedes timespec pointer import. */
 for(int mode=0;mode<6;mode++){
  zero(&q,sizeof(q));q.op=mode<2?11:12;q.fd=-1;
  q.addr=mode<2?(u64)&t:0xdead;q.len=mode<2?1:0;
  if(mode>=4){q.off=1;q.misc=2;}
  if((mode&1)==0)q.addr3=1;else q.pad=1;
  q.ud=0x5100+mode;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&
      c[0].ud==q.ud&&c[0].res==-22);
 }
 /* LINK_TIMEOUT uses the same extension layout.  A malformed deadline
  * cancels its predecessor and completes itself with EINVAL. */
 for(int mode=0;mode<2;mode++){
  lq(&r,0,4,-1,0,0,0,0x5110+mode*2);
  zero(&q,sizeof(q));q.op=15;q.fd=-1;q.addr=(u64)&t;q.len=1;
  q.ud=0x5111+mode*2;if(mode==0)q.addr3=1;else q.pad=1;
  queue(&r,q,0);
  CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0&&
      lresult(c,2,q.ud-1,-CANCELED)==0&&
      lresult(c,2,q.ud,-22)==0);
 }
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 return 0;
}

static int links_worker(void) {
 for(int fixed=0;fixed<2;fixed++)for(int timer=0;timer<2;timer++){struct ring r;struct cqe c[3];struct ltime t={0,30000000};int fd[2];char data[8]={0};struct rwvec v={data,8};CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);if(fixed)CHECK(breg(&r,&v,1)==0);
 lq(&r,fixed?4:22,16|(timer?4:0),fd[0],(u64)data,4,0,1);if(timer)lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,timer?2:1)==0);
 if(!timer){lpause(10000000);lq(&r,14,0,-1,1,0,0,2);CHECK(lsubmit(&r,1)==0);}
 CHECK(lget(&r,c,2)==0);CHECK(lresult(c,2,1,-CANCELED)==0&&lresult(c,2,2,timer?-LTIME:0)==0);for(int i=0;i<8;i++)CHECK(data[i]==0);
 CHECK(CALL(N_WRITE,fd[1],"SAFE",4)==4);CHECK(CALL(N_READ,fd[0],data,4)==4);for(int i=0;i<4;i++)CHECK(data[i]=="SAFE"[i]);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_race(void) {
 for(int n=0;n<96;n++){struct ring r;struct ltime t={0,2000000};struct cqe c[2];int fd[2],status;CHECK(init(&r,n&1?NOARRAY:0,8)==0&&bpipe(fd,0)==0);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){lpause((n%3)*2000000);CALL(N_WRITE,fd[1],"X",1);CALL(N_EXIT,0,0,0);}
 lq(&r,6,4,fd[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0);
 int target=0,timer=0;for(int i=0;i<2;i++){if(c[i].ud==1)target=c[i].res;else if(c[i].ud==2)timer=c[i].res;else CHECK(0);}
 CHECK(target==-CANCELED||(target>0&&(target&1)));CHECK(timer==-CANCELED||timer==-LTIME||timer==-2||timer==-LALREADY);if(target==-CANCELED)CHECK(timer==-LTIME);CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}
static int links_close(void) {
 /* Create the ring in the child so exit, rather than an explicit close,
  * must release every private readiness note and pending request. */
 for(int mode=0;mode<4;mode++)for(int n=0;n<8;n++){int sync[2],status;char ack;CHECK(bpipe(sync,0)==0);long pid=fork_child();CHECK(pid>=0);
 if(pid==0){struct ring r;int fd[2];char data[4]={0};struct ltime t={30,0};struct cqe c[2];
  if(init(&r,0,8)!=0||bpipe(fd,0)!=0)CALL(N_EXIT,90,0,0);
  lq(&r,mode&1?22:6,4|(mode&1?16:0),fd[0],mode&1?(u64)data:0,mode&1?4:0,mode&1?0:1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);
  if(lsubmit(&r,2)!=0)CALL(N_EXIT,91,0,0);
  struct ltime zero_wait={0,0};struct {u64 sig;u32 sz,min;u64 ts;} wait_arg={0,0,0,(u64)&zero_wait};
  if(sc(N_ENTER,r.fd,0,1,1|8,(long)&wait_arg,sizeof(wait_arg))!=-LTIME)CALL(N_EXIT,94,0,0);
  if(mode>=2){lq(&r,14,0,-1,1,0,0,3);if(lsubmit(&r,1)!=0)CALL(N_EXIT,92,0,0);/* leave CQEs unread */}
  CALL(N_WRITE,sync[1],"R",1);
  if(mode<2)(void)lget(&r,c,2);
  /* Keep the child alive until the parent kills it, even under TCG load. */
  for(;;)lpause(1000000000);
 }
 CALL(N_CLOSE,sync[1],0,0);CHECK(CALL(N_READ,sync[0],&ack,1)==1&&ack=='R');lpause(20000000);CHECK(CALL(N_KILL,pid,9,0)==0);CHECK(CALL(N_WAIT,pid,&status,0)==pid&&(status&127)==9);CALL(N_CLOSE,sync[0],0,0);}

 for(int worker=0;worker<2;worker++)for(int n=0;n<32;n++){struct ring r;struct ltime t={0,1000000};int fd[2];char data[4]={0};CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,worker?22:6,4|(worker?16:0),fd[0],worker?(u64)data:0,worker?4:0,worker?0:1,1);lq(&r,15,4,-1,(u64)&t,1,0,2);lq(&r,0,0,-1,0,0,0,3);
 CHECK(lsubmit(&r,3)==0);lq(&r,0,2,-1,0,0,0,4);CHECK(lsubmit(&r,1)==0);CHECK(finish(&r)==0);lpause(2000000);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}

static int links_hardlink(void) {
 struct ring r;struct ltime t={0,10000000};struct cqe c[3];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,8,fd[0],0,0,1,1);lq(&r,15,4,-1,(u64)&t,1,0,2);lq(&r,0,0,-1,0,0,0,3);
 CHECK(lsubmit(&r,3)==0&&lget(&r,c,3)==0);CHECK(lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-LTIME)==0&&lresult(c,3,3,0)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);return 0;
}
static int links_deferred(void) {
 struct ring r;struct ltime t={0,10000000};struct cqe c[3];int a[2],b[2];CHECK(init(&r,0,8)==0&&bpipe(a,0)==0&&bpipe(b,0)==0);
 lq(&r,6,4,a[0],0,0,1,9);lq(&r,6,4,b[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,3)==0);
 t.sec=30;t.nsec=0;lpause(30000000);CHECK(*r.ct==r.ci);CHECK(CALL(N_WRITE,a[1],"A",1)==1);
 CHECK(lget(&r,c,3)==0);CHECK(lresult(c,3,9,1)==0&&lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-LTIME)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);
 CALL(N_CLOSE,a[0],0,0);CALL(N_CLOSE,a[1],0,0);CALL(N_CLOSE,b[0],0,0);CALL(N_CLOSE,b[1],0,0);return 0;
}
static int links_rollback(void) {
 for(int mode=0;mode<5;mode++){struct ring r;struct ltime t={1,0};struct cqe c[4];struct sqe q;char path[]="link-rollback0";path[13]+=(char)mode;
 long fd=sc(N_OPENAT,-100,(long)path,OPENFLAGS,0600,0,0);CHECK(fd>=0&&init(&r,0,8)==0);
 lq(&r,23,4,fd,(u64)"BAD",3,0,1);zero(&q,sizeof(q));q.op=15;q.fd=-1;q.addr=(u64)&t;q.len=1;q.flags=4;q.ud=2;
 if(mode==0)q.addr=1;if(mode==1)q.len=0;if(mode==2)q.misc=12;if(mode==3)t.sec=-1;queue(&r,q,0);
 if(mode==4){q.flags=4;q.ud=4;queue(&r,q,0);}lq(&r,23,0,fd,(u64)"BAD",3,0,3);
 u32 n=mode==4?4:3;CHECK(lsubmit(&r,n)==0&&lget(&r,c,n)==0);CHECK(lresult(c,n,1,-CANCELED)==0&&lresult(c,n,3,-CANCELED)==0);
 CHECK(lresult(c,n,mode==4?4:2,mode==0?-14:-22)==0);if(mode==4)CHECK(lresult(c,n,2,-CANCELED)==0);
 char x;CHECK(CALL(N_READ,fd,&x,1)==0);CHECK(lhealth(&r)==0&&finish(&r)==0&&CALL(N_CLOSE,fd,0,0)==0);}
 return 0;
}
static int links_queued(void) {
 struct ring r;struct cqe c[32];int fd[2];char data[24]={0};CHECK(init(&r,0,64)==0&&bpipe(fd,0)==0);
 for(int n=0;n<24;n++)lq(&r,22,16,fd[0],(u64)&data[n],1,0,1);
 CHECK(lsubmit(&r,24)==0);lpause(10000000);lq(&r,14,0,-1,1,0,1,2);CHECK(lsubmit(&r,1)==0&&lget(&r,c,25)==0);
 int count=0;for(int n=0;n<25;n++){if(c[n].ud==1){CHECK(c[n].res==-CANCELED);count++;}else CHECK(c[n].ud==2&&c[n].res>0&&c[n].res<=24);}CHECK(count==24);
 for(int n=0;n<24;n++)CHECK(data[n]==0);CHECK(CALL(N_WRITE,fd[1],"Z",1)==1&&CALL(N_READ,fd[0],data,1)==1&&data[0]=='Z');CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);return 0;
}

static int links_poll_reuse(void) {
 for(int n=0;n<32;n++){struct ring r;struct cqe c[4];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,0,fd[0],0,0,1,1);lq(&r,6,0,fd[0],0,0,1,2);CHECK(lsubmit(&r,2)==0);
 lq(&r,14,0,-1,1,0,0,4);lq(&r,6,0,fd[0],0,0,1,3);CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0);CHECK(lresult(c,2,1,-CANCELED)==0&&lresult(c,2,4,0)==0);
 CHECK(CALL(N_WRITE,fd[1],"X",1)==1&&lget(&r,c,2)==0&&lresult(c,2,2,1)==0&&lresult(c,2,3,1)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 /* Retire the newest subscriber without registering a replacement.  The
  * shared knote must still deliver readiness to the surviving request. */
 for(int n=0;n<32;n++){struct ring r;struct cqe c[2];int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,0,fd[0],0,0,1,1);lq(&r,6,0,fd[0],0,0,1,2);CHECK(lsubmit(&r,2)==0);
 lq(&r,14,0,-1,2,0,0,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,2,-CANCELED)==0&&lresult(c,2,3,0)==0);
 CHECK(CALL(N_WRITE,fd[1],"X",1)==1&&lget(&r,c,1)==0&&c[0].ud==1&&(c[0].res&1));CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 /* A waiter scans while another process registers an already-readable
  * target.  Readiness must not disappear before request publication. */
 for(int n=0;n<64;n++){struct ring r;struct cqe c[2];int a[2],b[2],status;CHECK(init(&r,0,8)==0&&bpipe(a,0)==0&&bpipe(b,0)==0);
 lq(&r,6,0,a[0],0,0,1,1);CHECK(lsubmit(&r,1)==0);CHECK(CALL(N_WRITE,b[1],"X",1)==1);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){lpause(1000000);lq(&r,6,0,b[0],0,0,1,2);int rc=lsubmit(&r,1);CALL(N_EXIT,rc!=0,0,0);}
 CHECK(lget(&r,c,1)==0&&c[0].ud==2&&(c[0].res&1));CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);r.si=*r.st;
 lq(&r,14,0,-1,1,0,0,3);CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,1,-CANCELED)==0&&lresult(c,2,3,0)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,a[0],0,0);CALL(N_CLOSE,a[1],0,0);CALL(N_CLOSE,b[0],0,0);CALL(N_CLOSE,b[1],0,0);}
 return 0;
}
static int links_cancel_race(void) {
 for(int n=0;n<72;n++){struct ring r;struct ltime t={0,10000000};struct cqe c[4];int fd[2],status;CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);
 lq(&r,6,4,fd[0],0,0,1,1);lq(&r,15,0,-1,(u64)&t,1,0,2);CHECK(lsubmit(&r,2)==0);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){lpause((n%3)*8000000);lq(&r,14,0,-1,1,0,0,3);lq(&r,14,0,-1,1,0,0,4);int rc=lsubmit(&r,2);CALL(N_EXIT,rc!=0,0,0);}
 if(n%4==0)CHECK(CALL(N_WRITE,fd[1],"X",1)==1);
 CHECK(lget(&r,c,4)==0);int target=0,timer=0,cancel=99,again=99;u32 seen=0;
 for(int i=0;i<4;i++){CHECK(c[i].ud>=1&&c[i].ud<=4);CHECK((seen&(1U<<c[i].ud))==0);seen|=1U<<c[i].ud;if(c[i].ud==1)target=c[i].res;if(c[i].ud==2)timer=c[i].res;if(c[i].ud==3)cancel=c[i].res;if(c[i].ud==4)again=c[i].res;}
 CHECK(cancel==0||cancel==-2||cancel==-LALREADY);
 CHECK(again==0||again==-2||again==-LALREADY);
 CHECK(target==1||target==-CANCELED);
 CHECK(timer==-CANCELED||timer==-LTIME||timer==-2||timer==-LALREADY);
 if(n%4!=0)CHECK(target==-CANCELED);
 if(target==-CANCELED&&timer==-CANCELED)CHECK(cancel==0||again==0);
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);r.si=*r.st;CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}

static int links_io(void) {
 for(int mode=0;mode<3;mode++){struct ring r;struct ltime t={0,10000000};struct cqe c[2];int fd[2];char data[4]={0};struct rwvec v={data,4};CHECK(init(&r,0,8)==0&&bpipe(fd,mode==2)==0);
 if(mode==1)CHECK(sc(N_REGISTER,r.fd,2,(long)&fd[0],1,0,0)==0);if(mode==2)CHECK(breg(&r,&v,1)==0);
 lq(&r,mode==2?4:22,4|(mode==1?1:0),mode==1?0:fd[0],(u64)data,4,0,1);lq(&r,15,0,-1,(u64)&t,1,0,2);
 CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0&&lresult(c,2,1,-CANCELED)==0&&lresult(c,2,2,-LTIME)==0);for(int n=0;n<4;n++)CHECK(data[n]==0);
 CHECK(CALL(N_WRITE,fd[1],"KEEP",4)==4&&CALL(N_READ,fd[0],data,4)==4);for(int n=0;n<4;n++)CHECK(data[n]=="KEEP"[n]);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);}
 return 0;
}

static int links_queue_isolation(void) {
 struct ring r;struct cqe c[12];int fd[2];char data[9]={0};CHECK(init(&r,0,32)==0&&bpipe(fd,0)==0);
 /* Fill the BSD pool with unrelated work before canceling only the ninth. */
 for(int n=0;n<8;n++){lq(&r,22,16,fd[0],(u64)&data[n],1,0,1);CHECK(lsubmit(&r,1)==0);lpause(10000000);}
 lq(&r,22,16,fd[0],(u64)&data[8],1,0,9);CHECK(lsubmit(&r,1)==0);lq(&r,14,0,-1,9,0,0,10);CHECK(lsubmit(&r,1)==0);
 CHECK(lget(&r,c,2)==0&&lresult(c,2,9,-CANCELED)==0);int cr=99;for(int j=0;j<2;j++)if(c[j].ud==10)cr=c[j].res;CHECK(cr==0);CHECK(*r.ct==r.ci);
 lq(&r,14,0,-1,1,0,1,11);CHECK(lsubmit(&r,1)==0&&lget(&r,c,9)==0);int count=0;for(int n=0;n<9;n++){if(c[n].ud==1){CHECK(c[n].res==-CANCELED);count++;}else CHECK(c[n].ud==11&&c[n].res>0&&c[n].res<=8);}CHECK(count==8);
 for(int n=0;n<9;n++)CHECK(data[n]==0);CHECK(lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[0],0,0);CALL(N_CLOSE,fd[1],0,0);return 0;
}

/* Setup policy and restriction lifecycle, shared by native and Linux APIs. */
#define SDIS 64U
#define SALL 128U
#define SONE 4096U
#ifdef LINUX_ABI
#define BADSTATE 77
#define N_EXEC NR(59,221)
#else
#include <pthread.h>
#define BADSTATE EBADF
#define N_EXEC SYS_execve
#endif
struct srestriction { unsigned short type;unsigned char value,resv;u32 pad[3]; };
_Static_assert(sizeof(struct srestriction)==16,"restriction ABI");
static long sregfd(long fd,u32 op,void *p,u32 n) { return sc(N_REGISTER,fd,op,(long)p,n,0,0); }
static long sreg(struct ring *r,u32 op,void *p,u32 n) { return sregfd(r->fd,op,p,n); }

/* Re-map the successful replacement; a failed resize must leave r intact. */
static int resize_remap(struct ring *r,struct params *p)
{
 long m;
 CHECK(CALL(N_MUNMAP,r->mem,r->rlen,0)==0);
 CHECK(CALL(N_MUNMAP,r->sqes,r->slen,0)==0);
 if (!(p->flags&NOARRAY))
  p->so.field6=p->co.field5+p->cq*sizeof(struct cqe)*((p->flags&SCQE32)?2:1);
 r->p=*p;
 r->rlen=p->co.field5+(u64)p->cq*sizeof(struct cqe)*((p->flags&SCQE32)?2:1);
 if (!(p->flags&NOARRAY) && r->rlen<p->so.field6+(u64)p->sq*4)
  r->rlen=p->so.field6+(u64)p->sq*4;
 r->slen=(u64)p->sq*sizeof(struct sqe)*((p->flags&SSQE128)?2:1);
 m=sc(N_MMAP,0,r->rlen,3,1,r->fd,0);CHECK(m>=0);r->mem=(char *)m;
 m=sc(N_MMAP,0,r->slen,3,1,r->fd,0x10000000);CHECK(m>=0);r->sqes=(struct sqe *)m;
 r->sh=(u32 *)(r->mem+p->so.head);r->st=(u32 *)(r->mem+p->so.tail);
 r->sf=(u32 *)(r->mem+p->so.field4);r->ct=(u32 *)(r->mem+p->co.tail);
 r->ch=(u32 *)(r->mem+p->co.head);r->cf=(u32 *)(r->mem+p->co.field6);
 r->cqes=(struct cqe *)(r->mem+p->co.field5);
 r->array=(p->flags&NOARRAY)?0:(u32 *)(r->mem+p->so.field6);
 return 0;
}
static void resize_want(struct params *p,u32 sq,u32 cq)
{
 zero(p,sizeof(*p));p->sq=sq;p->cq=cq;p->flags=8;
}
static int resize_requires_defer_shared(void)
{
 struct ring r;struct params p;CHECK(init(&r,0,4)==0);
 resize_want(&p,8,16);CHECK(sreg(&r,33,&p,1)==-22);
 CHECK(*r.sh==0&&*r.ct==0);return finish(&r);
}
static int resize_invalid_shared(void)
{
 struct ring r;struct params p;CHECK(init(&r,SONE|SDEFER,4)==0);
 resize_want(&p,8,16);
 CHECK(sreg(&r,33,0,1)==-22&&sreg(&r,33,&p,0)==-22&&
     sreg(&r,33,&p,2)==-22&&sreg(&r,33,(void *)1,1)==-14);
 p.flags|=SONE;CHECK(sreg(&r,33,&p,1)==-22);
 resize_want(&p,0,16);CHECK(sreg(&r,33,&p,1)==-22);
 resize_want(&p,8,1);CHECK(sreg(&r,33,&p,1)==-22);
 CHECK(*r.sh==0&&*r.ct==0);return finish(&r);
}
static int resize_empty_shared(void)
{
 struct ring r;struct params p;struct sqe q;int pipefd[2];CHECK(init(&r,SONE|SDEFER,4)==0&&bpipe(pipefd,0)==0);
 resize_want(&p,8,16);CHECK(sreg(&r,33,&p,1)==0&&p.sq==8&&p.cq==16);
 CHECK(CALL(N_WRITE,pipefd[1],r.mem,4)==4);
 CHECK(CALL(N_WRITE,pipefd[1],r.sqes,4)==4);
 CHECK(resize_remap(&r,&p)==0&&*r.sh==0&&*r.ct==0);
 zero(&q,sizeof(q));q.ud=100;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,100,0)==0);
 resize_want(&p,2,4);CHECK(sreg(&r,33,&p,1)==0&&p.sq==2&&p.cq==4);
 CHECK(resize_remap(&r,&p)==0);q.ud=101;queue(&r,q,0);
 CHECK(flush(&r,1)==0);
 CHECK(reap(&r,101,0)==0);CHECK(CALL(N_CLOSE,pipefd[0],0,0)==0&&CALL(N_CLOSE,pipefd[1],0,0)==0);return finish(&r);
}
static int resize_pending_shared(int cqcase)
{
 struct ring r;struct params p;struct sqe q;u32 n=cqcase?4:3;
 CHECK(init(&r,SONE|SDEFER,4)==0);zero(&q,sizeof(q));
 for(u32 i=0;i<n;i++){q.ud=200+i;queue(&r,q,0);}
 if(cqcase)CHECK(flush(&r,n)==0);
 resize_want(&p,2,cqcase?2:4);
 CHECK(sreg(&r,33,&p,1)==-OVERFLOW);
 CHECK(*r.sh==(cqcase?n:0)&&*r.st==n&&r.p.sq==4);
 if(!cqcase)CHECK(flush(&r,n)==0);
 for(u32 i=0;i<n;i++)CHECK(reap(&r,200+i,0)==0);
 resize_want(&p,2,4);CHECK(sreg(&r,33,&p,1)==0&&resize_remap(&r,&p)==0);
 q.ud=300;queue(&r,q,0);
 CHECK(flush(&r,1)==0);
 CHECK(reap(&r,300,0)==0);
 return finish(&r);
}
static int resize_pending_sq_shared(void){return resize_pending_shared(0);}
static int resize_pending_cq_shared(void){return resize_pending_shared(1);}
static int resize_mapping_lifetime_shared(void)
{
 struct ring r;struct params p;int ready[2],ack[2],status;char b;
 CHECK(init(&r,SONE|SDEFER,4)==0&&bpipe(ready,0)==0&&bpipe(ack,0)==0);
 long pid=fork_child();CHECK(pid>=0);
 if(pid==0){
  CALL(N_CLOSE,r.fd,0,0);CALL(N_CLOSE,ready[1],0,0);CALL(N_CLOSE,ack[0],0,0);
  for(int phase=0;phase<2;phase++){
   if(CALL(N_READ,ready[0],&b,1)!=1)CALL(N_EXIT,10+phase,0,0);
   u32 entries=*(volatile u32 *)(r.mem+r.p.so.entries);
   if(entries!=4)CALL(N_EXIT,20+phase,0,0);
   b='K';if(CALL(N_WRITE,ack[1],&b,1)!=1)CALL(N_EXIT,30+phase,0,0);
  }
  CALL(N_MUNMAP,r.mem,r.rlen,0);CALL(N_MUNMAP,r.sqes,r.slen,0);
  CALL(N_CLOSE,ready[0],0,0);CALL(N_CLOSE,ack[1],0,0);CALL(N_EXIT,0,0,0);
 }
 CHECK(CALL(N_CLOSE,ready[0],0,0)==0&&CALL(N_CLOSE,ack[1],0,0)==0);
 resize_want(&p,8,16);CHECK(sreg(&r,33,&p,1)==0);
 b='R';CHECK(CALL(N_WRITE,ready[1],&b,1)==1&&CALL(N_READ,ack[0],&b,1)==1&&b=='K');
 CHECK(CALL(N_MUNMAP,r.mem,r.rlen,0)==0&&CALL(N_MUNMAP,r.sqes,r.slen,0)==0);
 CHECK(CALL(N_CLOSE,r.fd,0,0)==0);
 b='C';CHECK(CALL(N_WRITE,ready[1],&b,1)==1&&CALL(N_READ,ack[0],&b,1)==1&&b=='K');
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 CHECK(CALL(N_CLOSE,ready[1],0,0)==0&&CALL(N_CLOSE,ack[0],0,0)==0);
 return 0;
}
static int resize_mmap_race_shared(void)
{
 struct ring r;struct params p;struct sqe q;int sync[2],status;char b='S';
 CHECK(init(&r,SONE|SDEFER,4)==0&&bpipe(sync,0)==0);
 long pid=fork_child();CHECK(pid>=0);
 if(pid==0){
  CALL(N_CLOSE,sync[1],0,0);if(CALL(N_READ,sync[0],&b,1)!=1)CALL(N_EXIT,10,0,0);
  for(int n=0;n<512;n++){
   long m=sc(N_MMAP,0,4096,3,1,r.fd,0);
   long s=sc(N_MMAP,0,4096,3,1,r.fd,0x10000000);
   if(m<0||s<0)CALL(N_EXIT,11,0,0);
   u32 entries=*(volatile u32 *)(m+r.p.so.entries);
   if(entries!=4&&entries!=8)CALL(N_EXIT,12,0,0);
   if(CALL(N_MUNMAP,m,4096,0)!=0||CALL(N_MUNMAP,s,4096,0)!=0)
    CALL(N_EXIT,13,0,0);
  }
  CALL(N_CLOSE,r.fd,0,0);CALL(N_CLOSE,sync[0],0,0);CALL(N_EXIT,0,0,0);
 }
 CHECK(CALL(N_CLOSE,sync[0],0,0)==0&&CALL(N_WRITE,sync[1],&b,1)==1);
 for(int n=0;n<64;n++){
  resize_want(&p,(n&1)?4:8,(n&1)?8:16);
  CHECK(sreg(&r,33,&p,1)==0&&p.sq==((n&1)?4U:8U));
 }
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 CHECK(CALL(N_CLOSE,sync[1],0,0)==0);
 CHECK(resize_remap(&r,&p)==0);zero(&q,sizeof(q));q.ud=500;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,500,0)==0);return finish(&r);
}
static int resize_clamp_shared(void)
{
 struct ring r;struct params p;struct sqe q;CHECK(init(&r,SONE|SDEFER,4)==0);
 resize_want(&p,32769,65537);CHECK(sreg(&r,33,&p,1)==-22);
 CHECK(*r.sh==0&&*r.ct==0);
 resize_want(&p,32769,65537);p.flags|=16;
 CHECK(sreg(&r,33,&p,1)==0&&p.sq==32768&&p.cq==65536);
 CHECK(resize_remap(&r,&p)==0);zero(&q,sizeof(q));q.ud=600;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,600,0)==0);return finish(&r);
}
static int resize_layout_shared(void)
{
 struct ring r;struct params p;struct sqe q;
 CHECK(init(&r,SONE|SDEFER|NOARRAY|SSQE128|SCQE32,4)==0);
 resize_want(&p,8,16);CHECK(sreg(&r,33,&p,1)==0);
 CHECK(p.sq==8&&p.cq==16&&(p.flags&(NOARRAY|SSQE128|SCQE32))==
     (NOARRAY|SSQE128|SCQE32));
 CHECK(resize_remap(&r,&p)==0&&r.array==0);
 zero(&q,sizeof(q));q.ud=700;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,700,0)==0);return finish(&r);
}
static int resize_worker_completion_shared(void)
{
 struct ring r;struct params p;struct cqe c;int fd[2];char data=0;
 CHECK(init(&r,SONE|SDEFER,4)==0&&bpipe(fd,0)==0);
 lq(&r,22,16,fd[0],(u64)&data,1,0,800);
 CHECK(lsubmit(&r,1)==0&&*r.ct==r.ci);
 resize_want(&p,8,16);CHECK(sreg(&r,33,&p,1)==0);
 CHECK(resize_remap(&r,&p)==0);
 CHECK(CALL(N_WRITE,fd[1],"W",1)==1);
 CHECK(lget(&r,&c,1)==0&&c.ud==800&&c.res==1&&data=='W');
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0);
 return 0;
}
static int resize_fault_rollback_shared(void)
{
 struct ring r;struct sqe q;long m;
 CHECK(init(&r,SONE|SDEFER,4)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);
 resize_want((struct params *)m,8,16);
 CHECK(CALL(N_MPROTECT,m,4096,1)==0);
 CHECK(sreg(&r,33,(void *)m,1)==-14);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0);
 zero(&q,sizeof(q));q.ud=400;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,400,0)==0);
 return finish(&r);
}
static int nommap_shared(void)
{
 struct ring r;struct params p;struct sqe q;long mem,sqes,fd;
 mem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
 sqes=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
 CHECK(mem>=0&&sqes>=0);
 zero(&p,sizeof(p));p.flags=SNOMMAP;
 p.so.addr=sqes;p.co.addr=mem;
 p.so.addr=0;CHECK(CALL(N_SETUP,4,&p,0)==-14);p.so.addr=sqes;
 p.co.addr=0;CHECK(CALL(N_SETUP,4,&p,0)==-14);p.co.addr=mem;
 p.so.addr=sqes+1;CHECK(CALL(N_SETUP,4,&p,0)==-22);
 p.so.addr=sqes;p.co.addr=mem+1;CHECK(CALL(N_SETUP,4,&p,0)==-22);
 p.co.addr=mem;
 CHECK(CALL(N_MPROTECT,mem,65536,1)==0);
 CHECK(CALL(N_SETUP,4,&p,0)==-14);
 CHECK(CALL(N_MPROTECT,mem,65536,3)==0);
 CHECK(CALL(N_MPROTECT,sqes,65536,1)==0);
 CHECK(CALL(N_SETUP,4,&p,0)==-14);
 CHECK(CALL(N_MPROTECT,sqes,65536,3)==0);
 zero(&r,sizeof(r));r.p=p;r.mem=(char *)mem;r.sqes=(struct sqe *)sqes;
 r.rlen=65536;r.slen=65536;
 fd=CALL(N_SETUP,4,&r.p,0);CHECK(fd>=0);r.fd=fd;
 CHECK(r.p.sq==4&&r.p.cq==8&&r.p.so.addr==(u64)sqes&&r.p.co.addr==(u64)mem);
 r.sh=(u32 *)(r.mem+r.p.so.head);r.st=(u32 *)(r.mem+r.p.so.tail);
 r.ch=(u32 *)(r.mem+r.p.co.head);r.ct=(u32 *)(r.mem+r.p.co.tail);
 r.cqes=(struct cqe *)(r.mem+r.p.co.field5);
 r.array=(u32 *)(r.mem+r.p.so.field6);
 zero(&q,sizeof(q));q.ud=0x1234;queue(&r,q,0);
 CHECK(flush(&r,1)==0&&reap(&r,0x1234,0)==0);
 CHECK(sc(N_MMAP,0,4096,3,1,r.fd,0)==-BADMAP_ERROR);
 CHECK(sc(N_MMAP,0,4096,3,1,r.fd,0x10000000)==-BADMAP_ERROR);
 CHECK(finish(&r)==0);return 0;
}
struct nommap_ring_update {u32 offset,resv;u64 data;};
static int nommap_fdonly_shared(void)
{
 struct params p;struct nommap_ring_update up;long mem,sqes,idx;
 mem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
 sqes=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
 CHECK(mem>=0&&sqes>=0);
 zero(&p,sizeof(p));p.flags=1U<<15;
 CHECK(CALL(N_SETUP,4,&p,0)==-22);
 p.flags=SNOMMAP|(1U<<15);p.so.addr=sqes;p.co.addr=mem;
 idx=CALL(N_SETUP,4,&p,0);CHECK(idx>=0&&idx<16);
 CHECK(sc(N_ENTER,idx,0,0,1U<<4,0,0)==0);
 zero(&up,sizeof(up));up.offset=idx;
 CHECK(sc(N_REGISTER,idx,21U|(1U<<31),(long)&up,1,0,0)==1);
 CHECK(sc(N_ENTER,idx,0,0,1U<<4,0,0)==-9);
 CHECK(CALL(N_MUNMAP,mem,65536,0)==0);
 CHECK(CALL(N_MUNMAP,sqes,65536,0)==0);
 return 0;
}
struct pregion_desc { u64 user_addr,size;u32 flags,id;u64 mmap_offset,resv[4]; };
struct pregion_reg { u64 region_uptr,flags,resv[2]; };
struct pregion_wait { struct {long sec,nsec;} ts;u32 min_wait_usec,flags;u64 sigmask;u32 sigmask_sz,pad[3];u64 pad2[2]; };
_Static_assert(sizeof(struct pregion_desc)==64,"parameter region descriptor ABI");
_Static_assert(sizeof(struct pregion_wait)==64,"registered wait ABI");
#define PARAM_OFF 0x20000000ULL
#define PARAM_ENTER_FLAGS (1U|8U|64U)
static void param_want(struct pregion_reg *reg,struct pregion_desc *desc,u64 flags)
{
 zero(reg,sizeof(*reg));zero(desc,sizeof(*desc));reg->region_uptr=(u64)desc;reg->flags=flags;desc->size=4096;
}
static int param_region_mmap_shared(void)
{
 struct ring r;struct pregion_reg reg;struct pregion_desc desc;long m;struct sqe q;
 CHECK(init(&r,0,4)==0);param_want(&reg,&desc,0);
 CHECK(sreg(&r,34,&reg,1)==0&&desc.mmap_offset==PARAM_OFF&&desc.id==0);
 CHECK(sreg(&r,34,&reg,1)==-16);
 m=sc(N_MMAP,0,4096,3,1,r.fd,desc.mmap_offset);CHECK(m>=0);
 ((volatile u64 *)m)[0]=0x12345678abcdef00ULL;
 ((volatile u64 *)m)[511]=0xfedcba8765432100ULL;
 zero(&q,sizeof(q));q.ud=11;queue(&r,q,0);CHECK(flush(&r,1)==0&&reap(&r,11,0)==0);
 CHECK(finish(&r)==0);
 CHECK(((volatile u64 *)m)[0]==0x12345678abcdef00ULL&&((volatile u64 *)m)[511]==0xfedcba8765432100ULL);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0);return 0;
}
static int param_region_invalid_shared(void)
{
 struct ring r;struct pregion_reg reg;struct pregion_desc desc;long m;
 CHECK(init(&r,0,4)==0);param_want(&reg,&desc,0);
 CHECK(sreg(&r,34,0,1)==-22&&sreg(&r,34,&reg,0)==-22&&sreg(&r,34,&reg,2)==-22);
 reg.region_uptr=1;CHECK(sreg(&r,34,&reg,1)==-14);param_want(&reg,&desc,0);
 reg.resv[0]=1;CHECK(sreg(&r,34,&reg,1)==-22);param_want(&reg,&desc,0);
 desc.flags=1;CHECK(sreg(&r,34,&reg,1)==-14);param_want(&reg,&desc,0);
 desc.size=1;CHECK(sreg(&r,34,&reg,1)==-22);param_want(&reg,&desc,0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);
 param_want(&reg,(struct pregion_desc *)m,0);
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,34,&reg,1)==-14);
 CHECK(CALL(N_MPROTECT,m,4096,3)==0&&sreg(&r,34,&reg,1)==0);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0);
 return finish(&r);
}
static int param_region_wait_shared(void)
{
 struct ring r;struct pregion_reg reg;struct pregion_desc desc;
 struct pregion_wait *w;long m;
 CHECK(init(&r,SDIS,4)==0);param_want(&reg,&desc,1);
 CHECK(sreg(&r,34,&reg,1)==0&&desc.mmap_offset==PARAM_OFF);
 m=sc(N_MMAP,0,4096,3,1,r.fd,PARAM_OFF);CHECK(m>=0);w=(void *)m;
 zero(w,sizeof(*w));w->flags=1;w->ts.nsec=1000000;
 CHECK(sreg(&r,12,0,0)==0);
 CHECK(sc(N_ENTER,r.fd,0,1,PARAM_ENTER_FLAGS,0,sizeof(*w))==-LTIME);
 CHECK(sc(N_ENTER,r.fd,0,1,PARAM_ENTER_FLAGS,1,sizeof(*w))==-14);
 w->flags=2;CHECK(sc(N_ENTER,r.fd,0,1,PARAM_ENTER_FLAGS,0,sizeof(*w))==-22);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0);return finish(&r);
}
static int param_region_user_shared(void)
{
 struct ring r;struct pregion_reg reg;struct pregion_desc desc;
 struct pregion_wait *w;long m;
 CHECK(init(&r,SDIS,4)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);
 param_want(&reg,&desc,1);desc.flags=1;desc.user_addr=m;
 CHECK(sreg(&r,34,&reg,1)==0&&desc.mmap_offset==0);
 CHECK(sc(N_MMAP,0,4096,3,1,r.fd,PARAM_OFF)==-BADMAP_ERROR);
 w=(void *)m;zero(w,sizeof(*w));w->flags=1;w->ts.nsec=1000000;
 CHECK(sreg(&r,12,0,0)==0);
 CHECK(sc(N_ENTER,r.fd,0,1,PARAM_ENTER_FLAGS,0,sizeof(*w))==-LTIME);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0);return finish(&r);
}
static int senable(struct ring *r) { CHECK(sreg(r,12,0,0)==0);return 0; }
#define CQ_EVENTFD_DISABLED 1U
static int efd_empty(long fd)
{
 u64 v=0xfeedface;long n=CALL(N_READ,fd,&v,sizeof(v));
 CHECK(n==-AGAIN&&v==0xfeedface);return 0;
}
static int efd_wait(long fd,u64 *vp)
{
 for(u32 n=0;n<1000000;n++){long r=CALL(N_READ,fd,vp,sizeof(*vp));if(r==(long)sizeof(*vp))return 0;CHECK(r==-AGAIN);CALL(N_YIELD,0,0,0);}
 return __LINE__;
}
static int eventfd_submit(struct ring *r,long file,u64 ud)
{
 struct sqe q;zero(&q,sizeof(q));q.op=23;q.flags=16;q.fd=(int)file;q.addr=(u64)"WORK";q.len=4;q.ud=ud;
 queue(r,q,0);CHECK(sc(N_ENTER,r->fd,1,0,0,0,0)==1);return 0;
}
static int eventfd_reap(struct ring *r,u64 ud)
{
 if(__atomic_load_n(r->ct,__ATOMIC_ACQUIRE)==r->ci)CHECK(sc(N_ENTER,r->fd,0,1,1,0,0)==0);
 return reap(r,ud,4);
}
static int eventfd_async_shared(void)
{
 struct ring r;struct sqe q;long efd,file,m;int ei;u64 value;
 CHECK(init(&r,0,8)==0);efd=make_eventfd();CHECK(efd>=0);ei=(int)efd;
 file=sc(N_OPENAT,-100,(long)"eventfd-async",OPENFLAGS,0600,0,0);CHECK(file>=0);
 /* Exact registration shapes and errors; failures leave no registration. */
 CHECK(sreg(&r,5,0,0)==-6&&sreg(&r,5,&ei,0)==-22&&sreg(&r,5,0,1)==-22);
 CHECK(sreg(&r,7,0,0)==-22&&sreg(&r,7,0,1)==-14&&sreg(&r,7,(void *)1,1)==-14&&sreg(&r,7,&ei,2)==-22);
 int bad=-1,regular=(int)file;CHECK(sreg(&r,7,&bad,1)==-9&&sreg(&r,7,&regular,1)==-22);
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);int *cross=(int *)(m+4096-2);*(unsigned short *)cross=(unsigned short)ei;
 CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&sreg(&r,7,cross,1)==-14&&CALL(N_MUNMAP,m,8192,0)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);int *ro=(int *)m;*ro=ei;CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,7,ro,1)==0&&CALL(N_MUNMAP,m,4096,0)==0);
 /* A second ordinary or async registration is busy and preserves async mode. */
 CHECK(sreg(&r,4,&ei,1)==-16&&sreg(&r,7,&ei,1)==-16);
 zero(&q,sizeof(q));q.ud=1;queue(&r,q,0);CHECK(flush(&r,1)==0&&reap(&r,1,0)==0&&efd_empty(efd)==0);
 CHECK(eventfd_submit(&r,file,2)==0&&efd_wait(efd,&value)==0&&value>=1&&eventfd_reap(&r,2)==0);
 /* The userspace CQ flag suppresses both worker and ordinary notification. */
 __atomic_store_n(r.cf,CQ_EVENTFD_DISABLED,__ATOMIC_RELEASE);
 CHECK(eventfd_submit(&r,file,3)==0&&eventfd_reap(&r,3)==0&&efd_empty(efd)==0);
 __atomic_store_n(r.cf,0,__ATOMIC_RELEASE);
 /* Malformed unregister calls do not remove the live async registration. */
 CHECK(sreg(&r,5,&ei,0)==-22&&sreg(&r,5,0,1)==-22);
 CHECK(eventfd_submit(&r,file,4)==0&&efd_wait(efd,&value)==0&&eventfd_reap(&r,4)==0);
 CHECK(sreg(&r,5,0,0)==0&&sreg(&r,5,0,0)==-6);
 CHECK(eventfd_submit(&r,file,5)==0&&eventfd_reap(&r,5)==0&&efd_empty(efd)==0);
 /* Ordinary mode signals inline CQ publication and obeys the disable flag. */
 CHECK(sreg(&r,4,&ei,1)==0);zero(&q,sizeof(q));q.ud=6;queue(&r,q,0);CHECK(flush(&r,1)==0&&reap(&r,6,0)==0);
 CHECK(efd_wait(efd,&value)==0&&value>=1);__atomic_store_n(r.cf,CQ_EVENTFD_DISABLED,__ATOMIC_RELEASE);
 zero(&q,sizeof(q));q.ud=7;queue(&r,q,0);CHECK(flush(&r,1)==0&&reap(&r,7,0)==0&&efd_empty(efd)==0);
 __atomic_store_n(r.cf,0,__ATOMIC_RELEASE);CHECK(sreg(&r,5,0,0)==0);
 /* The ring's held file reference survives closing the registered descriptor. */
 long alias=CALL(N_DUP,efd,0,0);CHECK(alias>=0&&sreg(&r,7,&ei,1)==0&&CALL(N_CLOSE,efd,0,0)==0);
 CHECK(eventfd_submit(&r,file,8)==0&&efd_wait(alias,&value)==0&&eventfd_reap(&r,8)==0);
 CHECK(sreg(&r,5,0,0)==0&&CALL(N_CLOSE,alias,0,0)==0&&CALL(N_CLOSE,file,0,0)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 /* Registration is permitted while disabled and becomes active on enable. */
 CHECK(init(&r,SDIS,8)==0);efd=make_eventfd();CHECK(efd>=0);ei=(int)efd;
 file=sc(N_OPENAT,-100,(long)"eventfd-disabled",OPENFLAGS,0600,0,0);CHECK(file>=0);
 CHECK(sreg(&r,7,&ei,1)==0&&senable(&r)==0&&eventfd_submit(&r,file,9)==0);
 CHECK(efd_wait(efd,&value)==0&&eventfd_reap(&r,9)==0&&sreg(&r,5,0,0)==0);
 CHECK(CALL(N_CLOSE,efd,0,0)==0&&CALL(N_CLOSE,file,0,0)==0&&lhealth(&r)==0);return finish(&r);
}
struct sclock_reg { u32 clockid,resv[3]; };
struct sentergx { u64 sigmask;u32 sigmask_sz,min_wait_usec;u64 ts; };
static long clock_ns(u32 id)
{
 struct ltime t;if(CALL(LCLOCK,id,&t,0)!=0)return -1;return t.sec*1000000000L+t.nsec;
}
static int min_wait_shared(void)
{
 struct ring r;struct sentergx x;struct ltime ts;struct sqe q;
 struct pregion_reg reg;struct pregion_desc desc;struct pregion_wait *w;
 long start,elapsed,m;
 CHECK(init(&r,0,8)==0&&((r.p.features&(1U<<15))!=0));
 zero(&x,sizeof(x));x.min_wait_usec=20000;
 start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,1|8,(long)&x,sizeof(x))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=10000000&&elapsed<2000000000L);
 x.sigmask=1;x.sigmask_sz=
#ifdef LINUX_ABI
 8;
#else
 sizeof(sigset_t);
#endif
 CHECK(sc(N_ENTER,r.fd,0,2,1|8,(long)&x,sizeof(x))==-14);
 x.sigmask=0;x.sigmask_sz=0;
 ts.sec=0;ts.nsec=40000000;x.min_wait_usec=10000;x.ts=(u64)&ts;
 start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,1|8,(long)&x,sizeof(x))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=25000000&&elapsed<2000000000L);
 ts.nsec=5000000;x.min_wait_usec=20000;start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,1|8,(long)&x,sizeof(x))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=12000000&&elapsed<2000000000L);
 zero(&q,sizeof(q));q.ud=99;queue(&r,q,0);CHECK(lsubmit(&r,1)==0);
 x.ts=0;x.min_wait_usec=10000;start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,1|8,(long)&x,sizeof(x))==0);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=5000000&&elapsed<2000000000L);
 CHECK(reap(&r,99,0)==0&&finish(&r)==0);
 CHECK(init(&r,SDIS,8)==0);
 param_want(&reg,&desc,1);CHECK(sreg(&r,34,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,PARAM_OFF);CHECK(m>=0);w=(void *)m;
 CHECK(sreg(&r,12,0,0)==0);
 zero(w,sizeof(*w));w->min_wait_usec=15000;
 start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,PARAM_ENTER_FLAGS,0,sizeof(*w))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=7000000&&elapsed<2000000000L);
 w->sigmask=1;w->sigmask_sz=x.sigmask_sz;
#ifdef LINUX_ABI
 w->sigmask_sz=8;
#else
 w->sigmask_sz=sizeof(sigset_t);
#endif
 CHECK(sc(N_ENTER,r.fd,0,2,PARAM_ENTER_FLAGS,0,sizeof(*w))==-14);
 w->sigmask=0;w->sigmask_sz=0;
 w->flags=1;w->ts.sec=0;w->ts.nsec=40000000;w->min_wait_usec=10000;
 start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,PARAM_ENTER_FLAGS,0,sizeof(*w))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=25000000&&elapsed<2000000000L);
 zero(&q,sizeof(q));q.ud=100;queue(&r,q,0);CHECK(lsubmit(&r,1)==0);
 w->flags=0;w->min_wait_usec=10000;start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r.fd,0,2,PARAM_ENTER_FLAGS,0,sizeof(*w))==0);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=5000000&&elapsed<2000000000L);
 CHECK(reap(&r,100,0)==0);
 w->flags=2;CHECK(sc(N_ENTER,r.fd,0,2,PARAM_ENTER_FLAGS,0,sizeof(*w))==-22);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0&&lhealth(&r)==0);
 return finish(&r);
}
static int clock_abs_wait(struct ring *r,u32 id)
{
 struct ltime t;struct sentergx x;long start,elapsed;
 CHECK(CALL(LCLOCK,id,&t,0)==0);t.nsec+=20000000;if(t.nsec>=1000000000){t.sec++;t.nsec-=1000000000;}
 zero(&x,sizeof(x));x.ts=(u64)&t;start=clock_ns(LMONO);CHECK(start>=0);
 CHECK(sc(N_ENTER,r->fd,0,1,1|8|32,(long)&x,sizeof(x))==-LTIME);
 elapsed=clock_ns(LMONO)-start;CHECK(elapsed>=10000000&&elapsed<2000000000L);return 0;
}
static int register_clock_shared(void)
{
 struct ring r;struct sclock_reg reg;u32 invalid[]={0,2,3,6,0xffffffffU};
 CHECK(init(&r,0,8)==0);zero(&reg,sizeof(reg));reg.clockid=REG_CLOCK_MONOTONIC;
 CHECK(sreg(&r,29,0,0)==-22&&sreg(&r,29,&reg,1)==-22&&sreg(&r,29,(void *)1,0)==-14);
 for(u32 i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){reg.clockid=invalid[i];CHECK(sreg(&r,29,&reg,0)==-22);}
 for(u32 i=0;i<3;i++){zero(&reg,sizeof(reg));reg.clockid=REG_CLOCK_MONOTONIC;reg.resv[i]=1;CHECK(sreg(&r,29,&reg,0)==-22);}
 long m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);struct sclock_reg *cross=(void *)(m+4096-8);zero(cross,8);cross->clockid=REG_CLOCK_MONOTONIC;CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&sreg(&r,29,cross,0)==-14&&CALL(N_MUNMAP,m,8192,0)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);struct sclock_reg *ro=(void *)m;zero(ro,sizeof(*ro));ro->clockid=REG_CLOCK_MONOTONIC;CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,29,ro,0)==0&&CALL(N_MUNMAP,m,4096,0)==0);
 CHECK(clock_abs_wait(&r,REG_CLOCK_MONOTONIC)==0);zero(&reg,sizeof(reg));reg.clockid=REG_CLOCK_BOOTTIME;CHECK(sreg(&r,29,&reg,0)==0&&clock_abs_wait(&r,REG_CLOCK_BOOTTIME)==0);
 reg.clockid=REG_CLOCK_MONOTONIC;CHECK(sreg(&r,29,&reg,0)==0&&clock_abs_wait(&r,REG_CLOCK_MONOTONIC)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 CHECK(init(&r,SDIS,8)==0);reg.clockid=REG_CLOCK_BOOTTIME;CHECK(sreg(&r,29,&reg,0)==0&&senable(&r)==0&&lhealth(&r)==0);return finish(&r);
}
static void sr(struct srestriction *r,int type,int value) { zero(r,sizeof(*r));r->type=type;r->value=value; }
static int sqe_mixed_shared(void)
{
 struct ring r;struct sqe q;struct params p;
 CHECK(init(&r,SSQEMIXED|NOARRAY,8)==0);
 zero(&q,sizeof(q));q.ud=301;queue(&r,q,0);
 zero(&q,sizeof(q));q.op=63;q.ud=302;queue(&r,q,0);
 zero(&q,sizeof(q));queue(&r,q,0); /* second half of NOP128 */
 zero(&q,sizeof(q));q.ud=303;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,4,3,1,0,0)==4);
 CHECK(*r.sh==4&&reap(&r,301,0)==0&&reap(&r,302,0)==0&&
     reap(&r,303,0)==0&&lhealth(&r)==0&&finish(&r)==0);
 /* One available slot cannot hold a mixed 128-byte operation. */
 CHECK(init(&r,SSQEMIXED|NOARRAY,8)==0);
 zero(&q,sizeof(q));q.op=63;q.ud=306;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,1,1,0,0)==1&&*r.sh==1&&
     reap(&r,306,-22)==0&&lhealth(&r)==0&&finish(&r)==0);
 /* A 128-byte SQE cannot start at the final physical slot. */
 CHECK(init(&r,SSQEMIXED|NOARRAY,8)==0);
 for(u32 i=0;i<7;i++){zero(&q,sizeof(q));q.ud=400+i;queue(&r,q,0);}
 zero(&q,sizeof(q));q.op=63;q.ud=407;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,8,8,1,0,0)==8&&*r.sh==8);
 for(u32 i=0;i<7;i++)CHECK(reap(&r,400+i,0)==0);
 CHECK(reap(&r,407,-22)==0&&lhealth(&r)==0&&finish(&r)==0);
 CHECK(init(&r,0,8)==0);zero(&q,sizeof(q));q.op=63;q.ud=304;
 queue(&r,q,0);CHECK(sc(N_ENTER,r.fd,1,1,1,0,0)==1&&
     reap(&r,304,-22)==0&&finish(&r)==0);
 CHECK(init(&r,SSQE128,8)==0);zero(&q,sizeof(q));q.op=63;q.ud=305;
 queue(&r,q,0);CHECK(sc(N_ENTER,r.fd,1,1,1,0,0)==1&&
     reap(&r,305,0)==0&&finish(&r)==0);
 zero(&p,sizeof(p));p.flags=SSQEMIXED|SSQE128;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 zero(&p,sizeof(p));p.flags=SSQEMIXED;
 CHECK(CALL(N_SETUP,1,&p,0)==-OVERFLOW);
 return 0;
}
static int attach_wq_shared(void)
{
 struct ring source,attached,chained;struct params p;struct cqe c;
 u32 values[2],query[2];int first[2],second[2];char a=0,b=0;
 CHECK(init(&source,0,8)==0);
 values[0]=values[1]=1;
 CHECK(sreg(&source,19,values,2)==0&&values[0]>0&&values[1]>0);
 CHECK(init_ex_wq(&attached,SATTACHWQ|NOARRAY,8,0,source.fd)==0);
 CHECK((attached.p.flags&(SATTACHWQ|NOARRAY))==(SATTACHWQ|NOARRAY));
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==1&&query[1]==1);
 /* The attached ring retains the worker owner after the source fd closes. */
 CHECK(finish(&source)==0);
 zero(&p,sizeof(p));p.flags=SATTACHWQ;p.wq=source.fd;
 CHECK(CALL(N_SETUP,8,&p,0)==-6);
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==1&&query[1]==1);
 /* Attachment chains use the original canonical owner. */
 CHECK(init_ex_wq(&chained,SATTACHWQ,8,0,attached.fd)==0);
 values[0]=2;values[1]=1;
 CHECK(sreg(&chained,19,values,2)==0&&values[0]==1&&values[1]==1);
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==2&&query[1]==1);
 /* One shared unbound slot serializes work submitted through both rings. */
 CHECK(bpipe(first,0)==0&&bpipe(second,0)==0);
 lq(&attached,22,16,first[0],(u64)&a,1,0,501);
 CHECK(lsubmit(&attached,1)==0);
 lq(&chained,22,16,second[0],(u64)&b,1,0,502);
 CHECK(lsubmit(&chained,1)==0&&CALL(N_WRITE,second[1],"B",1)==1);
 lpause(50000000);CHECK(__atomic_load_n(chained.ct,__ATOMIC_ACQUIRE)==chained.ci);
 CHECK(CALL(N_WRITE,first[1],"A",1)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==501&&c.res==1&&a=='A');
 CHECK(lget(&chained,&c,1)==0&&c.ud==502&&c.res==1&&b=='B');
 CHECK(CALL(N_CLOSE,first[0],0,0)==0&&CALL(N_CLOSE,first[1],0,0)==0);
 CHECK(CALL(N_CLOSE,second[0],0,0)==0&&CALL(N_CLOSE,second[1],0,0)==0);
 CHECK(finish(&attached)==0);
 query[0]=query[1]=0;
 CHECK(sreg(&chained,19,query,2)==0&&query[0]==2&&query[1]==1);
 lq(&chained,0,0,-1,0,0,0,503);
 CHECK(lsubmit(&chained,1)==0&&lget(&chained,&c,1)==0&&
     c.ud==503&&c.res==0&&lhealth(&chained)==0&&finish(&chained)==0);
 zero(&p,sizeof(p));p.flags=SATTACHWQ;p.wq=9999;
 CHECK(CALL(N_SETUP,8,&p,0)==-6);
 CHECK(bpipe(first,0)==0);
 zero(&p,sizeof(p));p.flags=SATTACHWQ;p.wq=first[0];
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(CALL(N_CLOSE,first[0],0,0)==0&&CALL(N_CLOSE,first[1],0,0)==0);
 return 0;
}
static int setup_flags(void) {
 for(int mode=0;mode<16;mode++){struct ring r;u32 flags=(mode&1?SDIS:0)|(mode&2?SALL:0)|(mode&4?SONE:0)|(mode&8?NOARRAY:0);CHECK(init(&r,flags,8)==0);CHECK(r.p.flags==flags);if(mode&1)CHECK(senable(&r)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 struct params p;for(int bit=31;bit<32;bit++){u32 b=1U<<bit;zero(&p,sizeof(p));p.flags=SDIS|SALL|SONE|b;CHECK(CALL(N_SETUP,8,&p,0)==-22);}
 /* Linux setup dependencies: TASKRUN_FLAG needs COOP or DEFER; DEFER needs one issuer. */
 zero(&p,sizeof(p));p.flags=STASKRUN;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 zero(&p,sizeof(p));p.flags=SDEFER;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 u32 valid[]={SCOOP,SCOOP|STASKRUN,SONE|SDEFER,SONE|SDEFER|STASKRUN,SONE|SDEFER|SCOOP|STASKRUN};
 for(u32 i=0;i<sizeof(valid)/sizeof(valid[0]);i++){struct ring r;CHECK(init(&r,valid[i],8)==0&&r.p.flags==valid[i]&&lhealth(&r)==0&&finish(&r)==0);}
 /* A worker completion publishes SQ_TASKRUN until enter drains local work. */
 struct ring r;int fd[2];char byte=0;struct sqe q;struct cqe c;
 CHECK(init(&r,SONE|SDEFER|STASKRUN,8)==0&&bpipe(fd,0)==0);zero(&q,sizeof(q));q.op=22;q.flags=16;q.fd=fd[0];q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.ud=91;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&(*r.sf&SQ_TASKRUN)==0&&CALL(N_WRITE,fd[1],"T",1)==1);
 for(int n=0;n<1000000&&(*r.sf&SQ_TASKRUN)==0;n++)CALL(N_YIELD,0,0,0);
 CHECK((*r.sf&SQ_TASKRUN)!=0&&sc(N_ENTER,r.fd,0,1,1,0,0)==0&&
     lget(&r,&c,1)==0&&c.ud==91&&c.res==1&&byte=='T'&&(*r.sf&SQ_TASKRUN)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0&&finish(&r)==0);
 return 0;
}
static int setup_disabled(void) {
 struct ring r;struct cqe c;char probe[32];CHECK(init(&r,SDIS|SONE,8)==0);lq(&r,0,0,-1,0,0,0,1);__atomic_store_n(r.st,r.si,__ATOMIC_RELEASE);
 for(int submit=0;submit<2;submit++)for(int flags=0;flags<2;flags++)CHECK(sc(N_ENTER,r.fd,submit,1,flags,1,8)==-BADSTATE);
 CHECK(*r.sh==0&&*r.ct==0);zero(probe,sizeof(probe));CHECK(sreg(&r,8,probe,0)==0);
 CHECK(sreg(&r,12,(void *)1,0)==-22&&sreg(&r,12,0,1)==-22);CHECK(sc(N_ENTER,r.fd,0,0,0,0,0)==-BADSTATE);
 CHECK(senable(&r)==0);CHECK(sreg(&r,12,0,0)==-BADSTATE);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==1&&c.res==0);CHECK(lhealth(&r)==0);return finish(&r);
}
static int setup_restrict_ops(void) {
 struct ring r;struct srestriction policy[2];struct cqe c;char data[4];CHECK(init(&r,SDIS|SALL,8)==0);sr(&policy[0],1,0);sr(&policy[1],1,22);CHECK(sreg(&r,11,policy,2)==0&&senable(&r)==0);
 long fd=sc(N_OPENAT,-100,(long)"policy-data",OPENFLAGS,0600,0,0);CHECK(fd>=0&&CALL(N_WRITE,fd,"SAFE",4)==4);
 for(int flags=0;flags<=16;flags+=16){lq(&r,23,flags,fd,(u64)"BAD!",4,0,1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-13);}
 CHECK(CALL(N_SEEK,fd,0,0)==0&&CALL(N_READ,fd,data,4)==4);for(int i=0;i<4;i++)CHECK(data[i]=="SAFE"[i]);
 lq(&r,22,0,-1,(u64)data,4,0,2);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-9);CHECK(lhealth(&r)==0&&finish(&r)==0);CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;
}
static int setup_restrict_flags(void) {
 for(int mode=0;mode<5;mode++){struct ring r;struct srestriction p[5];struct cqe c;CHECK(init(&r,SDIS|SALL,8)==0);sr(&p[0],1,0);sr(&p[1],2,16);sr(&p[2],3,mode==0?16:0);int n=3;
 if(mode==1){sr(&p[n++],2,0);}if(mode==2){sr(&p[n++],3,16);}if(mode==3){sr(&p[n++],3,128);}if(mode==4){sr(&p[n++],2,128);}
 CHECK(sreg(&r,11,p,n)==0&&senable(&r)==0);
 for(int async=0;async<2;async++){lq(&r,0,async?16:0,-1,0,0,0,1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0);int ok=mode==0||mode==2?async:mode==1||mode==4?!async:0;CHECK(c.res==(ok?0:-13));}
 if(mode>=3){lq(&r,0,128,-1,0,0,0,1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-22);}CHECK(finish(&r)==0);}
 return 0;
}
static int setup_restrict_register(void) {
 struct ring r;struct srestriction p[3];char probe[32];CHECK(init(&r,SDIS,8)==0);sr(&p[0],0,8);sr(&p[1],0,1);sr(&p[2],1,0);CHECK(sreg(&r,11,p,3)==0);
 char data[4];struct rwvec v={data,4};CHECK(breg(&r,&v,1)==0&&senable(&r)==0);zero(probe,sizeof(probe));CHECK(sreg(&r,8,probe,0)==0&&bunreg(&r)==0);
 CHECK(breg(&r,&v,1)==-13&&sreg(&r,12,0,0)==-13&&sreg(&r,11,p,3)==-13);CHECK(sreg(&r,0x7fffffff,0,0)==-22);CHECK(lhealth(&r)==0);return finish(&r);
}
static int setup_restrict_empty(void) {
 for(int mode=0;mode<2;mode++){struct ring r;struct srestriction p;struct cqe c;CHECK(init(&r,SDIS,8)==0);sr(&p,1,0);CHECK(sreg(&r,11,0,0)==-22);CHECK(sreg(&r,11,(void *)1,0)==0);CHECK(sreg(&r,11,&p,1)==-16);CHECK(senable(&r)==0);
 lq(&r,0,0,-1,0,0,0,1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-13);CHECK(sreg(&r,8,&p,0)==-13&&finish(&r)==0);}
 return 0;
}
static int setup_restrict_invalid(void) {
 struct srestriction p[2];struct ring normal;sr(&p[0],1,0);CHECK(init(&normal,0,8)==0);CHECK(sreg(&normal,11,p,1)==-BADSTATE&&sreg(&normal,12,0,0)==-BADSTATE&&finish(&normal)==0);
 for(int mode=0;mode<5;mode++){struct ring r;CHECK(init(&r,SDIS,8)==0);sr(&p[0],1,0);sr(&p[1],1,0);if(mode==0)p[1].type=4;if(mode==1)p[1].type=65535;if(mode==2)p[1].value=255;if(mode==3)p[1].type=0,p[1].value=255;
 CHECK(sreg(&r,11,p,mode==4?4096:2)==-22);CHECK(sreg(&r,11,p,1)==0);CHECK(sreg(&r,11,(void *)1,4096)==-16);CHECK(senable(&r)==0&&lhealth(&r)==0&&finish(&r)==0);}
 /* Linux ignores padding; it is not an extra restriction opcode. */
 struct ring r;CHECK(init(&r,SDIS,8)==0);sr(&p[0],1,0);p[0].resv=255;p[0].pad[0]=~0U;CHECK(sreg(&r,11,p,1)==0&&senable(&r)==0&&lhealth(&r)==0);return finish(&r);
}
static int setup_restrict_faults(void) {
 for(int mode=0;mode<5;mode++){struct ring r;CHECK(init(&r,SDIS,8)==0);long mem=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(mem>0);struct srestriction *p=(void *)(mem+(mode==2?4088:0));sr(p,1,0);
 if(mode==0)CHECK(CALL(N_MPROTECT,mem,8192,0)==0);if(mode==1)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);if(mode==2)CHECK(CALL(N_MPROTECT,mem+4096,4096,0)==0);if(mode==3)CHECK(CALL(N_MPROTECT,mem,8192,1)==0);
 CHECK(sreg(&r,11,mode==4?(void *)1:p,1)==(mode==3?0:-14));struct srestriction good;sr(&good,1,0);if(mode!=3)CHECK(sreg(&r,11,&good,1)==0);CHECK(senable(&r)==0&&lhealth(&r)==0&&finish(&r)==0);if(mode!=1)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);}
 return 0;
}
static int setup_restrict_fixed(void) {
 struct ring r;struct srestriction p[3];struct cqe c;char data[4];CHECK(init(&r,SDIS|SALL,8)==0);long fd=sc(N_OPENAT,-100,(long)"restricted-fixed",OPENFLAGS,0600,0,0);CHECK(fd>=0&&CALL(N_WRITE,fd,"SAFE",4)==4);int file=fd;CHECK(sreg(&r,2,&file,1)==0);sr(&p[0],1,22);sr(&p[1],3,1);sr(&p[2],0,3);CHECK(sreg(&r,11,p,3)==0&&senable(&r)==0);
 lq(&r,22,0,fd,(u64)data,4,0,1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-13);CHECK(CALL(N_CLOSE,fd,0,0)==0);
 struct sqe q;zero(&q,sizeof(q));q.op=22;q.flags=1;q.fd=0;q.addr=(u64)data;q.len=4;q.ud=2;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==4);for(int i=0;i<4;i++)CHECK(data[i]=="SAFE"[i]);CHECK(sreg(&r,3,0,0)==0);return finish(&r);
}
static int setup_restrict_links(void) {
 for(int hard=0;hard<2;hard++){struct ring r;struct srestriction p[2];struct cqe c[3];CHECK(init(&r,SDIS|SALL,8)==0);sr(&p[0],1,23);sr(&p[1],2,4|8);CHECK(sreg(&r,11,p,2)==0&&senable(&r)==0);long fd=sc(N_OPENAT,-100,hard?(long)"hard-policy":(long)"soft-policy",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 lq(&r,23,hard?8:4,fd,(u64)"BAD",3,0,1);lq(&r,0,4,-1,0,0,0,2);lq(&r,23,0,fd,(u64)"BAD",3,0,3);CHECK(lsubmit(&r,3)==0&&lget(&r,c,3)==0&&lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-13)==0&&lresult(c,3,3,-CANCELED)==0);char x;CHECK(CALL(N_READ,fd,&x,1)==0&&finish(&r)==0&&CALL(N_CLOSE,fd,0,0)==0);}
 return 0;
}
static int setup_single(void) {
 struct ring r;int status;CHECK(init(&r,SONE,8)==0);long alias=CALL(N_DUP,r.fd,0,0);CHECK(alias>=0);long pid=fork_child();CHECK(pid>=0);if(pid==0){char p[32];zero(p,sizeof(p));int bad=sc(N_ENTER,alias,1,0,0,0,0)!=-17||sc(N_ENTER,alias,0,0,0,0,0)!=0||sc(N_REGISTER,alias,8,(long)p,0,0,0)!=-17;CALL(N_EXIT,bad,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);CHECK(CALL(N_CLOSE,r.fd,0,0)==0);r.fd=alias;CHECK(lhealth(&r)==0);return finish(&r);
}
static int setup_single_enable(void) {
 struct ring r;int status;CHECK(init(&r,SONE|SDIS,8)==0);long pid=fork_child();CHECK(pid>=0);if(pid==0){int bad=senable(&r)!=0||lhealth(&r)!=0;CALL(N_EXIT,bad,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);CHECK(sc(N_ENTER,r.fd,1,0,0,0,0)==-17&&sreg(&r,8,(void *)1,0)==-17);CHECK(sc(N_ENTER,r.fd,0,0,0,0,0)==0);return finish(&r);
}
struct sthread {struct ring *r;u32 done;int mode,result;};
static int sthread_work(void *arg) {struct sthread *s=arg;char p[32];zero(p,sizeof(p));s->result=0;if(s->mode==1){if(senable(s->r)!=0||lhealth(s->r)!=0)s->result=1;}else if(sc(N_ENTER,s->r->fd,1,0,0,0,0)!=-17||sreg(s->r,8,p,0)!=-17)s->result=2;__atomic_store_n(&s->done,1,__ATOMIC_RELEASE);return 0;}
#ifndef LINUX_ABI
static void *sthread_native(void *arg) {(void)sthread_work(arg);return 0;}
#endif
static int sthread_run(struct sthread *s) {
#ifdef LINUX_ABI
 long mem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);CHECK(mem>0);u64 *sp=(u64 *)(mem+65536)-2;sp[0]=(u64)sthread_work;sp[1]=(u64)s;long tid=bclone(0x10f00,sp);CHECK(tid>0);
 struct ltime end,now;CHECK(CALL(LCLOCK,LMONO,&end,0)==0);end.sec+=2;long pid=CALL(NR(39,172),0,0,0);
 while(!__atomic_load_n(&s->done,__ATOMIC_ACQUIRE)||CALL(NR(234,131),pid,tid,0)!=-3){CHECK(CALL(LCLOCK,LMONO,&now,0)==0&&now.sec<=end.sec);CALL(N_YIELD,0,0,0);}CHECK(CALL(N_MUNMAP,mem,65536,0)==0);
#else
 pthread_t thread;CHECK(pthread_create(&thread,0,sthread_native,s)==0&&pthread_join(thread,0)==0);
#endif
 CHECK(s->result==0);return 0;
}
static int setup_single_threads(void) {struct ring r;CHECK(init(&r,SONE,8)==0);for(int n=0;n<32;n++){struct sthread s={&r,0,0,0};CHECK(sthread_run(&s)==0&&lhealth(&r)==0);}return finish(&r);}
static int setup_single_exit(void) {struct ring r;CHECK(init(&r,SDIS|SONE,8)==0);struct sthread owner={&r,0,1,0};CHECK(sthread_run(&owner)==0);for(int n=0;n<64;n++){struct sthread other={&r,0,0,0};CHECK(sthread_run(&other)==0);}CHECK(sc(N_ENTER,r.fd,1,0,0,0,0)==-17);return finish(&r);}
static int setup_enable_race(void) {
 for(int n=0;n<32;n++){struct ring r;int status,sync[2];CHECK(init(&r,SDIS|SONE,8)==0&&bpipe(sync,0)==0);long pid=fork_child();CHECK(pid>=0);if(pid==0){char x;CALL(N_READ,sync[0],&x,1);long rc=sreg(&r,12,0,0);CALL(N_EXIT,rc==0?0:rc==-17?17:99,0,0);}CHECK(CALL(N_WRITE,sync[1],"R",1)==1);long rc=sreg(&r,12,0,0);CHECK(CALL(N_WAIT,pid,&status,0)==pid);CHECK((rc==0&&status==(17<<8))||(rc==-17&&status==0));CHECK(finish(&r)==0&&CALL(N_CLOSE,sync[0],0,0)==0&&CALL(N_CLOSE,sync[1],0,0)==0);}
 return 0;
}
static int setup_restrict_race(void) {
 for(int n=0;n<32;n++){struct ring r;struct srestriction p;int sync[2],status;sr(&p,1,0);CHECK(init(&r,SDIS,8)==0&&bpipe(sync,0)==0);long pid=fork_child();CHECK(pid>=0);if(pid==0){char x;CALL(N_READ,sync[0],&x,1);long rc=sreg(&r,11,&p,1);CALL(N_EXIT,rc==0?0:rc==-16?16:99,0,0);}CHECK(CALL(N_WRITE,sync[1],"R",1)==1);long rc=sreg(&r,11,&p,1);CHECK(CALL(N_WAIT,pid,&status,0)==pid);CHECK((rc==0&&status==(16<<8))||(rc==-16&&status==0));CHECK(senable(&r)==0&&lhealth(&r)==0&&finish(&r)==0);CALL(N_CLOSE,sync[0],0,0);CALL(N_CLOSE,sync[1],0,0);}
 return 0;
}
static int setup_submit_all(void) {
 for(int all=0;all<2;all++)for(int mode=0;mode<4;mode++){struct ring r;struct sqe q;struct cqe c[3];CHECK(init(&r,all?SALL:0,8)==0);lq(&r,0,0,-1,0,0,0,1);zero(&q,sizeof(q));q.ud=2;if(mode==0)q.op=255;if(mode==1)q.flags=128;if(mode==2)q.personality=1;if(mode==3)q.op=11,q.len=1,q.addr=1;queue(&r,q,0);lq(&r,0,0,-1,0,0,0,3);__atomic_store_n(r.st,r.si,__ATOMIC_RELEASE);
 CHECK(sc(N_ENTER,r.fd,3,0,0,0,0)==(all?3:2));CHECK(*r.sh==(all?3U:2U));CHECK(lget(&r,c,all?3:2)==0&&lresult(c,all?3:2,1,0)==0&&lresult(c,all?3:2,2,mode==3?-14:-22)==0);if(all)CHECK(lresult(c,3,3,0)==0);else CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].ud==3&&c[0].res==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int setup_submit_errors(void) {
 for(int all=0;all<2;all++){struct ring r;struct cqe c[3];char data[4];CHECK(init(&r,all?SALL:0,8)==0);lq(&r,22,0,-1,(u64)data,4,0,1);lq(&r,0,0,-1,0,0,0,2);CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0&&lresult(c,2,1,-9)==0&&lresult(c,2,2,0)==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int setup_submit_links(void) {
 for(int all=0;all<2;all++)for(int tailbad=0;tailbad<2;tailbad++){struct ring r;struct cqe c[4];CHECK(init(&r,all?SALL:0,8)==0);lq(&r,tailbad?0:255,4,-1,0,0,0,1);lq(&r,tailbad?255:0,0,-1,0,0,0,2);lq(&r,0,0,-1,0,0,0,3);__atomic_store_n(r.st,r.si,__ATOMIC_RELEASE);int n=tailbad&&!all?2:3;CHECK(sc(N_ENTER,r.fd,3,0,0,0,0)==n&&lget(&r,c,n)==0);CHECK(lresult(c,n,1,tailbad?-CANCELED:-22)==0&&lresult(c,n,2,tailbad?-22:-CANCELED)==0);if(n==3)CHECK(lresult(c,n,3,0)==0);else CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].ud==3&&c[0].res==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int setup_submit_indices(void) {
 for(int all=0;all<2;all++){struct ring r;struct cqe c;CHECK(init(&r,all?SALL:0,8)==0);lq(&r,0,0,-1,0,0,0,1);lq(&r,0,0,-1,0,0,0,2);r.array[0]=r.p.sq;__atomic_store_n(r.st,r.si,__ATOMIC_RELEASE);CHECK(sc(N_ENTER,r.fd,2,0,0,0,0)==0&&*r.sh==1&&*r.ct==0);CHECK(*(u32 *)(r.mem+r.p.so.field5)==1);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==2&&c.res==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
static int setup_permissions(void) {
 int status;long pid=fork_child();CHECK(pid>=0);if(pid==0){if(CALL(N_SETUID,65534,0,0)!=0)CALL(N_EXIT,90,0,0);int rc=setup_restrict_empty();CALL(N_EXIT,rc!=0,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);return 0;
}
static int setup_exec_helper(const char *arg,int owner) {long fd=0;while(*arg)fd=fd*10+*arg++-'0';char p[32];zero(p,sizeof(p));CHECK(sc(N_ENTER,fd,1,0,0,0,0)==(owner?0:-17));CHECK(sc(N_REGISTER,fd,8,(long)p,0,0,0)==(owner?0:-17));CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;}
static const char *setup_self;
static int setup_exec(void) {
 const char *self=setup_self;
 for(int owner=0;owner<2;owner++){struct ring r;int status;CHECK(init(&r,SONE,8)==0);long pid=fork_child();CHECK(pid>=0);if(pid==0){if(owner){CALL(N_CLOSE,r.fd,0,0);if(init(&r,SONE,8)!=0)CALL(N_EXIT,90,0,0);}if(CALL(N_FCNTL,r.fd,2,0)!=0)CALL(N_EXIT,91,0,0);char b[24],number[24];int n=0;long fd=r.fd;do{b[n++]='0'+fd%10;fd/=10;}while(fd);for(int j=0;j<n;j++)number[j]=b[n-1-j];number[n]=0;char *av[]={(char *)self,owner?"setup_exec_owner":"setup_exec_other",number,0};char *ev[]={0};sc(N_EXEC,(long)self,(long)av,(long)ev,0,0,0);CALL(N_EXIT,92,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0&&finish(&r)==0);}
 return 0;
}

/* Registered-file ownership and update transactions. */
#ifdef LINUX_ABI
#define FOVERFLOW 75
#else
#include <sys/capsicum.h>
#include <sys/ioctl.h>
#define FOVERFLOW EOVERFLOW
#endif
struct fupdate {u32 offset,resv;u64 fds;};
static long freg(struct ring *r,int *fds,u32 n) {return sreg(r,2,fds,n);}
static long funreg(struct ring *r) {return sreg(r,3,0,0);}
static long fupdate(struct ring *r,int sqe,u32 off,int *fds,u32 n) {
 if(!sqe){struct fupdate u={off,0,(u64)fds};return sreg(r,6,&u,n);}
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=20;q.off=off;q.addr=(u64)fds;q.len=n;q.ud=71;queue(r,q,0);
 if(lsubmit(r,1)!=0||lget(r,&c,1)!=0||c.ud!=71)return -999;return c.res;
}
static int fbyte(struct ring *r,int idx,int expected) {
 char data=0;struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=22;q.flags=1;q.fd=idx;q.addr=(u64)&data;q.len=1;q.ud=72;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==72);if(expected<0)CHECK(c.res==expected);else CHECK(c.res==1&&data==expected);return 0;
}
static long fdata(const char *path,char value) {long fd=sc(N_OPENAT,-100,(long)path,OPENFLAGS,0600,0,0);if(fd>=0&&CALL(N_WRITE,fd,&value,1)!=1){CALL(N_CLOSE,fd,0,0);return -1;}return fd;}
static int prep_reject_one(struct sqe bad,int expect) {
 for(int all=0;all<2;all++){struct ring r;struct cqe c[2];struct sqe good;CHECK(init(&r,all?SALL:0,8)==0);bad.ud=1;queue(&r,bad,0);zero(&good,sizeof(good));good.ud=2;queue(&r,good,0);long n=sc(N_ENTER,r.fd,2,0,0,0,0);CHECK(n==(all?2:1));CHECK(lget(&r,c,all?2:1)==0&&lresult(c,all?2:1,1,expect)==0);if(all)CHECK(lresult(c,2,2,0)==0);else CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&c[0].ud==2&&c[0].res==0);CHECK(lhealth(&r)==0&&finish(&r)==0);}
 return 0;
}
struct pbuf_reg {u64 ring_addr;u32 ring_entries;unsigned short bgid,flags;u32 min_left,resv[5];};
struct pbuf_status {u32 buf_group,head,resv[8];};
struct uring_buf {u64 addr;u32 len;unsigned short bid,resv;};
union uring_buf_ring {struct {u64 r1;u32 r2;unsigned short r3,tail;} h;struct uring_buf bufs[];};
static int pbuf_ring_shared(void) {
 struct ring r;struct pbuf_reg reg;struct pbuf_status st;union uring_buf_ring *br;struct sqe q;struct cqe c;char data=0;long m,fd;
 CHECK(init(&r,0,8)==0);zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=47;reg.flags=1;CHECK(sreg(&r,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,0x80000000UL|((u64)47<<16));CHECK(m>=0);br=(union uring_buf_ring *)m;br->bufs[0].addr=(u64)&data;br->bufs[0].len=1;br->bufs[0].bid=720;__atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 fd=fdata("pbuf-shared",'S');CHECK(fd>=0&&CALL(N_CLOSE,fd,0,0)==0);fd=sc(N_OPENAT,-100,(long)"pbuf-shared",0,0,0,0);CHECK(fd>=0);
 zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fd;q.addr=0;q.len=1;q.buf=47;q.ud=1;queue(&r,q,0);int se=lsubmit(&r,1),ge=se==0?lwait(&r,1):-1;if(ge==0){c=r.cqes[r.ci&(r.p.cq-1)];__atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);}if(se!=0||ge!=0||c.ud!=1||c.res!=1||(c.flags&1)==0||(c.flags>>16)!=720||data!='S'){put("PBUF_SHARED_DIAG ");putnum(se);put(" ");putnum(ge);put(" ");putnum(c.ud);put(" ");putnum(c.res);put(" ");putnum(c.flags);put(" ");putnum(data);put("\n");return __LINE__;}
 zero(&st,sizeof(st));st.buf_group=47;CHECK(sreg(&r,26,&st,1)==0&&st.head==1);zero(&reg,sizeof(reg));reg.bgid=47;CHECK(sreg(&r,23,&reg,1)==0&&sreg(&r,23,&reg,1)==-2);
 CHECK(CALL(N_CLOSE,fd,0,0)==0&&CALL(N_MUNMAP,(void *)m,4096,0)==0);return finish(&r);
}


static int pbuf_ring_incremental_shared(void) {
 struct ring r;struct pbuf_reg reg;struct pbuf_status st;union uring_buf_ring *br;struct sqe q;struct cqe c;char data[4]={0};long m;int fd[2];
 CHECK(init(&r,0,8)==0);zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=48;reg.flags=3;reg.min_left=2;CHECK(sreg(&r,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,0x80000000UL|((u64)48<<16));CHECK(m>=0);br=(union uring_buf_ring *)m;br->bufs[0].addr=(u64)data;br->bufs[0].len=4;br->bufs[0].bid=721;__atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 CHECK(bpipe(fd,0)==0&&CALL(N_WRITE,fd[1],"AB",2)==2);zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fd[0];q.off=~0UL;q.len=2;q.buf=48;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lwait(&r,1)==0);c=r.cqes[r.ci&(r.p.cq-1)];__atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);
 CHECK(c.ud==1&&c.res==2&&(c.flags&17)==17&&(c.flags>>16)==721&&data[0]=='A'&&data[1]=='B'&&br->bufs[0].addr==(u64)(data+2)&&br->bufs[0].len==2);
 zero(&st,sizeof(st));st.buf_group=48;CHECK(sreg(&r,26,&st,1)==0&&st.head==0);
 CHECK(CALL(N_WRITE,fd[1],"C",1)==1);q.len=1;q.ud=2;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lwait(&r,1)==0);c=r.cqes[r.ci&(r.p.cq-1)];__atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);
 CHECK(c.ud==2&&c.res==1&&(c.flags&1)==1&&(c.flags&16)==0&&(c.flags>>16)==721&&data[2]=='C'&&br->bufs[0].len==0);
 zero(&st,sizeof(st));st.buf_group=48;CHECK(sreg(&r,26,&st,1)==0&&st.head==1);zero(&reg,sizeof(reg));reg.bgid=48;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0&&CALL(N_MUNMAP,(void *)m,4096,0)==0);return finish(&r);
}

static int pbuf_legacy_submit(struct ring *r,unsigned char op,unsigned char flags,
 int count,u64 off,void *addr,u32 len,unsigned short bgid,unsigned short ioprio,
 u32 rw_flags,int splice_fd_in,u64 addr3,u64 pad,u64 ud,int expected) {
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=op;q.flags=flags;q.fd=count;
 q.off=off;q.addr=(u64)addr;q.len=len;q.buf=bgid;q.ioprio=ioprio;
 q.misc=rw_flags;q.fd2=splice_fd_in;q.addr3=addr3;q.pad=pad;q.ud=ud;
 queue(r,q,0);CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0);
 CHECK(c.ud==ud&&c.res==expected);return 0;
}
static int provided_buffer_options_shared(void) {
 struct ring r;struct pbuf_reg reg;static char pool[32];
 CHECK(init(&r,0,16)==0);
 /* Never-created and persistent empty groups are observably different. */
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,0,0,0,1,-2)==0);
 /* Linux-v6.18 count, length, address, bid-range, and reserved-field rules. */
 CHECK(pbuf_legacy_submit(&r,31,0,0,0,pool,8,77,0,0,0,0,0,2,-7)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,-1,0,pool,8,77,0,0,0,0,0,3,-7)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,65537,0,pool,8,77,0,0,0,0,0,4,-7)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,0,77,0,0,0,0,0,5,-22)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,65536,pool,8,77,0,0,0,0,0,6,-7)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,2,65535,pool,8,77,0,0,0,0,0,7,-22)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,2,0,(void *)(~0UL-3),8,77,0,0,0,0,0,8,-OVERFLOW)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,77,1,0,0,0,0,9,-22)==0);
 CHECK(pbuf_legacy_submit(&r,31,32,1,0,pool,8,77,0,0,0,0,0,10,-NOTSUP)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,77,0,1,0,0,0,11,-22)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,77,0,0,1,0,0,12,-22)==0);
 /* ASYNC and tail words are legal. Linux alone ignores FIXED_FILE here. */
 CHECK(pbuf_legacy_submit(&r,31,16,2,10,pool,8,77,0,0,0,0x1234,0x5678,16,0)==0);
#ifdef LINUX_ABI
 CHECK(pbuf_legacy_submit(&r,32,1,1,0,0,0,77,0,0,0,0,0,17,1)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,100,0,0,0,77,0,0,0,0,0,18,1)==0);
#else
 CHECK(pbuf_legacy_submit(&r,31,1,1,12,pool,8,77,0,0,0,0,0,17,-9)==0);
 CHECK(pbuf_legacy_submit(&r,32,1,1,0,0,0,77,0,0,0,0,0,18,-9)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,100,0,0,0,77,0,0,0,0,0,27,2)==0);
#endif
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,0,0,0,19,0)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,20,pool,8,77,0,0,0,0,0,20,0)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,0,0,0,21,1)==0);
 /* Registration replaces an empty classic group, but rejects a live one. */
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=77;reg.flags=1;
 CHECK(sreg(&r,22,&reg,1)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,77,0,0,0,0,0,22,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,0,0,0,23,-22)==0);
 zero(&reg,sizeof(reg));reg.bgid=77;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,0,0,0,24,-2)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,79,0,0,0,0,0,25,0)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=79;reg.flags=1;
 CHECK(sreg(&r,22,&reg,1)==-17);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,79,0,0,0,0,0,26,1)==0);
 /* REMOVE validates count and every otherwise-unused SQE union field. */
 CHECK(pbuf_legacy_submit(&r,32,0,0,0,0,0,77,0,0,0,0,0,32,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,65537,0,0,0,77,0,0,0,0,0,33,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,1,0,0,77,0,0,0,0,0,34,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,pool,0,77,0,0,0,0,0,35,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,1,77,0,0,0,0,0,36,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,1,0,0,0,0,37,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,1,0,0,0,38,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,77,0,0,1,0,0,39,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,32,1,0,0,0,77,0,0,0,0,0,40,-NOTSUP)==0);
 /* Legacy operations cannot target a registered provided-buffer ring. */
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=78;reg.flags=1;
 CHECK(sreg(&r,22,&reg,1)==0);
 CHECK(pbuf_legacy_submit(&r,31,0,1,0,pool,8,78,0,0,0,0,0,48,-22)==0);
 CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,78,0,0,0,0,0,49,-22)==0);
 zero(&reg,sizeof(reg));reg.bgid=78;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(lhealth(&r)==0);return finish(&r);
}

static int provided_buffer_race_shared(void) {
 static char pool[64];
 for(int n=0;n<64;n++) {
  struct ring r;struct pbuf_reg reg;struct sqe q;struct cqe c;int go[2],result[2],status,child_res=999;
  CHECK(init(&r,0,8)==0&&bpipe(go,0)==0&&bpipe(result,0)==0);
  long pid=fork_child();CHECK(pid>=0);
  if(pid==0) {
   char token;
   if(CALL(N_READ,go[0],&token,1)!=1)CALL(N_EXIT,90,0,0);
   zero(&q,sizeof(q));q.op=31;q.fd=1;q.addr=(u64)pool;q.len=1;q.buf=80;q.ud=1;
   queue(&r,q,0);
   if(lsubmit(&r,1)!=0||lget(&r,&c,1)!=0||c.ud!=1)CALL(N_EXIT,91,0,0);
   child_res=c.res;
   if(CALL(N_WRITE,result[1],&child_res,sizeof(child_res))!=sizeof(child_res))CALL(N_EXIT,92,0,0);
   CALL(N_EXIT,0,0,0);
  }
  CHECK(CALL(N_WRITE,go[1],"R",1)==1);
  zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=80;reg.flags=1;
  long registered=sreg(&r,22,&reg,1);
  CHECK(CALL(N_READ,result[0],&child_res,sizeof(child_res))==sizeof(child_res));
  CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
  CHECK((registered==0&&child_res==-22)||(registered==-17&&child_res==0));
  r.si=__atomic_load_n(r.st,__ATOMIC_ACQUIRE);
  r.ci=__atomic_load_n(r.ch,__ATOMIC_ACQUIRE);
  if(registered==0) {
   zero(&reg,sizeof(reg));reg.bgid=80;CHECK(sreg(&r,23,&reg,1)==0);
  } else {
   CHECK(pbuf_legacy_submit(&r,32,0,1,0,0,0,80,0,0,0,0,0,2,1)==0);
  }
  CHECK(lhealth(&r)==0&&finish(&r)==0);
  CHECK(CALL(N_CLOSE,go[0],0,0)==0&&CALL(N_CLOSE,go[1],0,0)==0);
  CHECK(CALL(N_CLOSE,result[0],0,0)==0&&CALL(N_CLOSE,result[1],0,0)==0);
 }
 return 0;
}

static int prep_ioprio(void) {
 static const unsigned char ops[]={0,3,6,7,8,11,12,14,15,16,17,18,19,20,21,24,25,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,49,50,51,52,53,54,55,56,57,59,62};
 for(u32 i=0;i<sizeof(ops);i++){struct sqe q;zero(&q,sizeof(q));q.op=ops[i];q.fd=-1;q.ioprio=1;CHECK(prep_reject_one(q,-22)==0);}
 return 0;
}
static void prep_set(struct sqe *q,int field) {
 switch(field){case 0:q->off=1;break;case 1:q->addr=1;break;case 2:q->len=1;break;case 3:q->misc=0x80000000U;break;case 4:q->buf=1;break;case 5:q->fd2=1;break;case 6:q->addr3=1;break;case 7:q->pad=1;break;case 8:q->fd=1;break;}
}
static int prep_reserved_core(void) {
 /* One Linux-v6.18-reserved field per row; repeated rows cover every union. */
 static const unsigned char rows[][2]={
  {3,1},{3,4},{3,5},{8,1},{8,4},{8,5},{17,4},{17,3},{17,5},
  {55,3},{55,1},{55,2},{55,4},{55,5},{55,6},{24,4},{24,5},
  {19,0},{19,1},{19,2},{19,3},{19,4},{6,4},{6,0},{6,1},{7,4},{7,5},
  {11,4},{11,5},{12,4},{12,2},{12,5},{14,0},{14,5},{31,3},{31,5},
  {32,3},{32,1},{32,2},{32,0},{32,5},{40,4},{49,1},{49,2},
  {54,0},{54,1},{54,2},{54,4},{54,5}
 };
 for(u32 i=0;i<sizeof(rows)/sizeof(rows[0]);i++){struct sqe q;struct ltime ts={0,1};zero(&q,sizeof(q));q.op=rows[i][0];q.fd=-1;if(q.op==11){q.len=1;q.addr=(u64)&ts;}if(q.op==49)q.flags=32;prep_set(&q,rows[i][1]);CHECK(prep_reject_one(q,-22)==0);}
 {struct sqe q;zero(&q,sizeof(q));q.op=3;q.fd=-1;q.misc=2;CHECK(prep_reject_one(q,-22)==0);}
 return 0;
}
static int prep_reserved_linux(void) {
 static const unsigned char rows[][2]={
  {33,0},{33,1},{59,0},{59,3},{59,4},{59,5},{50,1},{50,4},{50,6},{50,3},
  {18,4},{28,4},{21,4},{21,5},{35,4},{35,5},{36,0},{36,2},{36,4},{36,5},
  {37,0},{37,3},{37,4},{37,5},{38,2},{38,3},{38,4},{38,5},{39,4},{39,5},
  {25,4},{25,5},{29,4},{29,5},{45,1},{45,3},{45,4},{16,2},{16,4},{16,3},{16,5},
  {56,2},{56,4},{56,3},{56,5},{13,2},{13,4},{57,1},{57,4},{57,3},{57,5},{57,0},
  {34,0},{34,1},{34,3},{34,4},{34,5},{10,0},{47,7},{48,7},{62,8},{62,0},{62,6},
  {51,2},{51,3},{51,4},{51,5},{52,2},{52,3},{52,4},{52,5}
 };
 for(u32 i=0;i<sizeof(rows)/sizeof(rows[0]);i++){struct sqe q;zero(&q,sizeof(q));q.op=rows[i][0];q.fd=-1;if(q.op==62)q.fd=0;prep_set(&q,rows[i][1]);CHECK(prep_reject_one(q,-22)==0);}
 return 0;
}
static int prep_buffer_select(void) {
 static const unsigned char rejected[]={0,2,3,4,5,6,7,8,9,11,12,13,14,15,16,17,18,19,20,21,23,24,25,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,47,48,50,51,52,53,54,55,56,57,59,60,61,62};
 for(u32 i=0;i<sizeof(rejected);i++){struct sqe q;zero(&q,sizeof(q));q.op=rejected[i];q.flags=32;q.fd=-1;int e=prep_reject_one(q,-NOTSUP);if(e){put("buffer op=");putnum(q.op);put(" line=");putnum(e);put("\n");return e;}}
 return 0;
}
static int prep_rwflags(void) {
 static const unsigned char ops[]={22,23};long fd=sc(N_OPENAT,-100,(long)"prep-rwflags",OPENFLAGS,0600,0,0);CHECK(fd>=0);
 for(u32 i=0;i<sizeof(ops);i++){struct ring r;struct sqe q;struct cqe c[2];CHECK(init(&r,0,8)==0);zero(&q,sizeof(q));q.op=ops[i];q.fd=fd;q.addr=(u64)"X";q.len=1;q.misc=0x80000000U;q.ud=1;queue(&r,q,0);zero(&q,sizeof(q));q.ud=2;queue(&r,q,0);long n=sc(N_ENTER,r.fd,2,0,0,0,0);int e=n==2?lget(&r,c,2):999;if(n!=2||e||lresult(c,2,1,-NOTSUP)!=0||lresult(c,2,2,0)!=0){put("rwflags op=");putnum(q.op);put(" n=");putnum(n);put(" get=");putnum(e);put("\n");return __LINE__;}CHECK(finish(&r)==0);}
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;
}
static int prep_positive(void) {
 static const struct {unsigned char op;unsigned short prio;} rows[]={{1,0x4004},{2,0x4004},{4,0x4004},{5,0x4004},{9,1},{10,1},{13,2},{22,0x4004},{23,0x4004},{26,1},{27,1},{60,0x4004},{61,0x4004}};
 for(u32 i=0;i<sizeof(rows)/sizeof(rows[0]);i++){struct ring r;struct sqe q;struct cqe c[3];CHECK(init(&r,SALL,8)==0);zero(&q,sizeof(q));q.op=rows[i].op;q.ioprio=rows[i].prio;q.fd=-1;q.ud=1;queue(&r,q,0);zero(&q,sizeof(q));q.ud=2;queue(&r,q,0);long n=sc(N_ENTER,r.fd,2,0,0,0,0);if(n!=2){put("positive op=");putnum(q.op);put(" submitted=");putnum(n);put("\n");return __LINE__;}int e=lget(&r,c,2);if(e){put("positive op=");putnum(rows[i].op);put(" get line=");putnum(e);put("\n");return e;}e=lresult(c,2,2,0);if(e){put("positive op=");putnum(rows[i].op);put(" result line=");putnum(e);put("\n");return e;}CHECK(finish(&r)==0);}
 return 0;
}
static int prep_buffer_runtime(void) {
 static char pool[64];struct ring r;struct sqe q;struct cqe c;struct viov iov[2];long fd=sc(N_OPENAT,-100,(long)"prep-bufrun",OPENFLAGS,0600,0,0);CHECK(fd>=0&&CALL(N_WRITE,fd,"runtime",7)==7&&init(&r,0,8)==0);
 zero(&q,sizeof(q));q.op=31;q.fd=1;q.addr=(u64)pool;q.len=sizeof(pool);q.off=17;q.buf=12;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==0);
 iov[0].base=(void *)1;iov[0].len=4;iov[1]=iov[0];zero(&q,sizeof(q));q.op=1;q.flags=32;q.fd=fd;q.off=0;q.addr=(u64)iov;q.len=2;q.buf=12;q.ud=2;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-22);
 q.addr=1;q.len=1;q.ud=3;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-14);
 q.addr=(u64)iov;q.ud=4;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lwait(&r,1)==0);c=r.cqes[r.ci&(r.p.cq-1)];__atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);CHECK(c.res==4&&(c.flags&1)!=0&&(c.flags>>16)==17&&pool[0]=='r'&&pool[1]=='u'&&pool[2]=='n'&&pool[3]=='t');
 CHECK(CALL(N_CLOSE,fd,0,0)==0&&finish(&r)==0);return 0;
}
static int prep_fixed_file(void) {
 static const unsigned char rejected[]={18,28,19,21,35,36,37,38,39,42,44};
 for(u32 i=0;i<sizeof(rejected);i++){struct sqe q;u64 how[3]={0,0,0};zero(&q,sizeof(q));q.op=rejected[i];q.flags=1;q.fd=0;if(q.op==28){q.off=(u64)how;q.len=sizeof(how);}int e=prep_reject_one(q,-9);if(e){put("fixed op=");putnum(q.op);put(" line=");putnum(e);put("\n");return e;}}
 {struct sqe q;zero(&q,sizeof(q));q.op=54;q.fd=0;int e=prep_reject_one(q,-9);if(e){put("fixed install line=");putnum(e);put("\n");return e;}}
 {struct ring r;struct sqe q;struct cqe c;long fd=fdata("prep-install",'I');char b=0;CHECK(fd>=0&&CALL(N_CLOSE,fd,0,0)==0);fd=sc(N_OPENAT,-100,(long)"prep-install",0,0,0,0);int one=(int)fd;CHECK(fd>=0&&init(&r,0,8)==0&&freg(&r,&one,1)==0);zero(&q,sizeof(q));q.op=54;q.flags=1;q.fd=0;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==1&&c.res>=0);CHECK(CALL(N_READ,c.res,&b,1)==1&&b=='I'&&CALL(N_CLOSE,c.res,0,0)==0);CHECK(funreg(&r)==0&&finish(&r)==0&&CALL(N_CLOSE,fd,0,0)==0);}
 return 0;
}
static int prep_links(void) {
 struct ring r;struct sqe q;struct cqe c[3];long fd=sc(N_OPENAT,-100,(long)"prep-link",OPENFLAGS,0600,0,0);CHECK(fd>=0&&init(&r,SALL,8)==0);zero(&q,sizeof(q));q.op=23;q.flags=4;q.fd=fd;q.addr=(u64)"BAD";q.len=3;q.ud=1;queue(&r,q,0);zero(&q,sizeof(q));q.op=3;q.flags=4;q.fd=fd;q.addr=1;q.ud=2;queue(&r,q,0);zero(&q,sizeof(q));q.op=23;q.fd=fd;q.addr=(u64)"BAD";q.len=3;q.ud=3;queue(&r,q,0);CHECK(lsubmit(&r,3)==0&&lget(&r,c,3)==0&&lresult(c,3,1,-CANCELED)==0&&lresult(c,3,2,-22)==0&&lresult(c,3,3,-CANCELED)==0);char b;CHECK(CALL(N_READ,fd,&b,1)==0);CHECK(finish(&r)==0&&CALL(N_CLOSE,fd,0,0)==0);return 0;
}

static int files_cycles(void) {
 for(int mode=0;mode<3;mode++){struct ring r,other;CHECK(init(&r,0,8)==0);int fd=r.fd;long alias=-1;if(mode==1){alias=CALL(N_DUP,r.fd,0,0);CHECK(alias>=0);fd=alias;}if(mode==2){CHECK(init(&other,0,8)==0);fd=other.fd;}
 CHECK(freg(&r,&fd,1)==-9);int empty=-1;CHECK(freg(&r,&empty,1)==0&&funreg(&r)==0&&lhealth(&r)==0&&finish(&r)==0);if(mode==1)CHECK(CALL(N_CLOSE,alias,0,0)==0);if(mode==2)CHECK(finish(&other)==0);}
 return 0;
}
static int files_update_cycles(void) {
 for(int sqe=0;sqe<2;sqe++)for(int other=0;other<2;other++){struct ring r,t;CHECK(init(&r,0,8)==0);int fd=-1;CHECK(freg(&r,&fd,1)==0);if(other){CHECK(init(&t,0,8)==0);fd=t.fd;}else fd=r.fd;
 CHECK(fupdate(&r,sqe,0,&fd,1)==-9&&fbyte(&r,0,-9)==0&&funreg(&r)==0&&finish(&r)==0);if(other)CHECK(finish(&t)==0);}
 return 0;
}
static int files_skip(void) {
 long fd=fdata("skip",'A');CHECK(fd>=0);
 for(int sqe=0;sqe<2;sqe++){struct ring r;int fds[3]={fd,fd,fd},up[3]={-2,-1,-2};CHECK(init(&r,0,8)==0&&freg(&r,fds,3)==0);CHECK(fupdate(&r,sqe,0,up,3)==3);CHECK(fbyte(&r,0,'A')==0&&fbyte(&r,1,-9)==0&&fbyte(&r,2,'A')==0);up[1]=-2;CHECK(fupdate(&r,sqe,0,up,3)==3&&fbyte(&r,1,-9)==0);CHECK(funreg(&r)==0&&finish(&r)==0);}
 CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;
}
static int files_partial(void) {
 long a=fdata("partial-a",'A'),b=fdata("partial-b",'B');CHECK(a>=0&&b>=0);
 for(int sqe=0;sqe<2;sqe++){struct ring r;int fds[3]={a,a,a},up[3]={b,-123,b};CHECK(init(&r,0,8)==0&&freg(&r,fds,3)==0);CHECK(fupdate(&r,sqe,0,up,3)==1);CHECK(fbyte(&r,0,'B')==0&&fbyte(&r,1,-9)==0&&fbyte(&r,2,'A')==0);up[0]=-123;CHECK(fupdate(&r,sqe,0,up,1)==-9&&fbyte(&r,0,-9)==0);CHECK(funreg(&r)==0&&finish(&r)==0);}
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0);return 0;
}
static int files_faults(void) {
 long a=fdata("fault-a",'A'),b=fdata("fault-b",'B');CHECK(a>=0&&b>=0);
 for(int mode=0;mode<5;mode++){struct ring r;CHECK(init(&r,0,8)==0);long mem=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(mem>0);int *fds=(int *)(mem+(mode==2?4092:0));fds[0]=a;if(mode==2)fds[1]=b;
 if(mode==0)CHECK(CALL(N_MPROTECT,mem,8192,0)==0);if(mode==1)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);if(mode==2)CHECK(CALL(N_MPROTECT,mem+4096,4096,0)==0);if(mode==3)CHECK(CALL(N_MPROTECT,mem,8192,1)==0);
 CHECK(freg(&r,mode==4?(int *)1:fds,mode==2?2:1)==(mode==3?0:-14));if(mode!=3){int valid=a;CHECK(freg(&r,&valid,1)==0);}CHECK(fbyte(&r,0,'A')==0&&funreg(&r)==0&&finish(&r)==0);if(mode!=1)CHECK(CALL(N_MUNMAP,mem,8192,0)==0);}
 for(int sqe=0;sqe<2;sqe++){struct ring r;int fds[2]={a,a};CHECK(init(&r,0,8)==0&&freg(&r,fds,2)==0);long mem=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(mem>0);int *up=(int *)(mem+4092);up[0]=b;CHECK(CALL(N_MPROTECT,mem+4096,4096,0)==0);CHECK(fupdate(&r,sqe,0,up,2)==1);CHECK(fbyte(&r,0,'B')==0&&fbyte(&r,1,'A')==0);CHECK(fupdate(&r,sqe,0,(int *)1,1)==-14&&fbyte(&r,0,'B')==0);CHECK(funreg(&r)==0&&finish(&r)==0&&CALL(N_MUNMAP,mem,8192,0)==0);}
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0);return 0;
}
static int files_validation(void) {
 long a=fdata("validate-a",'A'),b=fdata("validate-b",'B');CHECK(a>=0&&b>=0);
 struct ring r;int empty=-1;CHECK(init(&r,0,8)==0);CHECK(freg(&r,0,1)==-14&&freg(&r,&empty,0)==-22);CHECK(funreg(&r)==-6);
 for(int sqe=0;sqe<2;sqe++){CHECK(fupdate(&r,sqe,0,&empty,1)==-6);CHECK(fupdate(&r,sqe,0,&empty,0)==-22);}
 CHECK(freg(&r,&empty,1)==0);struct fupdate up={0,1,(u64)&empty};CHECK(sreg(&r,6,&up,1)==-22);CHECK(sreg(&r,3,(void *)1,0)==-22&&sreg(&r,3,0,1)==-22);
 for(int sqe=0;sqe<2;sqe++){CHECK(fupdate(&r,sqe,1,&empty,1)==-22);CHECK(fupdate(&r,sqe,0xfffffffeU,&empty,3)==-FOVERFLOW);}
 CHECK(funreg(&r)==0);int bad[2]={-1,-2};CHECK(freg(&r,bad,2)==-9&&freg(&r,&empty,1)==0&&funreg(&r)==0);
 for(int all=0;all<2;all++)for(int mode=0;mode<6;mode++){struct ring t;int initial=a,replacement=b;struct sqe q;struct cqe c[2];CHECK(init(&t,all?SALL:0,8)==0);CHECK(freg(&t,&initial,1)==0);zero(&q,sizeof(q));q.op=20;q.addr=(u64)&replacement;q.len=1;q.ud=1;if(mode==0)q.flags=1;if(mode==1)q.flags=32;if(mode==2)q.misc=1;if(mode==3)q.fd2=1;if(mode==4)q.len=0;if(mode==5)q.flags=33;queue(&t,q,0);lq(&t,0,0,-1,0,0,0,2);__atomic_store_n(t.st,t.si,__ATOMIC_RELEASE);
 long submitted=sc(N_ENTER,t.fd,2,0,0,0,0);if(submitted!=(all?2:1)){put("files prep mode=");putnum(mode);put(" all=");putnum(all);put(" submitted=");putnum(submitted);put("\n");}CHECK(submitted==(all?2:1));CHECK(lget(&t,c,all?2:1)==0&&lresult(c,all?2:1,1,mode==1||mode==5?-NOTSUP:-22)==0);if(all)CHECK(lresult(c,2,2,0)==0);else CHECK(lsubmit(&t,1)==0&&lget(&t,c,1)==0&&c[0].res==0);CHECK(fbyte(&t,0,'A')==0&&funreg(&t)==0&&finish(&t)==0);}
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0);return finish(&r);
}
static int files_lifetime(void) {
 struct ring r;long a=fdata("life-a",'A'),b=fdata("life-b",'B');CHECK(a>=0&&b>=0&&init(&r,0,8)==0);int fds[2]={a,a};CHECK(freg(&r,fds,2)==0&&CALL(N_CLOSE,a,0,0)==0);CHECK(fbyte(&r,0,'A')==0&&fbyte(&r,1,'A')==0);int fd=b;CHECK(fupdate(&r,1,0,&fd,1)==1&&CALL(N_CLOSE,b,0,0)==0);CHECK(fbyte(&r,0,'B')==0&&fbyte(&r,1,'A')==0);CHECK(funreg(&r)==0&&fbyte(&r,0,-9)==0&&funreg(&r)==-6);return finish(&r);
}
static int files_update_alloc_shared(void) {
 struct ring r;struct lfile_range range={1,2,0};struct sqe q;struct cqe c;int sparse[4]={-1,-1,-1,-1},pair[2],clear[2]={-1,-1};long a=fdata("alloc-a",'A'),b=fdata("alloc-b",'B'),m;
 CHECK(a>=0&&b>=0&&init(&r,0,8)==0);pair[0]=(int)a;CHECK(fupdate(&r,1,0xffffffffU,pair,1)==-6&&pair[0]==a);
 CHECK(freg(&r,sparse,4)==0&&sreg(&r,25,&range,0)==0);pair[0]=(int)a;pair[1]=(int)b;
 CHECK(fupdate(&r,1,0xffffffffU,pair,2)==2&&pair[0]==1&&pair[1]==2);
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0&&fbyte(&r,1,'A')==0&&fbyte(&r,2,'B')==0);
 a=fdata("alloc-full",'X');CHECK(a>=0);pair[0]=(int)a;CHECK(fupdate(&r,1,0xffffffffU,pair,1)==-23&&pair[0]==a);CHECK(CALL(N_CLOSE,a,0,0)==0);
 CHECK(fupdate(&r,0,1,clear,2)==2);a=fdata("alloc-c",'C');CHECK(a>=0);pair[0]=(int)a;
 zero(&q,sizeof(q));q.op=20;q.flags=16;q.off=0xffffffffU;q.addr=(u64)pair;q.len=1;q.ud=73;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==73&&c.res==1&&pair[0]==2);
 CHECK(CALL(N_CLOSE,a,0,0)==0&&fbyte(&r,2,'C')==0&&fupdate(&r,0,1,clear,2)==2);
 a=fdata("alloc-fault",'F');CHECK(a>=0);m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);*(int *)m=(int)a;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0);CHECK(fupdate(&r,1,0xffffffffU,(int *)m,1)==-14);
 CHECK(CALL(N_MPROTECT,m,4096,3)==0&&fbyte(&r,1,-9)==0&&fbyte(&r,2,-9)==0);
 CHECK(CALL(N_MUNMAP,m,4096,0)==0&&CALL(N_CLOSE,a,0,0)==0&&funreg(&r)==0&&finish(&r)==0);return 0;
}
static int files_race(void) {
 struct ring r;long fd=fdata("race",'A');int fds[128],sync[2],status;for(int i=0;i<128;i++)fds[i]=fd;CHECK(fd>=0&&init(&r,0,8)==0&&freg(&r,fds,128)==0&&bpipe(sync,0)==0);
 long pid=fork_child();CHECK(pid>=0);if(pid==0){char x;CALL(N_READ,sync[0],&x,1);for(int n=0;n<512;n++){if(funreg(&r)!=0||freg(&r,fds,128)!=0)CALL(N_EXIT,1,0,0);}CALL(N_EXIT,0,0,0);}
 CHECK(CALL(N_WRITE,sync[1],"R",1)==1);int bad=0;for(int n=0;n<512;n++){long rc=fupdate(&r,1,0,fds,128);if(rc!=128&&rc!=-6)bad=1;}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0&&bad==0);CHECK(fbyte(&r,127,'A')==0&&funreg(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd,0,0);CALL(N_CLOSE,sync[0],0,0);CALL(N_CLOSE,sync[1],0,0);return 0;
}
static int files_read_race(void) {
 struct ring r;long a=fdata("read-race-a",'A'),b=fdata("read-race-b",'B');int fd=a,status;CHECK(a>=0&&b>=0&&init(&r,0,8)==0&&freg(&r,&fd,1)==0);long pid=fork_child();CHECK(pid>=0);if(pid==0){for(int n=0;n<512;n++){fd=n&1?a:b;if(fupdate(&r,0,0,&fd,1)!=1)CALL(N_EXIT,1,0,0);}CALL(N_EXIT,0,0,0);}
 for(int n=0;n<512;n++){struct sqe q;struct cqe c;char data=0;zero(&q,sizeof(q));q.op=22;q.flags=1;q.fd=0;q.addr=(u64)&data;q.len=1;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0);CHECK(c.res==1&&(data=='A'||data=='B'));}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0&&funreg(&r)==0&&finish(&r)==0);CALL(N_CLOSE,a,0,0);CALL(N_CLOSE,b,0,0);return 0;
}
static int files_permissions(void) {
 struct ring r;long fd=fdata("permissions",'A');CHECK(fd>=0&&CALL(N_CLOSE,fd,0,0)==0);fd=sc(N_OPENAT,-100,(long)"permissions",0,0,0,0);CHECK(fd>=0&&init(&r,0,8)==0);int file=fd;CHECK(freg(&r,&file,1)==0&&CALL(N_CLOSE,fd,0,0)==0);struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=23;q.flags=1;q.fd=0;q.addr=(u64)"B";q.len=1;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-9&&fbyte(&r,0,'A')==0);CHECK(funreg(&r)==0);return finish(&r);
}
#ifndef LINUX_ABI
static int files_capmode_poll_child(void) {
 struct ring r;struct sqe q;struct cqe c;int fd[2];
 CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0&&freg(&r,&fd[0],1)==0);
 CHECK(CALL(SYS_cap_enter,0,0,0)==0);
 /* A raw fd must not escape the registered capability set. */
 zero(&q,sizeof(q));q.op=6;q.fd=fd[0];q.misc=1;q.ud=1;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==1&&c.res==-ENOTCAPABLE);
 /* The registered file remains usable for the same poll. */
 CHECK(CALL(N_WRITE,fd[1],"P",1)==1);
 zero(&q,sizeof(q));q.op=6;q.flags=1;q.fd=0;q.misc=1;q.ud=2;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==2&&(c.res&1));
 CHECK(lhealth(&r)==0&&funreg(&r)==0&&finish(&r)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0);
 return 0;
}
#endif
static int files_caps(void) {
#ifdef LINUX_ABI
 return files_permissions(); /* Capsicum assertions are native-only. */
#else
 struct ring r;int fd[2];CHECK(init(&r,0,8)==0&&bpipe(fd,0)==0);cap_rights_t rights;cap_rights_init(&rights,CAP_READ,CAP_IOCTL);unsigned long cmd=FIONREAD;CHECK(cap_rights_limit(fd[0],&rights)==0&&cap_ioctls_limit(fd[0],&cmd,1)==0);CHECK(freg(&r,&fd[0],1)==0&&CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_WRITE,fd[1],"C",1)==1);
 struct sqe q;struct cqe c;char data=0;zero(&q,sizeof(q));q.op=22;q.flags=1;q.addr=(u64)&data;q.len=1;q.off=~0UL;q.ud=1;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==1&&data=='C');q.op=23;q.ud=2;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-ENOTCAPABLE);
 /* A held-file poll still requires CAP_EVENT from the registered file. */
 zero(&q,sizeof(q));q.op=6;q.flags=1;q.fd=0;q.misc=1;q.ud=3;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-ENOTCAPABLE);
 CHECK(funreg(&r)==0&&finish(&r)==0);CALL(N_CLOSE,fd[1],0,0);
 int status;long pid=fork_child();CHECK(pid>=0);
 if(pid==0)CALL(N_EXIT,files_capmode_poll_child()!=0,0,0);
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 return 0;
#endif
}
static int files_exit(void) {
 long fd=fdata("exit",'X');CHECK(fd>=0);for(int n=0;n<32;n++){int status;long pid=fork_child();CHECK(pid>=0);if(pid==0){struct ring r;int fds[4]={fd,fd,fd,fd};if(init(&r,0,8)!=0||freg(&r,fds,4)!=0||fbyte(&r,3,'X')!=0)CALL(N_EXIT,1,0,0);CALL(N_EXIT,0,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);}CHECK(CALL(N_CLOSE,fd,0,0)==0);return 0;
}


/* Extended registered files and generation-lifetime tags. */
struct frsrc_register {u32 nr,flags;u64 resv2,data,tags;};
struct frsrc_update2 {u32 offset,resv;u64 data,tags;u32 nr,resv2;};
_Static_assert(sizeof(struct frsrc_register)==32,"resource register ABI");
_Static_assert(sizeof(struct frsrc_update2)==32,"resource update ABI");
static long freg2(struct ring *r,struct frsrc_register *rr,u32 size) {return sreg(r,13,rr,size);}
static long fupdate2(struct ring *r,struct frsrc_update2 *up,u32 size) {return sreg(r,14,up,size);}
static int cq_empty(struct ring *r) {CHECK(__atomic_load_n(r->ct,__ATOMIC_ACQUIRE)==r->ci);return 0;}
static int files_v2_shared(void) {
 struct ring r;struct frsrc_register rr;struct frsrc_update2 up;struct cqe c[4];
 long a=fdata("files2-a",'A'),b=fdata("files2-b",'B'),m;u64 tags[4];int fds[4];
 CHECK(a>=0&&b>=0&&init(&r,0,16)==0);
 /* Exact structure size and all top-level validation are side-effect free. */
 zero(&rr,sizeof(rr));rr.nr=1;rr.flags=1;
 CHECK(freg2(&r,&rr,0)==-22&&freg2(&r,&rr,31)==-22&&freg2(&r,&rr,33)==-22);
 CHECK(freg2(&r,0,sizeof(rr))==-14);rr.nr=0;CHECK(freg2(&r,&rr,sizeof(rr))==-22);
 rr.nr=1;rr.flags=2;CHECK(freg2(&r,&rr,sizeof(rr))==-22);rr.flags=1;rr.resv2=1;CHECK(freg2(&r,&rr,sizeof(rr))==-22);
 rr.resv2=0;rr.data=(u64)&fds[0];CHECK(freg2(&r,&rr,sizeof(rr))==-22);
 rr.data=0;rr.nr=4097;CHECK(freg2(&r,&rr,sizeof(rr))==-24);
 rr.nr=1;rr.flags=0;rr.data=1;CHECK(freg2(&r,&rr,sizeof(rr))==-14);
 fds[0]=-1;tags[0]=101;rr.data=(u64)fds;rr.tags=(u64)tags;CHECK(freg2(&r,&rr,sizeof(rr))==-22&&funreg(&r)==-6&&cq_empty(&r)==0);
 fds[0]=(int)r.fd;tags[0]=0;CHECK(freg2(&r,&rr,sizeof(rr))==-9&&funreg(&r)==-6);
 fds[0]=(int)a;fds[1]=-123;tags[0]=111;tags[1]=222;rr.nr=2;
 CHECK(freg2(&r,&rr,sizeof(rr))==-9&&funreg(&r)==-6&&cq_empty(&r)==0);
 /* Faulting structures and arrays do not publish a table or tag CQEs. */
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_register *cross=(void *)(m+4096-16);zero(cross,16);
 CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&freg2(&r,cross,sizeof(*cross))==-14&&funreg(&r)==-6&&CALL(N_MUNMAP,m,8192,0)==0);
 rr.nr=1;rr.data=(u64)fds;rr.tags=1;CHECK(freg2(&r,&rr,sizeof(rr))==-14&&funreg(&r)==-6&&cq_empty(&r)==0);
 /* A read-only descriptor is valid input; duplicate registration is busy. */
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_register *ro=(void *)m;zero(ro,sizeof(*ro));ro->nr=1;ro->flags=1;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&freg2(&r,ro,sizeof(*ro))==0&&freg2(&r,ro,sizeof(*ro))==-16);
 CHECK(funreg(&r)==0&&CALL(N_MUNMAP,m,4096,0)==0&&cq_empty(&r)==0);
 /* Sparse slots, UPDATE2 validation, and tag/skip rules. */
 zero(&rr,sizeof(rr));rr.nr=4;rr.flags=1;CHECK(freg2(&r,&rr,sizeof(rr))==0);
 for(int i=0;i<4;i++)CHECK(fbyte(&r,i,-9)==0);
 zero(&up,sizeof(up));up.nr=1;up.data=(u64)fds;
 CHECK(fupdate2(&r,&up,0)==-22&&fupdate2(&r,&up,31)==-22&&fupdate2(&r,&up,33)==-22&&fupdate2(&r,0,sizeof(up))==-14);
 up.nr=0;CHECK(fupdate2(&r,&up,sizeof(up))==-22);up.nr=1;up.resv=1;CHECK(fupdate2(&r,&up,sizeof(up))==-22);
 up.resv=0;up.resv2=1;CHECK(fupdate2(&r,&up,sizeof(up))==-22);up.resv2=0;up.offset=0xffffffffU;up.nr=2;CHECK(fupdate2(&r,&up,sizeof(up))==-FOVERFLOW);
 up.offset=4;up.nr=1;CHECK(fupdate2(&r,&up,sizeof(up))==-22);up.offset=0;up.data=1;CHECK(fupdate2(&r,&up,sizeof(up))==-14);
 fds[0]=(int)a;up.data=(u64)fds;up.tags=1;CHECK(fupdate2(&r,&up,sizeof(up))==-14&&fbyte(&r,0,-9)==0);
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_update2 *ucross=(void *)(m+4096-16);zero(ucross,16);
 CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&fupdate2(&r,ucross,sizeof(*ucross))==-14&&CALL(N_MUNMAP,m,8192,0)==0);
 fds[0]=(int)a;fds[1]=(int)b;tags[0]=1001;tags[1]=1002;zero(&up,sizeof(up));up.data=(u64)fds;up.tags=(u64)tags;up.nr=2;
 CHECK(fupdate2(&r,&up,sizeof(up))==2&&fbyte(&r,0,'A')==0&&fbyte(&r,1,'B')==0);
 fds[0]=-2;tags[0]=9;up.nr=1;CHECK(fupdate2(&r,&up,sizeof(up))==-22&&fbyte(&r,0,'A')==0);
 fds[0]=-1;CHECK(fupdate2(&r,&up,sizeof(up))==-22&&fbyte(&r,0,'A')==0);
 /* Replacement and clearing publish the detached generations' tags. */
 fds[0]=(int)b;tags[0]=2001;CHECK(fupdate2(&r,&up,sizeof(up))==1&&lget(&r,c,1)==0&&c[0].ud==1001&&c[0].res==0);
 up.offset=1;fds[0]=-1;tags[0]=0;CHECK(fupdate2(&r,&up,sizeof(up))==1&&lget(&r,c,1)==0&&c[0].ud==1002&&c[0].res==0);
 /* A later bad fd returns the prefix and clears its destination. */
 up.offset=1;up.nr=3;fds[0]=(int)a;fds[1]=-123;fds[2]=(int)b;tags[0]=3001;tags[1]=3002;tags[2]=3003;
 CHECK(fupdate2(&r,&up,sizeof(up))==1&&fbyte(&r,0,'B')==0&&fbyte(&r,1,'A')==0&&fbyte(&r,2,-9)==0&&fbyte(&r,3,-9)==0);
 /* Read-only UPDATE2 metadata is accepted. */
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_update2 *uro=(void *)m;zero(uro,sizeof(*uro));
 fds[0]=(int)a;tags[0]=4001;uro->offset=3;uro->data=(u64)fds;uro->tags=(u64)tags;uro->nr=1;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&fupdate2(&r,uro,sizeof(*uro))==1&&CALL(N_MUNMAP,m,4096,0)==0);
 CHECK(funreg(&r)==0&&lget(&r,c,3)==0&&lresult(c,3,2001,0)==0&&lresult(c,3,3001,0)==0&&lresult(c,3,4001,0)==0);
 CHECK(cq_empty(&r)==0&&lhealth(&r)==0&&finish(&r)==0);
 /* A fixed request pins its old generation; replacement delays that tag. */
 int oldp[2];CHECK(bpipe(oldp,0)==0&&init(&r,0,8)==0);fds[0]=oldp[0];tags[0]=9001;
 zero(&rr,sizeof(rr));rr.nr=1;rr.data=(u64)fds;rr.tags=(u64)tags;CHECK(freg2(&r,&rr,sizeof(rr))==0);
 char byte=0;struct sqe q;zero(&q,sizeof(q));q.op=22;q.flags=1|16;q.fd=0;q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.ud=9100;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&cq_empty(&r)==0);
 fds[0]=(int)b;tags[0]=9002;zero(&up,sizeof(up));up.data=(u64)fds;up.tags=(u64)tags;up.nr=1;
 CHECK(fupdate2(&r,&up,sizeof(up))==1&&cq_empty(&r)==0&&fbyte(&r,0,'B')==0&&cq_empty(&r)==0);
 CHECK(CALL(N_WRITE,oldp[1],"O",1)==1&&lget(&r,c,2)==0&&lresult(c,2,9100,1)==0&&lresult(c,2,9001,0)==0&&byte=='O');
 CHECK(funreg(&r)==0&&lget(&r,c,1)==0&&c[0].ud==9002&&c[0].res==0);
 CHECK(CALL(N_CLOSE,oldp[0],0,0)==0&&CALL(N_CLOSE,oldp[1],0,0)==0&&lhealth(&r)==0&&finish(&r)==0);
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0);return 0;
}

static int close_direct_shared(void) {
 struct ring r;struct sqe q;struct cqe c[4];long a,b,ambient;int fds[3];
 a=fdata("close-direct-a",'A');b=fdata("close-direct-b",'B');
 int ir=init(&r,0,16);if(a<0||b<0||ir!=0){put("CLOSE_DIRECT_INIT ");putnum(a);put(" ");putnum(b);put(" ");putnum(ir);put("\n");return __LINE__;}
 /* file_index is one based.  A missing table differs from an empty slot. */
 zero(&q,sizeof(q));q.op=19;q.fd2=1;q.ud=1;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,1,-6)==0);
 fds[0]=(int)a;fds[1]=-1;fds[2]=(int)b;CHECK(freg(&r,fds,3)==0);
 q.ud=2;q.fd2=2;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,2,-9)==0);
 q.ud=3;q.fd2=4;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,3,-22)==0);
 /* Preparation failures leave the selected slot installed. */
 for(int field=0;field<7;field++){
  zero(&q,sizeof(q));q.op=19;q.fd2=3;q.ud=10+field;
  if(field==0)q.fd=1;if(field==1)q.flags=1;if(field==2)q.off=1;
  if(field==3)q.addr=1;if(field==4)q.len=1;if(field==5)q.misc=1;
  if(field==6)q.buf=1;
  queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0);
  CHECK(lresult(c,1,10+field,field==1?-9:-22)==0&&fbyte(&r,2,'B')==0);
 }
 /* Removing the same slot twice is atomic: one succeeds and one sees empty. */
 zero(&q,sizeof(q));q.op=19;q.fd2=1;q.ud=30;queue(&r,q,0);
 q.ud=31;queue(&r,q,0);CHECK(lsubmit(&r,2)==0&&lget(&r,c,2)==0);
 CHECK(lresult(c,2,30,0)==0&&lresult(c,2,31,-9)==0&&fbyte(&r,0,-9)==0);
 zero(&q,sizeof(q));q.op=19;q.fd2=3;q.ud=32;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,32,0)==0&&fbyte(&r,2,-9)==0);
 CHECK(funreg(&r)==0&&lhealth(&r)==0&&finish(&r)==0);
 /* file_index zero retains ordinary CLOSE behavior. */
 ambient=fdata("close-direct-ambient",'X');CHECK(ambient>=0&&init(&r,0,8)==0);
 zero(&q,sizeof(q));q.op=19;q.fd=(int)ambient;q.ud=40;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,40,0)==0);
 char byte=0;CHECK(CALL(N_READ,ambient,&byte,1)==-9&&finish(&r)==0);
 /* With no request holder, direct removal retires the generation tag now. */
 {struct frsrc_register trr;u64 ttag=8001;int tone=(int)a;
  CHECK(init(&r,0,8)==0);zero(&trr,sizeof(trr));trr.nr=1;trr.data=(u64)&tone;trr.tags=(u64)&ttag;
  CHECK(freg2(&r,&trr,sizeof(trr))==0);zero(&q,sizeof(q));q.op=19;q.fd2=1;q.ud=41;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0&&lget(&r,c,2)==0&&lresult(c,2,41,0)==0&&lresult(c,2,8001,0)==0);
  CHECK(funreg(&r)==0&&cq_empty(&r)==0&&finish(&r)==0);}
 /* Direct removal retires a tag only after a pending fixed request drops it,
  * and the now-empty slot may be populated immediately with a new generation. */
 int pipefd[2];struct frsrc_register rr;struct frsrc_update2 up;u64 tag;int one;
 CHECK(bpipe(pipefd,0)==0&&init(&r,0,16)==0);one=pipefd[0];tag=9001;
 zero(&rr,sizeof(rr));rr.nr=1;rr.data=(u64)&one;rr.tags=(u64)&tag;
 CHECK(freg2(&r,&rr,sizeof(rr))==0);
 zero(&q,sizeof(q));q.op=22;q.flags=1|16;q.fd=0;q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.ud=50;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&cq_empty(&r)==0);
 zero(&q,sizeof(q));q.op=19;q.fd2=1;q.ud=51;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,c,1)==0&&lresult(c,1,51,0)==0&&cq_empty(&r)==0);
 CHECK(fbyte(&r,0,-9)==0&&cq_empty(&r)==0);
 one=(int)b;tag=9002;zero(&up,sizeof(up));up.data=(u64)&one;up.tags=(u64)&tag;up.nr=1;
 CHECK(fupdate2(&r,&up,sizeof(up))==1&&fbyte(&r,0,'B')==0&&cq_empty(&r)==0);
 CHECK(CALL(N_WRITE,pipefd[1],"P",1)==1&&lget(&r,c,2)==0);
 CHECK(lresult(c,2,50,1)==0&&lresult(c,2,9001,0)==0&&byte=='P');
 CHECK(funreg(&r)==0&&lget(&r,c,1)==0&&lresult(c,1,9002,0)==0);
 CHECK(CALL(N_CLOSE,pipefd[0],0,0)==0&&CALL(N_CLOSE,pipefd[1],0,0)==0);
 CHECK(CALL(N_CLOSE,a,0,0)==0&&CALL(N_CLOSE,b,0,0)==0&&lhealth(&r)==0&&finish(&r)==0);
 return 0;
}


static long breg2(struct ring *r,struct frsrc_register *rr,u32 size) {return sreg(r,15,rr,size);}
static long bupdate2(struct ring *r,struct frsrc_update2 *up,u32 size) {return sreg(r,16,up,size);}
static int buffers_v2_shared(void) {
 struct ring r;struct frsrc_register rr;struct frsrc_update2 up;struct cqe c[4];
 struct rwvec iov[3];u64 tags[3];char *p=bmap(1),*np=bmap(1);long m,file;
 CHECK((long)p>=0&&(long)np>=0&&init(&r,0,16)==0);
 /* Exact metadata sizes, flags, counts, sparse rules and atomic failure. */
 zero(&rr,sizeof(rr));rr.nr=1;rr.flags=1;
 CHECK(breg2(&r,&rr,0)==-22&&breg2(&r,&rr,31)==-22&&breg2(&r,&rr,33)==-22&&breg2(&r,0,sizeof(rr))==-14);
 rr.nr=0;CHECK(breg2(&r,&rr,sizeof(rr))==-22);rr.nr=1;rr.flags=2;CHECK(breg2(&r,&rr,sizeof(rr))==-22);
 rr.flags=1;rr.resv2=1;CHECK(breg2(&r,&rr,sizeof(rr))==-22);rr.resv2=0;rr.data=(u64)iov;CHECK(breg2(&r,&rr,sizeof(rr))==-22);
 rr.data=0;rr.nr=1025;CHECK(breg2(&r,&rr,sizeof(rr))==-22);rr.nr=1;rr.flags=0;rr.data=1;CHECK(breg2(&r,&rr,sizeof(rr))==-14);
 iov[0]=(struct rwvec){0,0};tags[0]=101;rr.data=(u64)iov;rr.tags=(u64)tags;CHECK(breg2(&r,&rr,sizeof(rr))==-22&&bunreg(&r)==-6&&cq_empty(&r)==0);
 iov[0]=(struct rwvec){p,8};iov[1]=(struct rwvec){(void *)1,1};tags[0]=111;tags[1]=222;rr.nr=2;
 CHECK(breg2(&r,&rr,sizeof(rr))==-14&&bunreg(&r)==-6&&cq_empty(&r)==0);
 rr.nr=1;rr.tags=1;CHECK(breg2(&r,&rr,sizeof(rr))==-14&&bunreg(&r)==-6&&cq_empty(&r)==0);
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_register *cross=(void *)(m+4096-16);zero(cross,16);
 CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&breg2(&r,cross,sizeof(*cross))==-14&&CALL(N_MUNMAP,m,8192,0)==0);
 /* Read-only metadata and a fully sparse table are accepted. */
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_register *ro=(void *)m;zero(ro,sizeof(*ro));ro->nr=1;ro->flags=1;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&breg2(&r,ro,sizeof(*ro))==0&&breg2(&r,ro,sizeof(*ro))==-16&&bunreg(&r)==0&&CALL(N_MUNMAP,m,4096,0)==0);
 zero(&rr,sizeof(rr));rr.nr=3;rr.flags=1;CHECK(breg2(&r,&rr,sizeof(rr))==0);
 file=sc(N_OPENAT,-100,(long)"buffers2-data",OPENFLAGS,0600,0,0);CHECK(file>=0);
 CHECK(bop(&r,file,1,0,0,p,1,0,-14)==0);
 /* UPDATE2 validates its complete shape before touching the table. */
 zero(&up,sizeof(up));up.nr=1;up.data=(u64)iov;
 CHECK(bupdate2(&r,&up,0)==-22&&bupdate2(&r,&up,31)==-22&&bupdate2(&r,&up,33)==-22&&bupdate2(&r,0,sizeof(up))==-14);
 up.nr=0;CHECK(bupdate2(&r,&up,sizeof(up))==-22);up.nr=1;up.resv=1;CHECK(bupdate2(&r,&up,sizeof(up))==-22);
 up.resv=0;up.resv2=1;CHECK(bupdate2(&r,&up,sizeof(up))==-22);up.resv2=0;up.offset=0xffffffffU;up.nr=2;CHECK(bupdate2(&r,&up,sizeof(up))==-FOVERFLOW);
 up.offset=3;up.nr=1;CHECK(bupdate2(&r,&up,sizeof(up))==-22);up.offset=0;up.data=1;CHECK(bupdate2(&r,&up,sizeof(up))==-14);
 iov[0]=(struct rwvec){p,8};up.data=(u64)iov;up.tags=1;CHECK(bupdate2(&r,&up,sizeof(up))==-14&&bop(&r,file,1,0,0,p,1,0,-14)==0);
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0);struct frsrc_update2 *ucross=(void *)(m+4096-16);zero(ucross,16);
 CHECK(CALL(N_MPROTECT,m+4096,4096,0)==0&&bupdate2(&r,ucross,sizeof(*ucross))==-14&&CALL(N_MUNMAP,m,8192,0)==0);
 /* Populate, replace and observe immediate generation retirement. */
 for(int i=0;i<8;i++)p[i]='A';tags[0]=1001;zero(&up,sizeof(up));up.data=(u64)iov;up.tags=(u64)tags;up.nr=1;
 CHECK(bupdate2(&r,&up,sizeof(up))==1&&bop(&r,file,1,0,0,p,8,0,8)==0);
 iov[0]=(struct rwvec){np,8};tags[0]=2001;CHECK(bupdate2(&r,&up,sizeof(up))==1&&lget(&r,c,1)==0&&c[0].ud==1001&&c[0].res==0);
 /* Empty tagged buffers reject without replacing; later faults return prefix. */
 up.offset=1;iov[0]=(struct rwvec){0,0};tags[0]=9;CHECK(bupdate2(&r,&up,sizeof(up))==-22&&bop(&r,file,1,0,0,p,1,1,-14)==0);
 iov[0]=(struct rwvec){p+16,8};iov[1]=(struct rwvec){0,1};tags[0]=3001;tags[1]=3002;up.nr=2;
 CHECK(bupdate2(&r,&up,sizeof(up))==1&&bop(&r,file,1,0,0,p+16,1,1,1)==0&&bop(&r,file,1,0,0,p,1,2,-14)==0);
 /* A blocked fixed-buffer worker pins the old slot generation and pages. */
 int pipefd[2];CHECK(bpipe(pipefd,0)==0);zero(np,8);zero(p+32,8);struct sqe q;zero(&q,sizeof(q));q.op=4;q.flags=16;q.fd=pipefd[0];q.off=~0UL;q.addr=(u64)np;q.len=4;q.buf=0;q.ud=9100;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&cq_empty(&r)==0);
 up.offset=0;up.nr=1;iov[0]=(struct rwvec){p+32,8};tags[0]=4001;CHECK(bupdate2(&r,&up,sizeof(up))==1&&cq_empty(&r)==0);
 CHECK(CALL(N_WRITE,pipefd[1],"LIVE",4)==4&&lget(&r,c,2)==0&&lresult(c,2,9100,4)==0&&lresult(c,2,2001,0)==0);
 for(int i=0;i<4;i++)CHECK(np[i]=="LIVE"[i]&&p[32+i]==0);
 CHECK(bunreg(&r)==0&&lget(&r,c,2)==0&&lresult(c,2,3001,0)==0&&lresult(c,2,4001,0)==0);
 CHECK(CALL(N_CLOSE,pipefd[0],0,0)==0&&CALL(N_CLOSE,pipefd[1],0,0)==0&&CALL(N_CLOSE,file,0,0)==0);
 CHECK(cq_empty(&r)==0&&lhealth(&r)==0&&finish(&r)==0&&CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_MUNMAP,np,12288,0)==0);return 0;
}


/* Task-local registered-ring descriptors and shared buffer-table cloning. */
#define ENTER_REGISTERED_RING (1U<<4)
#define REGISTER_USE_RING (1U<<31)
#define CLONE_SRC_REGISTERED 1U
#define CLONE_DST_REPLACE 2U
struct clone_buffers {u32 src_fd,flags,src_off,dst_off,nr,pad[3];};
_Static_assert(sizeof(struct clone_buffers)==32,"clone buffers ABI");
static long ringfd_register(struct ring *r,struct fupdate *up,u32 nr) {return sreg(r,20,up,nr);}
static long ringfd_unregister_raw(long fd,u32 opflags,struct fupdate *up,u32 nr) {return sc(N_REGISTER,fd,21|opflags,(long)up,nr,0,0);}
static long clone_buffers(struct ring *r,struct clone_buffers *cb,u32 nr) {return sreg(r,30,cb,nr);}
static int feature_reg_ring_shared(void) {
 struct ring ctl,src;struct fupdate ru;u32 limits[2]={0,0};u32 idx;
 CHECK(init(&ctl,0,8)==0&&init(&src,0,8)==0);
 CHECK((ctl.p.features&(1U<<13))!=0);
 zero(&ru,sizeof(ru));ru.offset=~0U;ru.fds=(u64)src.fd;
 CHECK(ringfd_register(&ctl,&ru,1)==1&&ru.offset==0);
 idx=ru.offset;
 CHECK(sc(N_REGISTER,idx,19|REGISTER_USE_RING,(long)limits,2,0,0)==0);
 CHECK(sc(N_REGISTER,16,19|REGISTER_USE_RING,(long)limits,2,0,0)==-22);
 CHECK(sc(N_REGISTER,15,19|REGISTER_USE_RING,(long)limits,2,0,0)==-9);
 ru.fds=0;
 CHECK(ringfd_unregister_raw(idx,REGISTER_USE_RING,&ru,1)==1);
 CHECK(sc(N_REGISTER,idx,19|REGISTER_USE_RING,(long)limits,2,0,0)==-9);
 CHECK(lhealth(&ctl)==0&&lhealth(&src)==0);
 CHECK(finish(&src)==0&&finish(&ctl)==0);
 return 0;
}
static int clone_buffers_shared(void) {
 struct ring ctl,src,dst,tmp;struct fupdate ru[2];struct clone_buffers cb;
 struct frsrc_register rr;struct rwvec siov[3],diov[3];u64 stags[3],dtags[3];
 struct cqe c[4];char *p=bmap(1),*d=bmap(1);long ordinary,file,m;u32 srcidx,dstidx;
 CHECK((long)p>=0&&(long)d>=0&&init(&ctl,0,16)==0&&init(&src,0,16)==0&&init(&dst,0,16)==0);
 CHECK((ctl.p.features&(1U<<13))!=0);
 ordinary=fdata("clone-ordinary",'F');CHECK(ordinary>=0);
 /* Ring-fd registration validates each record and rolls copyout faults back. */
 zero(ru,sizeof(ru));ru[0].offset=~0U;ru[0].fds=(u64)src.fd;
 CHECK(ringfd_register(&ctl,ru,0)==-22&&ringfd_register(&ctl,ru,17)==-22&&ringfd_register(&ctl,0,1)==-14);
 ru[0].resv=1;CHECK(ringfd_register(&ctl,ru,1)==-22);ru[0].resv=0;ru[0].offset=16;CHECK(ringfd_register(&ctl,ru,1)==-22);
 ru[0].offset=~0U;ru[0].fds=~0U;CHECK(ringfd_register(&ctl,ru,1)==-9);ru[0].fds=(u64)ordinary;CHECK(ringfd_register(&ctl,ru,1)==-NOTSUP);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);struct fupdate *ro=(void *)m;ro->offset=~0U;ro->resv=0;ro->fds=(u64)src.fd;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&ringfd_register(&ctl,ro,1)==-14&&CALL(N_MUNMAP,m,4096,0)==0);
 ru[0].offset=~0U;ru[0].resv=0;ru[0].fds=(u64)src.fd;CHECK(ringfd_register(&ctl,ru,1)==1);srcidx=ru[0].offset;CHECK(srcidx==0);
 ru[0].offset=srcidx;CHECK(ringfd_register(&ctl,ru,1)==-16);ru[0].offset=~0U;ru[0].fds=(u64)dst.fd;CHECK(ringfd_register(&ctl,ru,1)==1);dstidx=ru[0].offset;CHECK(dstidx==1);
 CHECK(sc(N_ENTER,srcidx,0,0,ENTER_REGISTERED_RING,0,0)==0&&sc(N_ENTER,16,0,0,ENTER_REGISTERED_RING,0,0)==-22&&sc(N_ENTER,15,0,0,ENTER_REGISTERED_RING,0,0)==-9);
 CHECK(sc(N_REGISTER,srcidx,1|REGISTER_USE_RING,0,0,0,0)==-6);
 /* Clone metadata, source lookup and empty-source failures are side-effect free. */
 zero(&cb,sizeof(cb));cb.src_fd=srcidx;cb.flags=CLONE_SRC_REGISTERED;
 CHECK(clone_buffers(&dst,0,1)==-22&&clone_buffers(&dst,&cb,0)==-22&&clone_buffers(&dst,(void *)1,1)==-14);
 cb.flags=4;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.flags=CLONE_SRC_REGISTERED;cb.pad[1]=1;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.pad[1]=0;
 cb.src_fd=16;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.src_fd=15;CHECK(clone_buffers(&dst,&cb,1)==-9);
 cb.flags=0;cb.src_fd=(u32)ordinary;CHECK(clone_buffers(&dst,&cb,1)==-NOTSUP);cb.src_fd=0xffffffffU;CHECK(clone_buffers(&dst,&cb,1)==-9);
 cb.src_fd=(u32)src.fd;CHECK(clone_buffers(&dst,&cb,1)==-6);
 cb.nr=0;cb.src_off=1;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.src_off=0;cb.dst_off=1;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.dst_off=0;
 /* A whole-table clone shares only pinned storage; source tags retire independently. */
 for(int i=0;i<8;i++){p[i]='A';p[32+i]='C';}
 siov[0]=(struct rwvec){p,8};siov[1]=(struct rwvec){0,0};siov[2]=(struct rwvec){p+32,8};stags[0]=101;stags[1]=0;stags[2]=103;
 zero(&rr,sizeof(rr));rr.nr=3;rr.data=(u64)siov;rr.tags=(u64)stags;CHECK(breg2(&src,&rr,sizeof(rr))==0);
 cb.flags=CLONE_SRC_REGISTERED;cb.src_fd=srcidx;cb.nr=4;CHECK(clone_buffers(&dst,&cb,1)==-22);cb.nr=1;cb.src_off=3;CHECK(clone_buffers(&dst,&cb,1)==-22);
 cb.src_off=0;cb.dst_off=0xffffffffU;cb.nr=2;CHECK(clone_buffers(&dst,&cb,1)==-FOVERFLOW);cb.dst_off=1024;cb.nr=1;CHECK(clone_buffers(&dst,&cb,1)==-22);
 cb.dst_off=0;cb.nr=0;CHECK(clone_buffers(&dst,&cb,1)==0&&clone_buffers(&dst,&cb,1)==-16);
 CHECK(bunreg(&src)==0&&lget(&src,c,2)==0&&lresult(c,2,101,0)==0&&lresult(c,2,103,0)==0);
 file=sc(N_OPENAT,-100,(long)"clone-output",OPENFLAGS,0600,0,0);CHECK(file>=0);
 CHECK(bop(&dst,file,1,0,0,p,8,0,8)==0&&bop(&dst,file,1,0,0,p+32,8,2,8)==0&&bop(&dst,file,1,0,0,p,1,1,-14)==0);
 CHECK(bunreg(&dst)==0&&cq_empty(&dst)==0);
 /* Self-replacement creates untagged resource nodes and releases old tags. */
 siov[0]=(struct rwvec){p,8};stags[0]=201;zero(&rr,sizeof(rr));rr.nr=1;rr.data=(u64)siov;rr.tags=(u64)stags;CHECK(breg2(&src,&rr,sizeof(rr))==0);
 zero(&cb,sizeof(cb));cb.src_fd=(u32)src.fd;cb.flags=CLONE_DST_REPLACE;CHECK(clone_buffers(&src,&cb,1)==0&&lget(&src,c,1)==0&&c[0].ud==201&&c[0].res==0);
 CHECK(bop(&src,file,1,0,0,p,8,0,8)==0&&bunreg(&src)==0&&cq_empty(&src)==0);
 /* REPLACE preserves the destination prefix, clears its suffix and clones a slice. */
 for(int i=0;i<8;i++){d[i]='D';d[16+i]='E';d[32+i]='G';p[i]='S';p[32+i]='T';}
 diov[0]=(struct rwvec){d,8};diov[1]=(struct rwvec){d+16,8};diov[2]=(struct rwvec){d+32,8};dtags[0]=301;dtags[1]=302;dtags[2]=303;
 zero(&rr,sizeof(rr));rr.nr=3;rr.data=(u64)diov;rr.tags=(u64)dtags;CHECK(breg2(&dst,&rr,sizeof(rr))==0);
 siov[0]=(struct rwvec){p,8};siov[1]=(struct rwvec){p+32,8};stags[0]=401;stags[1]=402;rr.nr=2;rr.data=(u64)siov;rr.tags=(u64)stags;CHECK(breg2(&src,&rr,sizeof(rr))==0);
 zero(&cb,sizeof(cb));cb.src_fd=srcidx;cb.flags=CLONE_SRC_REGISTERED|CLONE_DST_REPLACE;cb.src_off=1;cb.dst_off=1;cb.nr=1;
 CHECK(clone_buffers(&dst,&cb,1)==0&&lget(&dst,c,2)==0&&lresult(c,2,302,0)==0&&lresult(c,2,303,0)==0);
 CHECK(bunreg(&src)==0&&lget(&src,c,2)==0&&lresult(c,2,401,0)==0&&lresult(c,2,402,0)==0);
 CHECK(bop(&dst,file,1,0,0,d,8,0,8)==0&&bop(&dst,file,1,0,0,p+32,8,1,8)==0&&bop(&dst,file,1,0,0,d+32,1,2,-14)==0);
 CHECK(bunreg(&dst)==0&&lget(&dst,c,1)==0&&c[0].ud==301&&c[0].res==0);
 /* Ordered two-ring locking survives concurrent cross-clone replacement. */
 CHECK(init(&tmp,0,8)==0);struct rwvec one={p,8},two={d,8};CHECK(breg(&dst,&one,1)==0&&breg(&tmp,&two,1)==0);int sync[2],status1,status2;CHECK(bpipe(sync,0)==0);
 long pid1=fork_child();CHECK(pid1>=0);if(pid1==0){char x;CALL(N_READ,sync[0],&x,1);struct clone_buffers xcb;zero(&xcb,sizeof(xcb));xcb.src_fd=(u32)tmp.fd;xcb.flags=CLONE_DST_REPLACE;for(int i=0;i<64;i++)if(clone_buffers(&dst,&xcb,1)!=0)CALL(N_EXIT,1,0,0);CALL(N_EXIT,0,0,0);}
 long pid2=fork_child();CHECK(pid2>=0);if(pid2==0){char x;CALL(N_READ,sync[0],&x,1);struct clone_buffers xcb;zero(&xcb,sizeof(xcb));xcb.src_fd=(u32)dst.fd;xcb.flags=CLONE_DST_REPLACE;for(int i=0;i<64;i++)if(clone_buffers(&tmp,&xcb,1)!=0)CALL(N_EXIT,2,0,0);CALL(N_EXIT,0,0,0);}
 CHECK(CALL(N_WRITE,sync[1],"RR",2)==2&&CALL(N_WAIT,pid1,&status1,0)==pid1&&CALL(N_WAIT,pid2,&status2,0)==pid2&&status1==0&&status2==0);
 CHECK(bunreg(&dst)==0&&bunreg(&tmp)==0&&finish(&tmp)==0&&CALL(N_CLOSE,sync[0],0,0)==0&&CALL(N_CLOSE,sync[1],0,0)==0);
 /* A task registry reference keeps a closed ring usable, including self-unregister. */
 CHECK(init(&tmp,0,8)==0);ru[0].offset=~0U;ru[0].resv=0;ru[0].fds=(u64)tmp.fd;CHECK(ringfd_register(&ctl,ru,1)==1);u32 lifeidx=ru[0].offset;long lifefd=tmp.fd;tmp.fd=-1;CHECK(CALL(N_CLOSE,lifefd,0,0)==0);
 CHECK(sc(N_ENTER,lifeidx,0,0,ENTER_REGISTERED_RING,0,0)==0);ru[0].offset=lifeidx;ru[0].resv=0;ru[0].fds=0;CHECK(ringfd_unregister_raw(lifeidx,REGISTER_USE_RING,ru,1)==1&&sc(N_ENTER,lifeidx,0,0,ENTER_REGISTERED_RING,0,0)==-9);
 CHECK(CALL(N_MUNMAP,tmp.mem,tmp.rlen,0)==0&&CALL(N_MUNMAP,tmp.sqes,tmp.slen,0)==0);
 /* Remove the persistent source/destination indexes; missing slots are benign. */
 ru[0].offset=srcidx;ru[0].resv=0;ru[0].fds=0;ru[1]=ru[0];ru[1].offset=dstidx;CHECK(ringfd_unregister_raw(ctl.fd,0,ru,2)==2);
 CHECK(sc(N_ENTER,srcidx,0,0,ENTER_REGISTERED_RING,0,0)==-9&&ringfd_unregister_raw(ctl.fd,0,ru,2)==2);
 CHECK(CALL(N_CLOSE,ordinary,0,0)==0&&CALL(N_CLOSE,file,0,0)==0&&lhealth(&ctl)==0&&lhealth(&src)==0&&lhealth(&dst)==0);
 CHECK(finish(&src)==0&&finish(&dst)==0&&finish(&ctl)==0&&CALL(N_MUNMAP,p,12288,0)==0&&CALL(N_MUNMAP,d,12288,0)==0);return 0;
}


static long personality_register(struct ring *r) {return sreg(r,9,0,0);}
static long personality_unregister(struct ring *r,u32 id) {return sreg(r,10,0,id);}
static int personality_nop(struct ring *r,u32 id,u64 key,int expected) {
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.personality=(unsigned short)id;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.res==expected);return 0;
}
static int personality_shared(void) {
 struct ring r;long first,second,third;CHECK(init(&r,0,16)==0);
 CHECK(sreg(&r,9,(void *)1,0)==-22&&sreg(&r,9,0,1)==-22);
 CHECK(sreg(&r,10,(void *)1,1)==-22&&personality_unregister(&r,0)==-22&&personality_unregister(&r,65536)==-22&&personality_unregister(&r,65535)==-22);
 first=personality_register(&r);second=personality_register(&r);CHECK(first>0&&first<=65535&&second>0&&second<=65535&&first!=second);
 CHECK(personality_nop(&r,(u32)first,1,0)==0&&personality_nop(&r,(u32)second,2,0)==0);
 CHECK(personality_unregister(&r,(u32)first)==0&&personality_unregister(&r,(u32)first)==-22&&personality_nop(&r,(u32)first,3,-22)==0);
 third=personality_register(&r);CHECK(third>0&&third!=first&&third!=second&&personality_nop(&r,(u32)third,4,0)==0);
 /* A prepared async request retains its credential after unregister. */
 int fd[2];char byte=0;CHECK(bpipe(fd,0)==0);struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=22;q.flags=16;q.fd=fd[0];q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.personality=(unsigned short)second;q.ud=5;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0);
 CHECK(cq_empty(&r)==0);
 CHECK(personality_unregister(&r,(u32)second)==0);
 CHECK(CALL(N_WRITE,fd[1],"P",1)==1);
 CHECK(lget(&r,&c,1)==0&&c.ud==5&&c.res==1&&byte=='P');
 CHECK(personality_nop(&r,(u32)second,6,-22)==0);
 CHECK(CALL(N_CLOSE,fd[0],0,0)==0&&CALL(N_CLOSE,fd[1],0,0)==0&&personality_unregister(&r,(u32)third)==0&&lhealth(&r)==0&&finish(&r)==0);
 /* Ring teardown and process exit release still-registered snapshots. */
 for(int n=0;n<16;n++){int status;long pid=fork_child();CHECK(pid>=0);if(pid==0){struct ring x;if(init(&x,0,8)!=0||personality_register(&x)<=0)CALL(N_EXIT,1,0,0);CALL(N_EXIT,0,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);}
#ifdef LINUX_ABI
 /* The snapshot, not the submitter's later uid, authorizes path operations. */
 long rootfd=fdata("personality-root",'R');CHECK(rootfd>=0&&CALL(N_CLOSE,rootfd,0,0)==0);int status;long pid=fork_child();CHECK(pid>=0);if(pid==0){struct ring x;struct sqe oq;struct cqe oc;char value=0;if(init(&x,0,8)!=0)CALL(N_EXIT,2,0,0);long id=personality_register(&x);if(id<=0||CALL(N_SETUID,65534,0,0)!=0)CALL(N_EXIT,3,0,0);if(sc(N_OPENAT,-100,(long)"personality-root",0,0,0,0)!=-13)CALL(N_EXIT,4,0,0);zero(&oq,sizeof(oq));oq.op=18;oq.fd=-100;oq.addr=(u64)"personality-root";oq.personality=(unsigned short)id;oq.ud=7;queue(&x,oq,0);if(lsubmit(&x,1)!=0||lget(&x,&oc,1)!=0||oc.ud!=7||oc.res<0)CALL(N_EXIT,5,0,0);if(CALL(N_READ,oc.res,&value,1)!=1||value!='R'||CALL(N_CLOSE,oc.res,0,0)!=0)CALL(N_EXIT,6,0,0);if(personality_unregister(&x,(u32)id)!=0||finish(&x)!=0)CALL(N_EXIT,7,0,0);CALL(N_EXIT,0,0,0);}CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
#endif
 return 0;
}

static int iowq_controls_shared(void) {
 struct ring r;u32 initial[2],values[2],queryv[2],*cross,*ro;long m;struct sqe q;struct cqe c[2];char a=0,b=0;int p1[2],p2[2];
 CHECK(init(&r,0,16)==0);
 CHECK(sreg(&r,19,0,2)==-22&&sreg(&r,19,(void *)1,2)==-14);
 values[0]=0;values[1]=0;CHECK(sreg(&r,19,values,1)==-22&&sreg(&r,19,values,3)==-22);
 CHECK(sreg(&r,19,values,2)==0&&values[0]>0&&values[1]>0);initial[0]=values[0];initial[1]=values[1];
 /* Values above signed-int range reject without changing either class. */
 values[0]=0x80000000U;values[1]=1;CHECK(sreg(&r,19,values,2)==-22&&values[0]==0x80000000U&&values[1]==1);
 queryv[0]=queryv[1]=0;CHECK(sreg(&r,19,queryv,2)==0&&queryv[0]==initial[0]&&queryv[1]==initial[1]);
 /* A zero element queries/leaves that class; success returns the old pair. */
 values[0]=1;values[1]=1;CHECK(sreg(&r,19,values,2)==0&&values[0]==initial[0]&&values[1]==initial[1]);
 values[0]=0;values[1]=2;CHECK(sreg(&r,19,values,2)==0&&values[0]==1&&values[1]==1);
 queryv[0]=queryv[1]=0;CHECK(sreg(&r,19,queryv,2)==0&&queryv[0]==1&&queryv[1]==2);
 /* A copyin fault is atomic and a final copyout fault follows Linux: applied. */
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>=0&&CALL(N_MUNMAP,m+4096,4096,0)==0);cross=(u32 *)(m+4092);cross[0]=2;
 CHECK(sreg(&r,19,cross,2)==-14);queryv[0]=queryv[1]=0;CHECK(sreg(&r,19,queryv,2)==0&&queryv[0]==1&&queryv[1]==2&&CALL(N_MUNMAP,m,4096,0)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);ro=(u32 *)m;ro[0]=2;ro[1]=2;CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,19,ro,2)==-14&&CALL(N_MUNMAP,m,4096,0)==0);
 queryv[0]=queryv[1]=0;CHECK(sreg(&r,19,queryv,2)==0&&queryv[0]==2&&queryv[1]==2);
 values[0]=1;values[1]=1;CHECK(sreg(&r,19,values,2)==0&&values[0]==2&&values[1]==2);
 /* With one unbounded slot, the second pipe read cannot run ahead. */
 CHECK(bpipe(p1,0)==0&&bpipe(p2,0)==0);zero(&q,sizeof(q));q.op=22;q.flags=16;q.fd=p1[0];q.off=~0UL;q.addr=(u64)&a;q.len=1;q.ud=1;queue(&r,q,0);
 q.fd=p2[0];q.addr=(u64)&b;q.ud=2;queue(&r,q,0);CHECK(lsubmit(&r,2)==0&&CALL(N_WRITE,p2[1],"B",1)==1);lpause(50000000);CHECK(cq_empty(&r)==0);
 CHECK(CALL(N_WRITE,p1[1],"A",1)==1&&lget(&r,c,2)==0&&c[0].ud==1&&c[0].res==1&&c[1].ud==2&&c[1].res==1&&a=='A'&&b=='B');
 CHECK(CALL(N_CLOSE,p1[0],0,0)==0&&CALL(N_CLOSE,p1[1],0,0)==0&&CALL(N_CLOSE,p2[0],0,0)==0&&CALL(N_CLOSE,p2[1],0,0)==0);
 values[0]=initial[0];values[1]=initial[1];CHECK(sreg(&r,19,values,2)==0&&values[0]==1&&values[1]==1);
 /* Affinity is a byte-sized bitmap; invalid masks never replace the old one. */
 u64 mask[16];zero(mask,sizeof(mask));CHECK(sreg(&r,17,0,8)==-22&&sreg(&r,17,mask,0)==-22&&sreg(&r,17,(void *)1,8)==-14);
 CHECK(sreg(&r,18,(void *)1,0)==-22&&sreg(&r,18,0,1)==-22);
 CHECK(sreg(&r,17,mask,8)==-22);mask[0]=1UL<<63;CHECK(sreg(&r,17,mask,8)==-22);
 /* Linux clamps an oversized byte count and ignores bytes beyond cpuset_t. */
 zero(mask,sizeof(mask));mask[0]=1;CHECK(sreg(&r,17,mask,4096)==0);
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>=0&&CALL(N_MUNMAP,m+4096,4096,0)==0);cross=(u32 *)(m+4092);cross[0]=1;
 CHECK(sreg(&r,17,cross,8)==-14&&CALL(N_MUNMAP,m,4096,0)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);((u64 *)m)[0]=1;CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,17,(void *)m,8)==0&&CALL(N_MUNMAP,m,4096,0)==0);
 /* A constrained worker must still execute and the mask can be restored twice. */
 CHECK(bpipe(p1,0)==0);zero(&q,sizeof(q));q.op=22;q.flags=16;q.fd=p1[0];q.off=~0UL;q.addr=(u64)&a;q.len=1;q.ud=3;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&CALL(N_WRITE,p1[1],"C",1)==1&&lget(&r,c,1)==0&&c[0].ud==3&&c[0].res==1&&a=='C');
 CHECK(CALL(N_CLOSE,p1[0],0,0)==0&&CALL(N_CLOSE,p1[1],0,0)==0&&sreg(&r,18,0,0)==0&&sreg(&r,18,0,0)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int
napi_register_shared(void)
{
 struct ring r,io;struct snapi n,*ro;long m;
 CHECK(init(&r,0,8)==0);
 /* Shape and copy faults are rejected without changing ring state. */
 zero(&n,sizeof(n));n.busy_poll_to=25;n.prefer_busy_poll=1;n.op_param=0;
 CHECK(sreg(&r,27,0,1)==-22&&sreg(&r,27,&n,0)==-22&&
     sreg(&r,27,&n,2)==-22&&sreg(&r,28,0,0)==-22);
 n.pad[0]=1;CHECK(sreg(&r,27,&n,1)==-22);n.pad[0]=0;
 n.pad[1]=1;CHECK(sreg(&r,27,&n,1)==-22);n.pad[1]=0;
 n.resv=1;CHECK(sreg(&r,27,&n,1)==-22);n.resv=0;
 n.opcode=3;CHECK(sreg(&r,27,&n,1)==-22);
 n.opcode=0;n.op_param=2;CHECK(sreg(&r,27,&n,1)==-22);
 CHECK(sreg(&r,27,(void *)1,1)==-14);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);ro=(void *)m;
 zero(ro,sizeof(*ro));ro->busy_poll_to=100;ro->op_param=0;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,27,ro,1)==-14&&
     CALL(N_MUNMAP,m,4096,0)==0);
 /* REGISTER returns the previous state and clamps the new timeout to 10ms. */
 zero(&n,sizeof(n));n.busy_poll_to=25000;n.prefer_busy_poll=7;n.op_param=0;
 CHECK(sreg(&r,27,&n,1)==0&&n.busy_poll_to==0&&
     n.prefer_busy_poll==0&&n.op_param==255);
 zero(&n,sizeof(n));n.busy_poll_to=50;n.op_param=1;
 CHECK(sreg(&r,27,&n,1)==0&&n.busy_poll_to==10000&&
     n.prefer_busy_poll==1&&n.op_param==0);
 /* Static ID updates report settings, reject bad/duplicate/missing IDs. */
 zero(&n,sizeof(n));n.opcode=1;n.op_param=0;CHECK(sreg(&r,27,&n,1)==-22);
 zero(&n,sizeof(n));n.opcode=1;n.op_param=0x10000;
 CHECK(sreg(&r,27,&n,1)==0&&n.busy_poll_to==50&&n.op_param==1);
 zero(&n,sizeof(n));n.opcode=1;n.op_param=0x10000;CHECK(sreg(&r,27,&n,1)==-17);
 zero(&n,sizeof(n));n.opcode=2;n.op_param=0x10001;CHECK(sreg(&r,27,&n,1)==-2);
 zero(&n,sizeof(n));n.opcode=2;n.op_param=0x10000;CHECK(sreg(&r,27,&n,1)==0);
 zero(&n,sizeof(n));n.opcode=2;n.op_param=0x10000;CHECK(sreg(&r,27,&n,1)==-2);
 /* UNREGISTER optionally returns old settings and can be repeated. */
 zero(&n,sizeof(n));CHECK(sreg(&r,28,&n,1)==0&&n.busy_poll_to==50&&
     n.prefer_busy_poll==0&&n.op_param==0&&n.resv==0);
 CHECK(sreg(&r,28,0,1)==0);
 zero(&n,sizeof(n));n.busy_poll_to=1;n.prefer_busy_poll=1;n.op_param=1;
 CHECK(sreg(&r,27,&n,1)==0&&n.op_param==255);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);ro=(void *)m;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sreg(&r,28,ro,1)==-14&&
     CALL(N_MUNMAP,m,4096,0)==0);
 zero(&n,sizeof(n));CHECK(sreg(&r,28,&n,1)==0&&n.busy_poll_to==1&&
     n.prefer_busy_poll==1);
 CHECK(finish(&r)==0);
 /* Linux rejects NAPI registration on an IOPOLL ring. */
 if(init(&io,1,8)==0){zero(&n,sizeof(n));n.op_param=0;
  CHECK(sreg(&io,27,&n,1)==-22&&finish(&io)==0);}
 return 0;
}

static void
bpf_want(struct sbpf_reg *reg,u32 opcode,u32 flags,unsigned char pdu,
    struct sbpf_insn *insns,u32 count)
{
 zero(reg,sizeof(*reg));reg->cmd_type=1;reg->filter.opcode=opcode;
 reg->filter.flags=flags;reg->filter.filter_len=count;
 reg->filter.pdu_size=pdu;reg->filter.filter_ptr=(u64)insns;
}
static int
bpf_nop(struct ring *r,u32 flags,u64 key,int expected)
{
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.flags=(unsigned char)flags;q.ud=key;
 queue(r,q,0);CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.res==expected);
 return 0;
}
static int
bpf_submit(struct ring *r,struct sqe *q,int expected)
{
 struct cqe c;queue(r,*q,0);CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&
     c.ud==q->ud&&c.res==expected);return 0;
}
#ifdef LINUX_ABI
static long
bpf_task_reg(struct sbpf_reg *reg)
{
 return sc(N_REGISTER,-1,37,(long)reg,1,0,0);
}
static int
bpf_task_exec_helper(void)
{
 struct ring x;
 CHECK(init(&x,0,8)==0&&bpf_nop(&x,0,900,-ACCESS)==0&&finish(&x)==0);
 return 0;
}
#endif
static int
bpf_filter_shared(void)
{
 struct ring r;struct sbpf_reg reg,*ro;long m;unsigned char *edge;
 struct sbpf_insn allow[]={{SBPF_RET_K,0,0,1}};
 struct sbpf_insn deny[]={{SBPF_RET_K,0,0,0}};
 struct sbpf_insn by_key[]={{SBPF_LD_W_ABS,0,0,0},
     {SBPF_JMP_JEQ_K,0,1,42},{SBPF_RET_K,0,0,1},{SBPF_RET_K,0,0,0}};
 struct sbpf_insn by_async[]={{SBPF_LD_W_ABS,0,0,8},
     {SBPF_ALU_AND_K,0,0,0xff00},{SBPF_JMP_JEQ_K,0,1,0x1000},
     {SBPF_RET_K,0,0,1},{SBPF_RET_K,0,0,0}};
 struct sbpf_insn invalid[]={{SBPF_LD_H_ABS,0,0,0},{SBPF_RET_K,0,0,1}};
 struct sbpf_insn oob[]={{SBPF_LD_W_ABS,0,0,40},{SBPF_RET_K,0,0,1}};
 struct sbpf_insn divzero[]={{SBPF_ALU_DIV_K,0,0,0},{SBPF_RET_K,0,0,1}};
 struct sbpf_insn by_family[]={{SBPF_LD_W_ABS,0,0,16},
     {SBPF_JMP_JEQ_K,0,1,2},{SBPF_RET_K,0,0,1},{SBPF_RET_K,0,0,0}};
 struct sbpf_insn by_mode[]={{SBPF_LD_W_ABS,0,0,24},
     {SBPF_JMP_JEQ_K,0,1,0600},{SBPF_RET_K,0,0,1},{SBPF_RET_K,0,0,0}};
#ifdef LINUX_ABI
 struct sbpf_insn by_open_flags[]={{SBPF_LD_W_ABS,0,0,16},
     {SBPF_JMP_JEQ_K,0,1,0},{SBPF_RET_K,0,0,1},{SBPF_RET_K,0,0,0}};
#endif
 struct sqe q;struct cqe c;char byte=0,ready;
 int syncfd[2],status;
 CHECK(init(&r,0,8)==0);
 bpf_want(&reg,0,0,0,allow,1);
 CHECK(sreg(&r,37,0,0)==-22&&sreg(&r,37,0,1)==-14&&
     sreg(&r,37,&reg,0)==-22&&sreg(&r,37,&reg,2)==-22);
 reg.cmd_type=0;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,1);
 reg.cmd_flags=1;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,1);
 reg.resv=1;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,1);
 reg.filter.opcode=255;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,4,0,allow,1);
 CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,1);
 reg.filter.resv[1]=1;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,1);
 reg.filter.resv2[3]=1;CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,0);
 CHECK(sreg(&r,37,&reg,1)==-22);bpf_want(&reg,0,0,0,allow,4097);
 CHECK(sreg(&r,37,&reg,1)==-22);
 bpf_want(&reg,0,SBPF_SZ_STRICT,1,allow,1);
 CHECK(sreg(&r,37,&reg,1)==-MSGSIZE&&reg.filter.pdu_size==0);
 bpf_want(&reg,45,SBPF_SZ_STRICT,0,allow,1);
 CHECK(sreg(&r,37,&reg,1)==-MSGSIZE&&reg.filter.pdu_size==12);
 bpf_want(&reg,45,0,13,allow,1);
 CHECK(sreg(&r,37,&reg,1)==-MSGSIZE&&reg.filter.pdu_size==12);
 bpf_want(&reg,0,0,0,invalid,2);CHECK(sreg(&r,37,&reg,1)==-22);
 bpf_want(&reg,0,0,0,oob,2);CHECK(sreg(&r,37,&reg,1)==-22);
 bpf_want(&reg,0,0,0,divzero,2);CHECK(sreg(&r,37,&reg,1)==-22);
 bpf_want(&reg,0,0,0,(void *)1,1);CHECK(sreg(&r,37,&reg,1)==-14);
 /* The instruction array is one atomic copy, including a page boundary. */
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>0&&
     CALL(N_MUNMAP,m+4096,4096,0)==0);edge=(unsigned char *)m+4096-sizeof(*allow);
 *(struct sbpf_insn *)edge=allow[0];bpf_want(&reg,0,0,0,
     (struct sbpf_insn *)edge,2);CHECK(sreg(&r,37,&reg,1)==-14&&
     CALL(N_MUNMAP,m,4096,0)==0);
 /* Copyout happens before program import and a failed copyout installs nothing. */
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>0);ro=(void *)m;
 bpf_want(ro,0,0,0,deny,1);CHECK(CALL(N_MPROTECT,m,4096,1)==0&&
     sreg(&r,37,ro,1)==-14&&CALL(N_MUNMAP,m,4096,0)==0);
 CHECK(bpf_nop(&r,0,90,0)==0&&finish(&r)==0);
 /* The context uses native-endian word loads; filters stack conjunctively. */
 CHECK(init(&r,0,8)==0);bpf_want(&reg,0,0,0,by_key,4);
 CHECK(sreg(&r,37,&reg,1)==0&&bpf_nop(&r,0,42,0)==0&&
     bpf_nop(&r,0,43,-ACCESS)==0);
 bpf_want(&reg,0,0,0,by_async,5);CHECK(sreg(&r,37,&reg,1)==0);
 CHECK(bpf_nop(&r,0,42,-ACCESS)==0&&bpf_nop(&r,16,42,0)==0);
 bpf_want(&reg,0,0,0,deny,1);CHECK(sreg(&r,37,&reg,1)==0&&
     bpf_nop(&r,16,42,-ACCESS)==0&&finish(&r)==0);
 /* DENY_REST blocks every previously-unfiltered opcode before file lookup. */
 CHECK(init(&r,0,8)==0);bpf_want(&reg,0,SBPF_DENY_REST,0,allow,1);
 CHECK(sreg(&r,37,&reg,1)==0&&bpf_nop(&r,0,44,0)==0);
 zero(&q,sizeof(q));q.op=22;q.fd=-1;q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.ud=45;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.res==-ACCESS);
 bpf_want(&reg,22,0,0,allow,1);CHECK(sreg(&r,37,&reg,1)==0);
 q.ud=46;queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&
     c.res==-ACCESS&&lhealth(&r)==0&&finish(&r)==0);
 /* PDU word loads expose prepared SOCKET fields before any side effect. */
 CHECK(init(&r,0,8)==0);bpf_want(&reg,45,0,12,by_family,4);
 CHECK(sreg(&r,37,&reg,1)==0);zero(&q,sizeof(q));q.op=45;q.fd=10;
 q.off=1;q.ud=50;CHECK(bpf_submit(&r,&q,-ACCESS)==0);q.fd=2;q.ud=51;
#ifdef LINUX_ABI
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==q.ud&&
     c.res>=0&&CALL(N_CLOSE,c.res,0,0)==0);
#else
 CHECK(bpf_submit(&r,&q,-22)==0);
#endif
 CHECK(finish(&r)==0);
 /* OPENAT exposes flags/mode/resolve in its 24-byte payload. */
 CHECK(init(&r,0,8)==0);bpf_want(&reg,18,SBPF_SZ_STRICT,24,by_mode,4);
 CHECK(sreg(&r,37,&reg,1)==0);zero(&q,sizeof(q));q.op=18;q.fd=-1;
 q.addr=(u64)"bpf-openat";q.len=0601;q.misc=OPENFLAGS;q.ud=54;
 CHECK(bpf_submit(&r,&q,-ACCESS)==0);q.len=0600;q.ud=55;
#ifdef LINUX_ABI
 CHECK(bpf_submit(&r,&q,-9)==0&&finish(&r)==0);
#else
 CHECK(bpf_submit(&r,&q,-22)==0&&finish(&r)==0);
#endif
#ifdef LINUX_ABI
 struct lopen_how how;
 /* OPENAT2 snapshots open_how before filtering and descriptor lookup. */
 CHECK(init(&r,0,8)==0);
 bpf_want(&reg,28,SBPF_SZ_STRICT,24,by_open_flags,4);
 CHECK(sreg(&r,37,&reg,1)==0);zero(&how,sizeof(how));zero(&q,sizeof(q));
 q.op=28;q.fd=-1;q.off=(u64)&how;q.addr=(u64)"bpf-openat2";
 q.len=sizeof(how);q.ud=56;how.flags=1;CHECK(bpf_submit(&r,&q,-ACCESS)==0);
 how.flags=0;q.ud=57;CHECK(bpf_submit(&r,&q,-9)==0&&finish(&r)==0);
 struct lsockaddr_in sin;
 /* CONNECT's imported sockaddr snapshot is also visible before fd lookup. */
 CHECK(init(&r,0,8)==0);bpf_want(&reg,16,0,24,by_family,4);
 CHECK(sreg(&r,37,&reg,1)==0);zero(&sin,sizeof(sin));sin.family=10;
 zero(&q,sizeof(q));q.op=16;q.fd=-1;q.addr=(u64)&sin;q.off=sizeof(sin);q.ud=52;
 CHECK(bpf_submit(&r,&q,-ACCESS)==0);sin.family=2;q.ud=53;
 CHECK(bpf_submit(&r,&q,-9)==0&&finish(&r)==0);
#endif
 /* Registration and submission share a ring safely under contention. */
 CHECK(init(&r,0,64)==0&&bpipe(syncfd,0)==0);long pid=fork_child();CHECK(pid>=0);
 if(pid==0){CHECK(CALL(N_CLOSE,syncfd[0],0,0)==0&&
     CALL(N_WRITE,syncfd[1],"R",1)==1);for(int i=0;i<256;i++)
     if(bpf_nop(&r,0,1000+(u64)i,0)!=0)CALL(N_EXIT,2,0,0);
     CALL(N_EXIT,0,0,0);}
 CHECK(CALL(N_CLOSE,syncfd[1],0,0)==0&&CALL(N_READ,syncfd[0],&ready,1)==1);
 for(int i=0;i<32;i++){bpf_want(&reg,0,0,0,allow,1);
     CHECK(sreg(&r,37,&reg,1)==0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0&&
     CALL(N_CLOSE,syncfd[0],0,0)==0);r.si=*r.st;r.ci=*r.ch;
 CHECK(lhealth(&r)==0&&finish(&r)==0);
#ifdef LINUX_ABI
 /*
  * Blind registration is task-scoped, requires privilege or no_new_privs,
  * snapshots into new rings, stacks, and is inherited across fork.
  */
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){struct ring x;bpf_want(&reg,0,0,0,deny,1);
     if(CALL(N_SETUID,65534,0,0)!=0||bpf_task_reg(&reg)!=-ACCESS||
     sc(N_PRCTL,38,1,0,0,0,0)!=0||bpf_task_reg(&reg)!=0||
     init(&x,0,8)!=0||bpf_nop(&x,0,600,-ACCESS)!=0||finish(&x)!=0)
     CALL(N_EXIT,3,0,0);CALL(N_EXIT,0,0,0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 /* Like Linux task restrictions, blind filters survive a Linux exec. */
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){char *av[]={(char *)setup_self,(char *)"bpf_task_exec",0};
     char *ev[]={0};bpf_want(&reg,0,0,0,deny,1);
     if(bpf_task_reg(&reg)!=0)CALL(N_EXIT,5,0,0);
     sc(N_EXEC,(long)setup_self,(long)av,(long)ev,0,0,0);
     CALL(N_EXIT,6,0,0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 struct ring before,task1,task2,task3;CHECK(init(&before,0,8)==0);
 bpf_want(&reg,0,0,0,by_key,4);CHECK(bpf_task_reg(&reg)==0&&
     bpf_nop(&before,0,701,0)==0&&init(&task1,0,8)==0&&
     bpf_nop(&task1,0,700,-ACCESS)==0&&bpf_nop(&task1,0,42,0)==0);
 bpf_want(&reg,0,0,0,by_async,5);CHECK(bpf_task_reg(&reg)==0&&
     bpf_nop(&task1,0,42,0)==0&&init(&task2,0,8)==0&&
     bpf_nop(&task2,0,42,-ACCESS)==0&&bpf_nop(&task2,16,42,0)==0);
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){struct ring x;if(init(&x,0,8)!=0||
     bpf_nop(&x,0,42,-ACCESS)!=0||bpf_nop(&x,16,42,0)!=0||finish(&x)!=0)
     CALL(N_EXIT,4,0,0);CALL(N_EXIT,0,0,0);}
 CHECK(CALL(N_WAIT,pid,&status,0)==pid&&status==0);
 bpf_want(&reg,0,SBPF_DENY_REST,0,allow,1);CHECK(bpf_task_reg(&reg)==0&&
     init(&task3,0,8)==0&&bpf_nop(&task3,16,42,0)==0);
 zero(&q,sizeof(q));q.op=22;q.fd=-1;q.off=~0UL;q.addr=(u64)&byte;q.len=1;q.ud=702;
 CHECK(bpf_submit(&task3,&q,-ACCESS)==0&&finish(&task3)==0&&
     finish(&task2)==0&&finish(&task1)==0&&finish(&before)==0);
#endif
 return 0;
}

static int
nop_one(struct ring *r, u32 flags, int fd, u32 buf, u32 result,
    u64 key, int expected)
{
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=0;q.fd=fd;q.len=result;
 q.misc=flags;q.buf=(unsigned short)buf;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.res==expected&&
     c.flags==0);return 0;
}

static int
nop_flags_shared(void)
{
 struct ring r;struct sqe q;char data[8]={0};struct rwvec bufs[2];
 long fd;int files[2];

 fd=fdata("nop-file",'N');CHECK(fd>=0&&init(&r,0,8)==0);
 files[0]=(int)fd;files[1]=-1;bufs[0].base=data;bufs[0].len=sizeof(data);
 bufs[1].base=0;bufs[1].len=0;
 CHECK(freg(&r,files,2)==0&&breg(&r,bufs,2)==0);
 CHECK(nop_one(&r,1,-1,0,123,1,123)==0);
 CHECK(nop_one(&r,1,-1,0,~0U,2,-1)==0);
 CHECK(nop_one(&r,2,(int)fd,0,0,3,0)==0);
 CHECK(nop_one(&r,2,-1,0,0,4,-9)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0); /* fixed registration retains the file */
 CHECK(nop_one(&r,2|4,0,0,0,5,0)==0);
 CHECK(nop_one(&r,2|4,1,0,0,6,-9)==0);
 CHECK(nop_one(&r,4,-1,0,0,7,0)==0); /* modifier ignored without FILE */
 CHECK(nop_one(&r,8,-1,0,0,8,0)==0);
 CHECK(nop_one(&r,8,-1,1,0,9,-14)==0);
 CHECK(nop_one(&r,8,-1,2,0,10,-14)==0);
 CHECK(nop_one(&r,16,-1,0,0,11,0)==0);
 CHECK(nop_one(&r,1|2|4|8|16,0,0,77,12,77)==0);

 /* Unknown and CQE32-only flags fail in preparation before fd/buffer lookup. */
 zero(&q,sizeof(q));q.op=0;q.fd=-1;q.buf=99;q.misc=0x80000000U;
 CHECK(prep_reject_one(q,-22)==0);q.misc=32;CHECK(prep_reject_one(q,-22)==0);
 CHECK(bunreg(&r)==0&&nop_one(&r,8,-1,0,0,13,-14)==0);
 CHECK(funreg(&r)==0&&nop_one(&r,2|4,0,0,0,14,-9)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int
fallocate_one(struct ring *r, u32 flags, int fd, u64 off, u64 length,
    u32 mode, unsigned short personality, unsigned short buf, u32 rw_flags,
    int fd2, u64 addr3, u64 pad, u64 key, int expected)
{
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=17;q.flags=flags;q.fd=fd;
 q.off=off;q.addr=length;q.len=mode;q.misc=rw_flags;q.personality=personality;
 q.buf=buf;q.fd2=fd2;q.addr3=addr3;q.pad=pad;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.flags==0&&
     c.res==expected);return 0;
}

static int
fallocate_options_shared(void)
{
 struct ring r;struct sqe q;long fd,personality;int files[2],pfd[2];
#ifdef LINUX_ABI
 const int bad_fd_negative=-9,bad_fd_mode=-9;
#else
 const int bad_fd_negative=-22,bad_fd_mode=-NOTSUP;
#endif
 fd=fdata("fallocate-options",'F');CHECK(fd>=0&&init(&r,0,16)==0);
 /* Generic checks precede personality, opcode preparation, and file lookup. */
 zero(&q,sizeof(q));q.op=17;q.fd=9999;q.addr=4096;q.ioprio=1;
 q.personality=99;q.buf=1;CHECK(prep_reject_one(q,-22)==0);
 q.ioprio=0;q.flags=32;CHECK(prep_reject_one(q,-NOTSUP)==0);
 /* buf_index, rw_flags, and splice_fd_in are reserved for FALLOCATE. */
 CHECK(fallocate_one(&r,0,9999,0,4096,0,0,1,0,0,0,0,1,-22)==0);
 CHECK(fallocate_one(&r,0,9999,0,4096,0,0,0,1,0,0,0,2,-22)==0);
 CHECK(fallocate_one(&r,0,9999,0,4096,0,0,0,0,1,0,0,3,-22)==0);
 CHECK(fallocate_one(&r,0,9999,0,4096,0,99,0,0,0,0,0,4,-22)==0);
 personality=sreg(&r,9,0,0);CHECK(personality>0&&personality<=65535);
 /* Linux resolves the file first; native squeue validates its mode first. */
 CHECK(fallocate_one(&r,0,9999,0,4096,0x100,
     (unsigned short)personality,0,0,0,0,0,5,bad_fd_mode)==0);
 CHECK(fallocate_one(&r,0,9999,(u64)-1,4096,0,0,0,0,0,0,0,6,
     bad_fd_negative)==0);
 CHECK(fallocate_one(&r,0,(int)fd,(u64)-1,4096,0,0,0,0,0,0,0,7,-22)==0);
 CHECK(fallocate_one(&r,0,(int)fd,0,0,0,0,0,0,0,0,0,8,-22)==0);
 CHECK(fallocate_one(&r,0,(int)fd,0x7fffffffffffff00UL,4096,0,0,0,0,
     0,0,0,9,-27)==0);
 /* ASYNC and tail words reach execution; a pipe supplies an fs-independent error. */
 CHECK(bpipe(pfd,0)==0&&fallocate_one(&r,16,pfd[1],0,4096,0,
     (unsigned short)personality,0,0,0,0x1122334455667788UL,
     0x8877665544332211UL,10,-29)==0);
 /* Fixed registration pins the pipe after ambient close; sparse slots fail. */
 files[0]=pfd[1];files[1]=-1;CHECK(freg(&r,files,2)==0&&
     CALL(N_CLOSE,pfd[1],0,0)==0);
 CHECK(fallocate_one(&r,1,0,0,4096,0,0,0,0,0,0,0,20,-29)==0);
 CHECK(fallocate_one(&r,1,1,0,4096,0,0,0,0,0,0,0,21,-9)==0);
 CHECK(fallocate_one(&r,1,99,0,4096,0,0,0,0,0,0,0,22,-9)==0);
 CHECK(funreg(&r)==0&&fallocate_one(&r,1,0,0,4096,0,0,0,0,0,0,0,
     23,-9)==0);
 CHECK(CALL(N_CLOSE,pfd[0],0,0)==0&&CALL(N_CLOSE,fd,0,0)==0);
 CHECK(sreg(&r,10,0,(u32)personality)==0&&lhealth(&r)==0&&finish(&r)==0);
 return 0;
}

static int
fsync_one(struct ring *r, u32 flags, int fd, u64 off, u32 len,
    u32 fsync_flags, unsigned short personality, unsigned short buf, int fd2,
    u64 addr, u64 addr3, u64 pad, u64 key, int expected)
{
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=3;q.flags=flags;q.fd=fd;
 q.off=off;q.addr=addr;q.len=len;q.misc=fsync_flags;q.personality=personality;
 q.buf=buf;q.fd2=fd2;q.addr3=addr3;q.pad=pad;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.flags==0&&
     c.res==expected);return 0;
}

static int
fsync_options_shared(void)
{
 struct ring r;struct sqe q;long fd,personality;int files[2],pfd[2];
 fd=fdata("fsync-options",'S');CHECK(fd>=0&&init(&r,0,16)==0);
 /* Generic checks precede personality, opcode preparation, and file lookup. */
 zero(&q,sizeof(q));q.op=3;q.fd=9999;q.ioprio=1;q.personality=99;q.addr=1;
 CHECK(prep_reject_one(q,-22)==0);q.ioprio=0;q.flags=32;
 CHECK(prep_reject_one(q,-NOTSUP)==0);
 /* FSYNC prep rejects addr, buf_index, and splice_fd_in before file lookup. */
 CHECK(fsync_one(&r,0,9999,0,0,0,0,0,0,1,0,0,1,-22)==0);
 CHECK(fsync_one(&r,0,9999,0,0,0,0,1,0,0,0,0,2,-22)==0);
 CHECK(fsync_one(&r,0,9999,0,0,0,0,0,1,0,0,0,3,-22)==0);
 CHECK(fsync_one(&r,0,(int)fd,0,0,0,99,0,0,0,0,0,4,-22)==0);
 personality=sreg(&r,9,0,0);CHECK(personality>0&&personality<=65535);
 /* Unknown flags, both sync modes, and Linux range edge behavior. */
 CHECK(fsync_one(&r,0,9999,0,0,2,(unsigned short)personality,0,0,
     0,0,0,5,-22)==0);
 /* File lookup precedes execution-time range validation. */
 CHECK(fsync_one(&r,0,9999,(u64)-1,0,0,0,0,0,0,0,0,24,-9)==0);
 CHECK(fsync_one(&r,0,(int)fd,0,0,0,(unsigned short)personality,0,0,
     0,0,0,6,0)==0);
 CHECK(fsync_one(&r,0,(int)fd,1,2,1,(unsigned short)personality,0,0,
     0,0,0,7,0)==0);
 CHECK(fsync_one(&r,0,(int)fd,(u64)-1,0,0,0,0,0,0,0,0,8,-22)==0);
 CHECK(fsync_one(&r,0,(int)fd,0x7fffffffffffffffUL,2,0,0,0,0,
     0,0,0,9,0)==0);
 /* ASYNC, addr3, and final padding are accepted. */
 CHECK(fsync_one(&r,16,(int)fd,0,0,1,(unsigned short)personality,0,0,0,
     0x1122334455667788UL,0x8877665544332211UL,10,0)==0);
 CHECK(bpipe(pfd,0)==0&&fsync_one(&r,0,pfd[0],0,0,0,0,0,0,0,0,0,
     11,-22)==0);
 CHECK(CALL(N_CLOSE,pfd[0],0,0)==0&&CALL(N_CLOSE,pfd[1],0,0)==0);
 /* Fixed registration pins the file after ambient close; sparse slots fail. */
 files[0]=(int)fd;files[1]=-1;CHECK(freg(&r,files,2)==0&&CALL(N_CLOSE,fd,0,0)==0);
 CHECK(fsync_one(&r,1,0,0,0,1,0,0,0,0,0,0,20,0)==0);
 CHECK(fsync_one(&r,1,1,0,0,0,0,0,0,0,0,0,21,-9)==0);
 CHECK(fsync_one(&r,1,99,0,0,0,0,0,0,0,0,0,22,-9)==0);
 CHECK(funreg(&r)==0&&fsync_one(&r,1,0,0,0,0,0,0,0,0,0,0,23,-9)==0);
 CHECK(sreg(&r,10,0,(u32)personality)==0&&lhealth(&r)==0&&finish(&r)==0);
 return 0;
}

static int
fadvise_one(struct ring *r, u32 flags, int fd, u64 off, u64 length, u32 len,
    u32 advice, unsigned short personality, unsigned short buf, int fd2,
    u64 addr3, u64 pad, u64 key, int expected)
{
 struct sqe q;struct cqe c;zero(&q,sizeof(q));q.op=24;q.flags=flags;q.fd=fd;
 q.off=off;q.addr=length;q.len=len;q.misc=advice;q.personality=personality;
 q.buf=buf;q.fd2=fd2;q.addr3=addr3;q.pad=pad;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.flags==0&&
     c.res==expected);return 0;
}

static int
fadvise_options_shared(void)
{
 struct ring r;struct sqe q;long fd,personality;int files[2];
#ifdef LINUX_ABI
 const int bad_advice_bad_fd=-9, negative_offset=0;
#else
 const int bad_advice_bad_fd=-22, negative_offset=-22;
#endif
 fd=fdata("fadvise-options",'A');CHECK(fd>=0&&init(&r,0,16)==0);
 /* Generic options and reserved fields precede personality/file lookup. */
 zero(&q,sizeof(q));q.op=24;q.fd=9999;q.ioprio=1;q.personality=99;
 CHECK(prep_reject_one(q,-22)==0);q.ioprio=0;q.flags=32;
 CHECK(prep_reject_one(q,-NOTSUP)==0);
 CHECK(fadvise_one(&r,0,9999,0,1,0,0,99,1,0,0,0,1,-22)==0);
 CHECK(fadvise_one(&r,0,9999,0,1,0,0,99,0,1,0,0,2,-22)==0);
 personality=sreg(&r,9,0,0);CHECK(personality>0&&personality<=65535);
 /* All advice values, primary/fallback/zero lengths, and valid personality. */
 for(u32 advice=0;advice<=5;advice++)
  CHECK(fadvise_one(&r,0,(int)fd,0,advice==1?0:1,advice==1?1:0,
      advice,(unsigned short)personality,0,0,0,0,10+advice,0)==0);
 CHECK(fadvise_one(&r,0,(int)fd,0,0,0,0,0,0,0,0,0,20,0)==0);
 /* File lookup precedes range/advice execution errors. */
 CHECK(fadvise_one(&r,0,9999,0,1,0,0xffffffffU,0,0,0,0,0,21,
     bad_advice_bad_fd)==0);
 CHECK(fadvise_one(&r,0,(int)fd,0,1,0,0xffffffffU,0,0,0,0,0,22,-22)==0);
 CHECK(fadvise_one(&r,0,(int)fd,(u64)-1,1,0,0,0,0,0,0,0,23,
     negative_offset)==0);
 CHECK(fadvise_one(&r,0,(int)fd,0,(u64)-1,0,0,0,0,0,0,0,24,-22)==0);
 /* ASYNC, addr3, and final padding are accepted. */
 CHECK(fadvise_one(&r,16,(int)fd,0,1,0,3,(unsigned short)personality,
     0,0,0x1122334455667788UL,0x8877665544332211UL,25,0)==0);
 files[0]=(int)fd;files[1]=-1;CHECK(freg(&r,files,2)==0&&CALL(N_CLOSE,fd,0,0)==0);
 CHECK(fadvise_one(&r,1,0,0,1,0,0,0,0,0,0,0,30,0)==0);
 CHECK(fadvise_one(&r,1,1,0,1,0,0,0,0,0,0,0,31,-9)==0);
 CHECK(fadvise_one(&r,1,99,0,1,0,0,0,0,0,0,0,32,-9)==0);
 CHECK(funreg(&r)==0&&fadvise_one(&r,1,0,0,1,0,0,0,0,0,0,0,33,-9)==0);
 CHECK(sreg(&r,10,0,(u32)personality)==0&&lhealth(&r)==0&&finish(&r)==0);
 return 0;
}

static int
fixed_install_one(struct ring *r, u32 flags, int slot, u64 key, int cloexec,
    int expected)
{
 struct sqe q;struct cqe c;char value=0;zero(&q,sizeof(q));q.op=54;q.flags=1;
 q.fd=slot;q.misc=flags;q.ud=key;queue(r,q,0);
 CHECK(lsubmit(r,1)==0&&lget(r,&c,1)==0&&c.ud==key&&c.flags==0);
 if(expected<0){CHECK(c.res==expected);return 0;}
 CHECK(c.res>=0&&((CALL(N_FCNTL,c.res,1,0)&1)!=0)==cloexec);
 CHECK(CALL(N_SEEK,c.res,0,0)==0);
 CHECK(CALL(N_READ,c.res,&value,1)==1&&value=='F');
 CHECK(CALL(N_CLOSE,c.res,0,0)==0);return 0;
}

static int
fixed_fd_install_flags_shared(void)
{
 struct ring r;struct sqe q;long fd;int files[2];
 fd=fdata("fixed-install",'F');CHECK(fd>=0&&init(&r,0,8)==0);
 files[0]=(int)fd;files[1]=-1;CHECK(freg(&r,files,2)==0);
 CHECK(CALL(N_CLOSE,fd,0,0)==0); /* registration owns the surviving ref */
 /* Generic options precede personality lookup and opcode preparation. */
 zero(&q,sizeof(q));q.op=54;q.flags=1;q.fd=99;q.ioprio=1;q.personality=99;
 CHECK(prep_reject_one(q,-22)==0);q.ioprio=0;q.flags=1|32;
 CHECK(prep_reject_one(q,-NOTSUP)==0);
 /* Linux checks all six reserved fields before requiring FIXED_FILE. */
 for(int field=0;field<6;field++){
  zero(&q,sizeof(q));q.op=54;q.fd=99;
  if(field==0)q.off=1;if(field==1)q.addr=1;if(field==2)q.len=1;
  if(field==3)q.buf=1;if(field==4)q.fd2=1;if(field==5)q.addr3=1;
  CHECK(prep_reject_one(q,-22)==0);
 }
 zero(&q,sizeof(q));q.op=54;q.fd=99;q.misc=0x80000000U;
 CHECK(prep_reject_one(q,-9)==0);
 CHECK(fixed_install_one(&r,0,0,1,1,0)==0);
 CHECK(fixed_install_one(&r,1,0,2,0,0)==0);
 CHECK(fixed_install_one(&r,0,1,3,0,-9)==0);
 for(int i=0;i<32;i++)
  CHECK(fixed_install_one(&r,(u32)(i&1),0,10+i,(i&1)==0,0)==0);
 zero(&q,sizeof(q));q.op=54;q.flags=1;q.fd=99;q.misc=2;
 CHECK(prep_reject_one(q,-22)==0);q.misc=0x80000000U;
 CHECK(prep_reject_one(q,-22)==0);
 zero(&q,sizeof(q));q.op=54;q.fd=0;q.misc=1;
 CHECK(prep_reject_one(q,-9)==0);
 /* Unknown flags precede personality EPERM; accepted padding has no effect. */
 long personality=sreg(&r,9,0,0);CHECK(personality>0&&personality<=65535);
 zero(&q,sizeof(q));q.op=54;q.flags=1;q.fd=0;q.misc=2;
 q.personality=(unsigned short)personality;q.ud=51;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,(struct cqe[1]){{0}},0)==0);
 {struct cqe c;CHECK(lget(&r,&c,1)==0&&c.ud==51&&c.res==-22);}
 q.misc=0;q.ud=52;queue(&r,q,0);CHECK(lsubmit(&r,1)==0);
 {struct cqe c;CHECK(lget(&r,&c,1)==0&&c.ud==52&&c.res==-1);}
 CHECK(sreg(&r,10,0,(u32)personality)==0);
 zero(&q,sizeof(q));q.op=54;q.flags=1|16;q.fd=0;q.misc=1;
 q.pad=0xfeedface;q.ud=53;queue(&r,q,0);CHECK(lsubmit(&r,1)==0);
 {struct cqe c;CHECK(lget(&r,&c,1)==0&&c.ud==53&&c.res>=0&&
     (CALL(N_FCNTL,c.res,1,0)&1)==0&&CALL(N_CLOSE,c.res,0,0)==0);}
 CHECK(funreg(&r)==0&&fixed_install_one(&r,0,0,50,0,-9)==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static void
msgq(struct ring *r, int target, u64 cmd, u64 msg_ud, u32 len,
    u32 msg_flags, u32 dst_idx, u64 src_idx, u64 key)
{
 struct sqe q;zero(&q,sizeof(q));q.op=40;q.fd=target;q.off=msg_ud;
 q.addr=cmd;q.len=len;q.misc=msg_flags;q.fd2=(int)dst_idx;
 q.addr3=src_idx;q.ud=key;queue(r,q,0);
}

static int
msg_ring_shared(void)
{
 struct ring a,b,d;struct cqe c[3];long fa,fb,fold,regular;
 int src[3],dst[3],empty=-1;

 /* Cross-ring and self MSG_DATA, including exact target CQE flags. */
 CHECK(init(&a,0,8)==0&&init(&b,0,8)==0);
 msgq(&a,(int)b.fd,0,101,42,0,0,0,1);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&lresult(c,1,1,0)==0);
 CHECK(lget(&b,c,1)==0&&c[0].ud==101&&c[0].res==42);
 msgq(&a,(int)b.fd,0,102,43,2,0xa5000002U,0,2);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].ud==2&&c[0].res==0);
 CHECK(lget_any(&b,c,1)==0&&c[0].ud==102&&c[0].res==43&&
     c[0].flags==0xa5000002U);
 msgq(&a,(int)a.fd,0,103,44,0,0,0,3);
 CHECK(lsubmit(&a,1)==0&&lget_any(&a,c,2)==0&&
     lresult(c,2,3,0)==0&&lresult(c,2,103,44)==0);

 /* Execution-time validation must not publish a target message. */
 for(int mode=0;mode<4;mode++) {
  msgq(&a,(int)b.fd,mode==3?99:0,110+mode,1,
      mode==0?1:0,mode==1?1:0,mode==2?1:0,10+mode);
  CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&
      c[0].ud==(u64)(10+mode)&&c[0].res==-22);
  CHECK(*b.ct==b.ci);
 }
 /* Unknown flags are a preparation error, before target lookup. */
 msgq(&a,-1,0,120,1,0x80000000U,0,0,20);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);
 regular=sc(N_OPENAT,-100,(long)"msg-regular",OPENFLAGS,0600,0,0);
 CHECK(regular>=0);msgq(&a,(int)regular,0,121,1,0,0,0,21);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-BADSTATE);
 msgq(&a,-1,0,122,1,0,0,0,22);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-9);
 CHECK(init(&d,SDIS,8)==0);msgq(&a,(int)d.fd,0,123,1,0,0,0,23);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-BADSTATE);
 CHECK(senable(&d)==0&&finish(&d)==0&&CALL(N_CLOSE,regular,0,0)==0);

 /* SEND_FD preserves source ownership and captured access, and supports
  * explicit replacement, allocation, and target-CQE suppression. */
 fa=fdata("msg-a",'A');fb=fdata("msg-b",'B');fold=fdata("msg-old",'O');
 CHECK(fa>=0&&fb>=0&&fold>=0);src[0]=(int)fa;src[1]=(int)fb;src[2]=-1;
 dst[0]=-1;dst[1]=-1;dst[2]=(int)fold;
 CHECK(freg(&a,src,3)==0&&freg(&b,dst,3)==0);
 CHECK(CALL(N_CLOSE,fa,0,0)==0&&CALL(N_CLOSE,fb,0,0)==0&&
     CALL(N_CLOSE,fold,0,0)==0);
 msgq(&a,(int)b.fd,1,201,0,0,1,0,31);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].ud==31&&c[0].res==0);
 CHECK(lget(&b,c,1)==0&&c[0].ud==201&&c[0].res==0&&fbyte(&b,0,'A')==0);
 CHECK(fbyte(&a,0,'A')==0); /* transfer is a copy, not a move */
 msgq(&a,(int)b.fd,1,202,0,0,1,1,32);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==0);
 CHECK(lget(&b,c,1)==0&&c[0].ud==202&&c[0].res==0&&fbyte(&b,0,'B')==0);
 msgq(&a,(int)b.fd,1,203,0,0,~0U,0,33);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==1);
 CHECK(lget(&b,c,1)==0&&c[0].ud==203&&c[0].res==1&&fbyte(&b,1,'A')==0);
 msgq(&a,(int)b.fd,1,204,0,3,3,1,34);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==0&&
     *b.ct==b.ci&&fbyte(&b,2,'B')==0);

 /* SEND_FD negative paths leave both tables usable and unchanged. */
 msgq(&a,(int)a.fd,1,210,0,0,1,0,40);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);
 msgq(&a,(int)b.fd,1,211,1,0,1,0,41);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);
 msgq(&a,(int)b.fd,1,212,0,0,1,2,42);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-9&&
     fbyte(&b,0,'B')==0);
 msgq(&a,(int)b.fd,1,213,0,0,0,0,43);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);
 msgq(&a,(int)b.fd,1,214,0,0,4,0,44);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);
 msgq(&a,(int)b.fd,1,215,0,0,~0U,0,45);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-23);
 CHECK(init(&d,0,8)==0);msgq(&a,(int)d.fd,1,216,0,0,1,0,46);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-6&&
     fbyte(&a,0,'A')==0);
 CHECK(freg(&d,&empty,1)==0);msgq(&d,(int)b.fd,1,217,0,0,1,0,47);
 CHECK(lsubmit(&d,1)==0&&lget(&d,c,1)==0&&c[0].res==-9&&
     fbyte(&b,0,'B')==0);
 msgq(&a,(int)b.fd,1,218,0,0x80000000U,1,0,48);
 CHECK(lsubmit(&a,1)==0&&lget(&a,c,1)==0&&c[0].res==-22);

 CHECK(funreg(&d)==0&&finish(&d)==0);
 CHECK(funreg(&a)==0&&funreg(&b)==0&&lhealth(&a)==0&&lhealth(&b)==0);
 CHECK(finish(&a)==0&&finish(&b)==0);return 0;
}

static int
sq_rewind_shared(void)
{
 struct params p;struct ring r;struct sqe q;struct cqe c;
 zero(&p,sizeof(p));p.flags=SREWIND;CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(init(&r,NOARRAY|SREWIND,8)==0&&r.p.flags==(NOARRAY|SREWIND));
 CHECK(*r.sh==0&&*r.st==0);
 /* No tail publication: each enter consumes the requested prefix at index 0. */
 for(u32 i=0;i<8;i++){zero(&q,sizeof(q));q.ud=1000+i;r.sqes[i]=q;}
 CHECK(sc(N_ENTER,r.fd,3,0,0,0,0)==3&&*r.sh==0&&*r.st==0);
 for(u32 i=0;i<3;i++){CHECK(lget(&r,&c,1)==0&&c.ud==1000+i&&c.res==0);}
 /* A later call rewinds, observes rewritten entries, and clamps to SQ size. */
 for(u32 i=0;i<8;i++)r.sqes[i].ud=1100+i;
 CHECK(sc(N_ENTER,r.fd,99,0,0,0,0)==8&&*r.sh==0&&*r.st==0);
 for(u32 i=0;i<8;i++)CHECK(lget(&r,&c,1)==0&&c.ud==1100+i&&c.res==0);
 /* Preparation failure follows SUBMIT_ALL policy without changing head/tail. */
 r.sqes[0].op=255;r.sqes[0].ud=1200;r.sqes[1].op=0;r.sqes[1].ud=1201;
 CHECK(sc(N_ENTER,r.fd,2,0,0,0,0)==1&&lget(&r,&c,1)==0&&c.ud==1200&&c.res==-22&&*r.sh==0&&*r.st==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 CHECK(init(&r,NOARRAY|SREWIND|SALL,8)==0);r.sqes[0].op=255;r.sqes[0].ud=1300;r.sqes[1].op=0;r.sqes[1].ud=1301;
 CHECK(sc(N_ENTER,r.fd,2,0,0,0,0)==2&&lget(&r,&c,1)==0&&c.ud==1300&&c.res==-22&&lget(&r,&c,1)==0&&c.ud==1301&&c.res==0&&*r.sh==0&&*r.st==0);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int
extended_layout_shared(void)
{
 u32 modes[]={SSQE128,SCQE32,SSQE128|SCQE32,SSQE128|SCQE32|NOARRAY};
 for(u32 m=0;m<sizeof(modes)/sizeof(modes[0]);m++){
  struct ring r;struct sqe q;CHECK(init(&r,modes[m],8)==0&&r.p.flags==modes[m]);
  for(u32 n=0;n<32;n++){
   u32 slot=r.si&(r.p.sq-1);unsigned char *ext=(unsigned char *)&r.sqes[slot*((modes[m]&SSQE128)?2:1)+1];
   if(modes[m]&SSQE128)for(u32 i=0;i<sizeof(struct sqe);i++)ext[i]=(unsigned char)(0xa5U+i+n);
   zero(&q,sizeof(q));q.ud=900+n;queue(&r,q,0);CHECK(lsubmit(&r,1)==0);
   u32 ci=r.ci&(r.p.cq-1);struct cqe *cp=&r.cqes[ci*((modes[m]&SCQE32)?2:1)];
   CHECK(lwait(&r,1)==0&&cp[0].ud==900+n&&cp[0].res==0&&cp[0].flags==0);
   if(modes[m]&SCQE32)CHECK(cp[1].ud==0&&cp[1].res==0&&cp[1].flags==0);
   if(modes[m]&SSQE128)for(u32 i=0;i<sizeof(struct sqe);i++)CHECK(ext[i]==(unsigned char)(0xa5U+i+n));
   __atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);
  }
  CHECK(lhealth(&r)==0&&finish(&r)==0);
 }
 return 0;
}

static int
cqe_mixed_shared(void)
{
 struct params p;struct ring r;struct sqe q;struct cqe *c;u64 *ext;
 /* Mixed and fixed-width CQEs are exclusive; a mixed CQ needs two slots. */
 zero(&p,sizeof(p));p.flags=SCQE32|SCQEMIXED;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 zero(&p,sizeof(p));p.flags=SCQEMIXED|8;p.cq=1;
 CHECK(CALL(N_SETUP,1,&p,0)==-OVERFLOW);

 CHECK(init(&r,SCQEMIXED,4)==0&&r.p.flags==SCQEMIXED);
 /* An ordinary completion consumes one logical 16-byte slot. */
 zero(&q,sizeof(q));q.ud=600;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lwait(&r,1)==0&&*r.ct==1);
 c=&r.cqes[0];CHECK(c->ud==600&&c->res==0&&c->flags==0);
 __atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);
 /* NOP_CQE32 consumes two slots and preserves both 64-bit extension words. */
 zero(&q,sizeof(q));q.op=0;q.misc=32;q.off=0x1122334455667788UL;
 q.addr=0x8877665544332211UL;q.ud=601;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lwait(&r,2)==0&&*r.ct==3);
 c=&r.cqes[1];ext=(u64 *)&r.cqes[2];
 CHECK(c->ud==601&&c->res==0&&c->flags==CQE_F32&&
     ext[0]==q.off&&ext[1]==q.addr);
 r.ci+=2;__atomic_store_n(r.ch,r.ci,__ATOMIC_RELEASE);
 /* Put the logical tail at the last slot, then require SKIP wrap padding. */
 for(u32 i=0;i<4;i++){zero(&q,sizeof(q));q.ud=610+i;queue(&r,q,0);
  CHECK(lsubmit(&r,1)==0);}
 CHECK(lwait(&r,4)==0&&*r.ct==7);
 for(u32 i=0;i<4;i++)if(r.cqes[3+i].ud!=610+i||
     r.cqes[3+i].res!=0||r.cqes[3+i].flags!=0){
  put("CQE_MIXED_ORDINARY_DIAG ");putnum(i);put(" ");
  putnum(r.cqes[3+i].ud);put(" ");putnum(r.cqes[3+i].res);put(" ");
  putnum(r.cqes[3+i].flags);put("\n");return __LINE__;
 }
 r.ci+=4;__atomic_store_n(r.ch,r.ci,__ATOMIC_RELEASE);
 zero(&q,sizeof(q));q.misc=32;q.off=0xa1a2a3a4a5a6a7a8UL;
 q.addr=0xb1b2b3b4b5b6b7b8UL;q.ud=620;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lwait(&r,3)==0&&*r.ct==10);
 CHECK(r.cqes[7].ud==0&&r.cqes[7].res==0&&r.cqes[7].flags==CQE_SKIP);
 c=&r.cqes[0];ext=(u64 *)&r.cqes[1];
 CHECK(c->ud==620&&c->res==0&&c->flags==CQE_F32&&
     ext[0]==q.off&&ext[1]==q.addr);
 r.ci+=3;__atomic_store_n(r.ch,r.ci,__ATOMIC_RELEASE);
 CHECK(lhealth(&r)==0&&finish(&r)==0);

 /* If only the wrap slot is free, publish SKIP and backlog the large CQE. */
 CHECK(init(&r,SCQEMIXED,4)==0);
 for(u32 i=0;i<7;i++){zero(&q,sizeof(q));q.ud=700+i;queue(&r,q,0);
  if((i&1)!=0)CHECK(lsubmit(&r,2)==0);}
 CHECK(lsubmit(&r,1)==0&&*r.ct==7);
 zero(&q,sizeof(q));q.misc=32;q.off=0xc1c2c3c4c5c6c7c8UL;
 q.addr=0xd1d2d3d4d5d6d7d8UL;q.ud=720;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&*r.ct==8&&(*r.sf&2)!=0);
 for(u32 i=0;i<7;i++)CHECK(r.cqes[i].ud==700+i&&
     r.cqes[i].res==0&&r.cqes[i].flags==0);
 CHECK(r.cqes[7].ud==0&&r.cqes[7].res==0&&r.cqes[7].flags==CQE_SKIP);
 r.ci=8;__atomic_store_n(r.ch,r.ci,__ATOMIC_RELEASE);
 CHECK(sc(N_ENTER,r.fd,0,0,0,0,0)==0&&lwait(&r,2)==0&&
     *r.ct==10&&(*r.sf&2)==0);
 c=&r.cqes[0];ext=(u64 *)&r.cqes[1];
 CHECK(c->ud==720&&c->res==0&&c->flags==CQE_F32&&
     ext[0]==q.off&&ext[1]==q.addr);
 r.ci+=2;__atomic_store_n(r.ch,r.ci,__ATOMIC_RELEASE);
 CHECK(lhealth(&r)==0&&finish(&r)==0);

 /* Fixed CQE32 carries the same NOP payload without the mixed-width marker. */
 CHECK(init(&r,SCQE32,8)==0);zero(&q,sizeof(q));q.misc=32;
 q.off=0xe1e2e3e4e5e6e7e8UL;q.addr=0xf1f2f3f4f5f6f7f8UL;q.ud=800;
 queue(&r,q,0);CHECK(lsubmit(&r,1)==0&&lwait(&r,1)==0&&*r.ct==1);
 c=&r.cqes[0];ext=(u64 *)&r.cqes[1];
 CHECK(c->ud==800&&c->res==0&&c->flags==0&&
     ext[0]==q.off&&ext[1]==q.addr);
 __atomic_store_n(r.ch,++r.ci,__ATOMIC_RELEASE);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int
enter_no_iowait_shared(void)
{
 struct ring r;struct sqe q;struct cqe c;const u32 no_iowait=1U<<7;
 CHECK(init(&r,0,8)==0);
 /* The hint neither requires nor inspects an argument when no wait occurs. */
 CHECK(sc(N_ENTER,r.fd,0,0,no_iowait,1,~0UL)==0);
 zero(&q,sizeof(q));q.ud=801;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,no_iowait,1,~0UL)==1&&
     lget(&r,&c,1)==0&&c.ud==801&&c.res==0);
 /* It composes with GETEVENTS and a completion produced by this call. */
 zero(&q,sizeof(q));q.ud=802;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,1,no_iowait|1,0,0)==1&&
     lget(&r,&c,1)==0&&c.ud==802&&c.res==0);
 /* EXT_ARG remains uninspected without GETEVENTS; unknown flags still fail. */
 CHECK(sc(N_ENTER,r.fd,0,0,no_iowait|8,1,~0UL)==0);
 CHECK(sc(N_ENTER,r.fd,0,0,no_iowait|(1U<<30),0,0)==-22);
 CHECK(lhealth(&r)==0&&finish(&r)==0);return 0;
}

static int
register_msg_ring_shared(void)
{
 struct ring target,disabled;struct sqe q;struct cqe c;long regular,m;struct sqe *cross,*ro;
 CHECK(init(&target,0,8)==0);
 zero(&q,sizeof(q));q.op=40;q.fd=(int)target.fd;q.off=700;q.len=71;
 /* Blind registration has an exact pointer/count/SQE contract. */
 CHECK(sregfd(-1,31,0,1)==-22&&sregfd(-1,31,&q,0)==-22&&
     sregfd(-1,31,&q,2)==-22&&sregfd(-1,31,(void *)1,1)==-14);
 for(int mode=0;mode<8;mode++){
  struct sqe bad=q;
  if(mode==0)bad.op=0;else if(mode==1)bad.flags=1;else if(mode==2)bad.buf=1;
  else if(mode==3)bad.personality=1;else if(mode==4)bad.addr=1;
  else if(mode==5)bad.addr3=1;else if(mode==6)bad.misc=1;
  else bad.fd2=1;
  CHECK(sregfd(-1,31,&bad,1)==-22&&*target.ct==target.ci);
 }
 /* Nonblind descriptors still resolve as source rings; bad targets are exact. */
 CHECK(sregfd(-2,31,&q,1)==-9);
 q.fd=-1;CHECK(sregfd(-1,31,&q,1)==-9);q.fd=(int)target.fd;
 regular=sc(N_OPENAT,-100,(long)"register-msg-regular",OPENFLAGS,0600,0,0);
 CHECK(regular>=0);q.fd=(int)regular;CHECK(sregfd(-1,31,&q,1)==-BADSTATE&&*target.ct==target.ci);
 CHECK(CALL(N_CLOSE,regular,0,0)==0&&init(&disabled,SDIS,8)==0);
 q.fd=(int)disabled.fd;CHECK(sregfd(-1,31,&q,1)==-BADSTATE&&senable(&disabled)==0&&finish(&disabled)==0);
 /* Faulting and read-only SQEs do not require a writable argument. */
 m=sc(N_MMAP,0,8192,3,ANON_FLAGS,-1,0);CHECK(m>=0&&CALL(N_MUNMAP,m+4096,4096,0)==0);
 cross=(struct sqe *)(m+4096-sizeof(struct sqe)/2);zero(cross,sizeof(struct sqe)/2);
 CHECK(sregfd(-1,31,cross,1)==-14&&CALL(N_MUNMAP,m,4096,0)==0);
 m=sc(N_MMAP,0,4096,3,ANON_FLAGS,-1,0);CHECK(m>=0);ro=(struct sqe *)m;*ro=q;ro->fd=(int)target.fd;
 CHECK(CALL(N_MPROTECT,m,4096,1)==0&&sregfd(-1,31,ro,1)==0&&CALL(N_MUNMAP,m,4096,0)==0);
 CHECK(lget(&target,&c,1)==0&&c.ud==700&&c.res==71&&c.flags==0);
 /* FLAGS_PASS publishes the supplied target-CQE flags. */
 q.fd=(int)target.fd;q.off=701;q.len=72;q.misc=2;q.fd2=(int)0xa5000002U;
 CHECK(sregfd(-1,31,&q,1)==0&&lget_any(&target,&c,1)==0&&
     c.ud==701&&c.res==72&&c.flags==0xa5000002U);
 /* The registered-ring high bit is ignored for a blind operation, as on Linux. */
 q.off=702;q.len=73;q.misc=0;q.fd2=0;
 CHECK(sregfd(-1,31|(1U<<31),&q,1)==0&&lget(&target,&c,1)==0&&
     c.ud==702&&c.res==73&&c.flags==0);
 CHECK(lhealth(&target)==0&&finish(&target)==0);return 0;
}

static int
sqpoll_nonfixed_shared(void)
{
 struct ring r;struct cqe c;int fds[2];char byte=0;
 CHECK(init(&r,0,8)==0);
 CHECK((r.p.features&(1U<<7))!=0&&finish(&r)==0);
 CHECK(init(&r,SSQPOLL,8)==0);
 CHECK((r.p.features&(1U<<7))!=0&&bpipe(fds,0)==0);
 CHECK(CALL(N_WRITE,fds[1],"N",1)==1);
 lq(&r,22,0,fds[0],(u64)&byte,1,0,0x7101);
 CHECK(lsubmit(&r,1)==0);
 CHECK(sc(N_ENTER,r.fd,0,0,SQ_WAKEUP,0,0)==0);
 CHECK(lget(&r,&c,1)==0&&c.ud==0x7101&&c.res==1&&byte=='N');
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 lq(&r,22,0,fds[0],(u64)&byte,1,0,0x7102);
 CHECK(lsubmit(&r,1)==0);
 CHECK(sc(N_ENTER,r.fd,0,0,SQ_WAKEUP,0,0)==0);
 CHECK(lget(&r,&c,1)==0&&c.ud==0x7102&&c.res==-9);
 CHECK(lhealth(&r)==0&&finish(&r)==0);
 return 0;
}

static int
sqpoll_attach_shared(void)
{
 struct ring source,attached,nested;struct cqe c;int fds[2];char byte=0;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 for(u32 i=0;i<8;i++){
  lq(&source,0,0,-1,0,0,0,0x6000+i);
  lq(&attached,0,0,-1,0,0,0,0x6100+i);
 }
 CHECK(sc(N_ENTER,source.fd,8,0,SQ_WAKEUP|SQ_WAIT,0,0)==8);
 CHECK(sc(N_ENTER,attached.fd,8,0,SQ_WAKEUP|SQ_WAIT,0,0)==8);
 for(u32 i=0;i<8;i++){
  CHECK(lget(&source,&c,1)==0&&c.ud==0x6000+i&&c.res==0);
  CHECK(lget(&attached,&c,1)==0&&c.ud==0x6100+i&&c.res==0);
 }
 CHECK(bpipe(fds,0)==0&&CALL(N_WRITE,fds[1],"S",1)==1);
 lq(&attached,22,0,fds[0],(u64)&byte,1,0,0x6200);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6200&&c.res==1&&byte=='S');
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 lq(&attached,22,0,fds[0],(u64)&byte,1,0,0x6201);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6201&&c.res==-9);
 CHECK(finish(&source)==0);
 CHECK(init_ex_wq(&nested,SSQPOLL|SATTACHWQ,8,0,attached.fd)==0);
 lq(&attached,0,0,-1,0,0,0,0x6300);
 lq(&nested,0,0,-1,0,0,0,0x6400);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sc(N_ENTER,nested.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6300&&c.res==0);
 CHECK(lget(&nested,&c,1)==0&&c.ud==0x6400&&c.res==0);
 CHECK(finish(&attached)==0);
 lq(&nested,0,0,-1,0,0,0,0x6500);
 CHECK(sc(N_ENTER,nested.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&nested,&c,1)==0&&c.ud==0x6500&&c.res==0);
 CHECK(finish(&nested)==0);
 return 0;
}
static int
sqpoll_attach_reverse_close_shared(void)
{
 struct ring source,attached;struct cqe c;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 lq(&attached,0,0,-1,0,0,0,0x6600);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6600&&c.res==0);
 CHECK(finish(&attached)==0);
 lq(&source,0,0,-1,0,0,0,0x6601);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x6601&&c.res==0);
 CHECK(finish(&source)==0);
 return 0;
}
/* Each member of a shared poller owns a separate CQ and overflow backlog. */
static int
sqpoll_attach_wait_counter(volatile u32 *counter, u32 at_least)
{
 struct ltime end,now;
 CHECK(CALL(LCLOCK,LMONO,&end,0)==0);end.sec+=4;
 while(__atomic_load_n(counter,__ATOMIC_ACQUIRE)<at_least){
  CHECK(CALL(LCLOCK,LMONO,&now,0)==0);
  CHECK(now.sec<end.sec || (now.sec==end.sec&&now.nsec<=end.nsec));
  lpause(1000000);
 }
 return 0;
}
static int
sqpoll_attach_wait_flag(volatile u32 *flags,u32 mask)
{
 struct ltime end,now;
 CHECK(CALL(LCLOCK,LMONO,&end,0)==0);end.sec+=4;
 while((__atomic_load_n(flags,__ATOMIC_ACQUIRE)&mask)==0){
  CHECK(CALL(LCLOCK,LMONO,&now,0)==0);
  CHECK(now.sec<end.sec || (now.sec==end.sec&&now.nsec<=end.nsec));
  lpause(1000000);
 }
 return 0;
}
static int
sqpoll_attach_queue_nops(struct ring *r,u64 base,u32 count)
{
 for(u32 sent=0;sent<count;){
  u32 batch=count-sent>8?8:count-sent;
  for(u32 i=0;i<batch;i++)lq(r,0,0,-1,0,0,0,base+sent+i);
  CHECK(sc(N_ENTER,r->fd,batch,0,SQ_WAKEUP,0,0)==batch);
  sent+=batch;
  CHECK(sqpoll_attach_wait_counter(r->sh,r->si)==0);
 }
 return 0;
}
static int
sqpoll_attach_drain_nops(struct ring *r,u64 base,u32 count)
{
 struct cqe c;u64 seen[2]={0,0};
 CHECK(count<=128);
 for(u32 i=0;i<count;i++){
  CHECK(lget(r,&c,1)==0&&c.res==0&&c.ud>=base&&c.ud<base+count);
  u32 bit=(u32)(c.ud-base);
  CHECK((seen[bit>>6]&(1ULL<<(bit&63)))==0);
  seen[bit>>6]|=1ULL<<(bit&63);
 }
 for(u32 i=0;i<count;i++)CHECK((seen[i>>6]&(1ULL<<(i&63)))!=0);
 CHECK((*r->sf&(1U<<1))==0);
 return 0;
}
static int
sqpoll_attach_cq_overflow_shared(void)
{
 struct ring source,attached,closing;struct cqe c;volatile u32 *so,*ao,*co;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 u32 count=source.p.cq+8;
 CHECK(source.p.cq==attached.p.cq&&count<=128);
 so=(volatile u32 *)(source.mem+source.p.co.field4);
 ao=(volatile u32 *)(attached.mem+attached.p.co.field4);
 CHECK(sqpoll_attach_queue_nops(&source,0x7000,count)==0);
 CHECK(sqpoll_attach_wait_flag(source.sf,1U<<1)==0);
 CHECK(__atomic_load_n(so,__ATOMIC_ACQUIRE)==0);
 CHECK(__atomic_load_n(source.ct,__ATOMIC_ACQUIRE)-source.ci==source.p.cq);
 CHECK(__atomic_load_n(ao,__ATOMIC_ACQUIRE)==0);
 lq(&attached,0,0,-1,0,0,0,0x7200);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x7200&&c.res==0);
 CHECK(sqpoll_attach_drain_nops(&source,0x7000,count)==0);
 CHECK(sqpoll_attach_queue_nops(&attached,0x7100,count)==0);
 CHECK(sqpoll_attach_wait_flag(attached.sf,1U<<1)==0);
 CHECK(__atomic_load_n(ao,__ATOMIC_ACQUIRE)==0);
 CHECK(__atomic_load_n(attached.ct,__ATOMIC_ACQUIRE)-attached.ci==attached.p.cq);
 lq(&source,0,0,-1,0,0,0,0x7201);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7201&&c.res==0);
 CHECK(sqpoll_attach_drain_nops(&attached,0x7100,count)==0);
 CHECK(init_ex_wq(&closing,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 co=(volatile u32 *)(closing.mem+closing.p.co.field4);
 CHECK(sqpoll_attach_queue_nops(&closing,0x7300,count)==0);
 CHECK(sqpoll_attach_wait_flag(closing.sf,1U<<1)==0);
 CHECK(__atomic_load_n(co,__ATOMIC_ACQUIRE)==0);
 CHECK(finish(&closing)==0);
 lq(&source,0,0,-1,0,0,0,0x7202);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7202&&c.res==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}
static int
sqpoll_attach_blocked_read_progress_shared(void)
{
 struct ring source,attached;struct cqe c;int fds[2];char byte=0;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 CHECK(bpipe(fds,0)==0);
 lq(&source,22,0,fds[0],(u64)&byte,1,0,0x7500);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sqpoll_attach_wait_counter(source.sh,source.si)==0);
 CHECK(__atomic_load_n(source.ct,__ATOMIC_ACQUIRE)==source.ci);
 lq(&attached,0,0,-1,0,0,0,0x7501);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x7501&&c.res==0);
 CHECK(CALL(N_WRITE,fds[1],"R",1)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7500&&c.res==1&&byte=='R');
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}
/* Selected buffers must not make a shared SQPOLL thread block on READ. */
static int
sqpoll_attach_pbuf_read_shared(void)
{
 struct ring source,attached;struct pbuf_reg reg;struct pbuf_status st;
 union uring_buf_ring *br;struct sqe q;struct cqe c;struct viov iov;
 int fds[2];char first=0,second=0;long m;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=57;reg.flags=1;
 CHECK(sreg(&source,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,source.fd,0x80000000UL|((u64)57<<16));
 CHECK(m>=0);br=(union uring_buf_ring *)m;
 CHECK(bpipe(fds,0)==0);
 zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fds[0];q.off=~0UL;
 q.len=1;q.buf=57;q.ud=0x7600;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7600&&c.res==-NO_BUFS);
 br->bufs[0].addr=(u64)&first;br->bufs[0].len=1;br->bufs[0].bid=721;
 __atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 q.ud=0x7601;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sqpoll_attach_wait_counter(source.sh,source.si)==0);
 CHECK(__atomic_load_n(source.ct,__ATOMIC_ACQUIRE)==source.ci);
 lq(&attached,0,0,-1,0,0,0,0x7602);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x7602&&c.res==0);
 CHECK(CALL(N_WRITE,fds[1],"P",1)==1);
 CHECK(lget_any(&source,&c,1)==0&&c.ud==0x7601&&c.res==1&&
     (c.flags&1)==1&&(c.flags>>16)==721&&first=='P');
 zero(&st,sizeof(st));st.buf_group=57;
 CHECK(sreg(&source,26,&st,1)==0&&st.head==1);
 br->bufs[1].addr=(u64)&second;br->bufs[1].len=1;br->bufs[1].bid=722;
 __atomic_store_n(&br->h.tail,2,__ATOMIC_RELEASE);
 q.fd=-1;q.ud=0x7603;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7603&&c.res==-9);
 zero(&st,sizeof(st));st.buf_group=57;
 CHECK(sreg(&source,26,&st,1)==0&&st.head==1);
 iov.base=(void *)1;iov.len=1;
 q.op=1;q.fd=fds[0];q.addr=(u64)&iov;q.len=1;q.ud=0x7604;
 queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,fds[1],"Q",1)==1);
 CHECK(lget_any(&source,&c,1)==0&&c.ud==0x7604&&c.res==1&&
     (c.flags&1)==1&&(c.flags>>16)==722&&second=='Q');
 zero(&st,sizeof(st));st.buf_group=57;
 CHECK(sreg(&source,26,&st,1)==0&&st.head==2);
 zero(&reg,sizeof(reg));reg.bgid=57;CHECK(sreg(&source,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,(void *)m,4096,0)==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}
/* Explicit IOSQE_ASYNC uses the same selected-buffer worker completion. */
static int
async_pbuf_worker_shared(void)
{
 struct ring r;struct pbuf_reg reg;struct pbuf_status st;
 union uring_buf_ring *br;struct sqe q;struct cqe c;int fds[2];
 char byte=0;long m;
 CHECK(init(&r,0,8)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=58;reg.flags=1;
 CHECK(sreg(&r,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,0x80000000UL|((u64)58<<16));
 CHECK(m>=0);br=(union uring_buf_ring *)m;
 br->bufs[0].addr=(u64)&byte;br->bufs[0].len=1;br->bufs[0].bid=723;
 __atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 CHECK(bpipe(fds,0)==0);
 zero(&q,sizeof(q));q.op=22;q.flags=16|32;q.fd=fds[0];q.off=~0UL;
 q.len=1;q.buf=58;q.ud=0x7610;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0);
 lq(&r,0,0,-1,0,0,0,0x7611);
 CHECK(lsubmit(&r,1)==0);
 CHECK(lget(&r,&c,1)==0&&c.ud==0x7611&&c.res==0);
 CHECK(CALL(N_WRITE,fds[1],"A",1)==1);
 CHECK(lget_any(&r,&c,1)==0&&c.ud==0x7610&&c.res==1&&
     (c.flags&1)==1&&(c.flags>>16)==723&&byte=='A');
 zero(&st,sizeof(st));st.buf_group=58;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==1);
 br->bufs[1].addr=(u64)&byte;br->bufs[1].len=1;br->bufs[1].bid=724;
 __atomic_store_n(&br->h.tail,2,__ATOMIC_RELEASE);
 q.fd=-1;q.ud=0x7612;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&lget(&r,&c,1)==0&&c.ud==0x7612&&c.res==-9);
 zero(&st,sizeof(st));st.buf_group=58;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==1);
 byte=0;q.fd=fds[0];q.ud=0x7613;queue(&r,q,0);
 CHECK(lsubmit(&r,1)==0&&CALL(N_WRITE,fds[1],"B",1)==1);
 CHECK(lget_any(&r,&c,1)==0&&c.ud==0x7613&&c.res==1&&
     (c.flags&1)==1&&(c.flags>>16)==724&&byte=='B');
 zero(&st,sizeof(st));st.buf_group=58;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==2);
 zero(&reg,sizeof(reg));reg.bgid=58;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,(void *)m,4096,0)==0);
 return finish(&r);
}
/* Incremental PBUF_RING accounting must survive the SQPOLL worker path. */
static int
sqpoll_pbuf_incremental_shared(void)
{
 struct ring source,attached;struct pbuf_reg reg;struct pbuf_status st;
 union uring_buf_ring *br;struct sqe q;struct cqe c;int fds[2];
 char data[4]={0};long m;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=59;
 reg.flags=3;reg.min_left=2;CHECK(sreg(&source,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,source.fd,0x80000000UL|((u64)59<<16));
 CHECK(m>=0);br=(union uring_buf_ring *)m;
 br->bufs[0].addr=(u64)data;br->bufs[0].len=4;br->bufs[0].bid=725;
 __atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 CHECK(bpipe(fds,0)==0);
 zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fds[0];q.off=~0UL;
 q.len=2;q.buf=59;q.ud=0x7620;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sqpoll_attach_wait_counter(source.sh,source.si)==0);
 lq(&attached,0,0,-1,0,0,0,0x7621);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x7621&&c.res==0);
 CHECK(CALL(N_WRITE,fds[1],"AB",2)==2);
 CHECK(lget_any(&source,&c,1)==0&&c.ud==0x7620&&c.res==2&&
     (c.flags&17)==17&&(c.flags>>16)==725&&
     data[0]=='A'&&data[1]=='B'&&
     br->bufs[0].addr==(u64)(data+2)&&br->bufs[0].len==2);
 zero(&st,sizeof(st));st.buf_group=59;
 CHECK(sreg(&source,26,&st,1)==0&&st.head==0);
 q.len=1;q.ud=0x7622;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,fds[1],"C",1)==1);
 CHECK(lget_any(&source,&c,1)==0&&c.ud==0x7622&&c.res==1&&
     (c.flags&1)==1&&(c.flags&16)==0&&(c.flags>>16)==725&&
     data[2]=='C'&&br->bufs[0].len==0);
 zero(&st,sizeof(st));st.buf_group=59;
 CHECK(sreg(&source,26,&st,1)==0&&st.head==1);
 q.ud=0x7623;queue(&source,q,0);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x7623&&c.res==-NO_BUFS);
 zero(&reg,sizeof(reg));reg.bgid=59;CHECK(sreg(&source,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,(void *)m,4096,0)==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}

/* A canceled selected-buffer worker returns its buffer for a later read. */
static int
sqpoll_pbuf_cancel_shared(void)
{
 struct ring r;struct pbuf_reg reg;struct pbuf_status st;
 union uring_buf_ring *br;struct sqe q;struct cqe c[2];int fds[2];
 char byte=0;long m;
 CHECK(init(&r,SSQPOLL,8)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=60;reg.flags=1;
 CHECK(sreg(&r,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,0x80000000UL|((u64)60<<16));
 CHECK(m>=0);br=(union uring_buf_ring *)m;
 br->bufs[0].addr=(u64)&byte;br->bufs[0].len=1;br->bufs[0].bid=726;
 __atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 CHECK(bpipe(fds,0)==0);
 zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fds[0];q.off=~0UL;
 q.len=1;q.buf=60;q.ud=0x7630;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sqpoll_attach_wait_counter(r.sh,r.si)==0);
 lq(&r,14,0,-1,0x7630,0,0,0x7631);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget_any(&r,c,2)==0);
 if(lresult(c,2,0x7630,-CANCELED)!=0||
     lresult(c,2,0x7631,0)!=0||c[0].flags!=0||c[1].flags!=0){
  put("PBUF_CANCEL_DIAG ");putnum(c[0].ud);put(" ");putnum(c[0].res);
  put(" ");putnum(c[0].flags);put(" ");putnum(c[1].ud);
  put(" ");putnum(c[1].res);put(" ");putnum(c[1].flags);put("\n");
  return __LINE__;
 }
 zero(&st,sizeof(st));st.buf_group=60;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==0);
 q.ud=0x7632;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,fds[1],"R",1)==1);
 CHECK(lget_any(&r,c,1)==0&&c[0].ud==0x7632&&c[0].res==1&&
     (c[0].flags&1)==1&&(c[0].flags>>16)==726&&byte=='R');
 zero(&st,sizeof(st));st.buf_group=60;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==1);
 zero(&reg,sizeof(reg));reg.bgid=60;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,(void *)m,4096,0)==0);
 return finish(&r);
}
/* Cancellation after incremental progress must retain the remaining range. */
static int
sqpoll_pbuf_incremental_cancel_shared(void)
{
 struct ring r;struct pbuf_reg reg;struct pbuf_status st;
 union uring_buf_ring *br;struct sqe q;struct cqe c[2];int fds[2];
 char data[4]={0};long m;
 CHECK(init(&r,SSQPOLL,8)==0);
 zero(&reg,sizeof(reg));reg.ring_entries=4;reg.bgid=61;
 reg.flags=3;reg.min_left=2;CHECK(sreg(&r,22,&reg,1)==0);
 m=sc(N_MMAP,0,4096,3,1,r.fd,0x80000000UL|((u64)61<<16));
 CHECK(m>=0);br=(union uring_buf_ring *)m;
 br->bufs[0].addr=(u64)data;br->bufs[0].len=4;br->bufs[0].bid=727;
 __atomic_store_n(&br->h.tail,1,__ATOMIC_RELEASE);
 CHECK(bpipe(fds,0)==0);
 zero(&q,sizeof(q));q.op=22;q.flags=32;q.fd=fds[0];q.off=~0UL;
 q.len=2;q.buf=61;q.ud=0x7640;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,fds[1],"AB",2)==2);
 CHECK(lget_any(&r,c,1)==0&&c[0].ud==0x7640&&c[0].res==2&&
     (c[0].flags&17)==17&&(c[0].flags>>16)==727&&
     data[0]=='A'&&data[1]=='B'&&br->bufs[0].addr==(u64)(data+2)&&
     br->bufs[0].len==2);
 zero(&st,sizeof(st));st.buf_group=61;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==0);
 q.len=1;q.ud=0x7641;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sqpoll_attach_wait_counter(r.sh,r.si)==0);
 lq(&r,14,0,-1,0x7641,0,0,0x7642);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget_any(&r,c,2)==0&&lresult(c,2,0x7641,-CANCELED)==0&&
     lresult(c,2,0x7642,0)==0&&c[0].flags==0&&c[1].flags==0);
 zero(&st,sizeof(st));st.buf_group=61;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==0&&
     br->bufs[0].addr==(u64)(data+2)&&br->bufs[0].len==2);
 q.len=2;q.ud=0x7643;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,fds[1],"CD",2)==2);
 CHECK(lget_any(&r,c,1)==0&&c[0].ud==0x7643&&c[0].res==2&&
     (c[0].flags&1)==1&&(c[0].flags&16)==0&&
     (c[0].flags>>16)==727&&data[2]=='C'&&data[3]=='D'&&
     br->bufs[0].len==0);
 zero(&st,sizeof(st));st.buf_group=61;
 CHECK(sreg(&r,26,&st,1)==0&&st.head==1);
 q.len=1;q.ud=0x7644;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&r,c,1)==0&&c[0].ud==0x7644&&c[0].res==-NO_BUFS);
 zero(&reg,sizeof(reg));reg.bgid=61;CHECK(sreg(&r,23,&reg,1)==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(CALL(N_MUNMAP,(void *)m,4096,0)==0);
 return finish(&r);
}
struct sqatt_close_barrier { volatile u32 go,ready; int fd[2]; };
struct sqatt_close_arg { struct sqatt_close_barrier *barrier; int which; };
static int
sqpoll_attach_close_worker(void *arg)
{
 struct sqatt_close_arg *a=arg;
 __atomic_add_fetch(&a->barrier->ready,1,__ATOMIC_RELEASE);
 while(__atomic_load_n(&a->barrier->go,__ATOMIC_ACQUIRE)==0)
  CALL(N_YIELD,0,0,0);
 return CALL(N_CLOSE,a->barrier->fd[a->which],0,0)==0?0:1;
}
static int
sqpoll_attach_concurrent_close_shared(void)
{
 for(int turn=0;turn<2;turn++){
  struct ring source,attached,fresh;struct cqe c;int pipefd[2],status;
  char *stacks[2];long child[2];
  struct sqatt_close_barrier barrier={0};
  struct sqatt_close_arg args[2]={{&barrier,0},{&barrier,1}};
  CHECK(init(&source,SSQPOLL,8)==0);
  CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
  CHECK(bpipe(pipefd,0)==0);
  lq(&source,6,0,pipefd[0],0,0,1,0x7600+turn);
  lq(&attached,6,0,pipefd[0],0,0,1,0x7700+turn);
  CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
  CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
  CHECK(sqpoll_attach_wait_counter(source.sh,source.si)==0);
  CHECK(sqpoll_attach_wait_counter(attached.sh,attached.si)==0);
  CHECK(__atomic_load_n(source.ct,__ATOMIC_ACQUIRE)==source.ci);
  CHECK(__atomic_load_n(attached.ct,__ATOMIC_ACQUIRE)==attached.ci);
  if(turn&1){
   lq(&source,14,0,-1,0x7600+turn,0,0,0x7800+turn);
   CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
  }
  barrier.fd[0]=source.fd;barrier.fd[1]=attached.fd;
  for(int i=0;i<2;i++){
   stacks[i]=(char *)sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
   CHECK((long)stacks[i]>=0);
   child[i]=bspawn_files(sqpoll_attach_close_worker,&args[i],stacks[i]+65536);
   CHECK(child[i]>0);
  }
  CHECK(sqpoll_attach_wait_counter(&barrier.ready,2)==0);
  __atomic_store_n(&barrier.go,1,__ATOMIC_RELEASE);
  for(int i=0;i<2;i++)CHECK(CALL(N_WAIT,child[i],&status,0)==child[i]&&status==0);
  CHECK(sc(N_ENTER,source.fd,0,0,0,0,0)==-9);
  CHECK(sc(N_ENTER,attached.fd,0,0,0,0,0)==-9);
  for(int i=0;i<2;i++)CHECK(CALL(N_MUNMAP,stacks[i],65536,0)==0);
  CHECK(CALL(N_MUNMAP,source.mem,source.rlen,0)==0);
  CHECK(CALL(N_MUNMAP,source.sqes,source.slen,0)==0);
  CHECK(CALL(N_MUNMAP,attached.mem,attached.rlen,0)==0);
  CHECK(CALL(N_MUNMAP,attached.sqes,attached.slen,0)==0);
  CHECK(CALL(N_CLOSE,pipefd[0],0,0)==0&&CALL(N_CLOSE,pipefd[1],0,0)==0);
  CHECK(init(&fresh,SSQPOLL,8)==0);
  lq(&fresh,0,0,-1,0,0,0,0x7900+turn);
  CHECK(sc(N_ENTER,fresh.fd,1,0,SQ_WAKEUP,0,0)==1);
  CHECK(lget(&fresh,&c,1)==0&&c.ud==0x7900+(u32)turn&&c.res==0);
  CHECK(finish(&fresh)==0);
 }
 return 0;
}
static int
sqpoll_attach_invalid_shared(void)
{
 struct params p;struct ring source,ordinary;int fds[2];long stale;
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=9999;
 CHECK(CALL(N_SETUP,8,&p,0)==-6);
 CHECK(bpipe(fds,0)==0);
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=fds[0];
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(init(&ordinary,0,8)==0);
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=ordinary.fd;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(finish(&ordinary)==0);
 CHECK(init(&source,SSQPOLL,8)==0);stale=source.fd;
 CHECK(finish(&source)==0);
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=stale;
 CHECK(CALL(N_SETUP,8,&p,0)==-6);
 return 0;
}
#ifdef LINUX_ABI
#define SQ_OWNER_DEAD 130
#else
#define SQ_OWNER_DEAD EOWNERDEAD
#endif
static int
sqpoll_attach_waitid_close_shared(void)
{
#ifdef LINUX_ABI
 struct ring source,attached;struct sqe q;u32 info[32];long pid;int status;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){lpause(200000000);CALL(N_EXIT,43,0,0);}
 zero(info,sizeof(info));zero(&q,sizeof(q));q.op=50;q.fd=(int)pid;
 q.len=1;q.fd2=4;q.addr=(u64)info;q.ud=0x6b00;
 queue(&attached,q,0);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 for(int i=0;i<2000&&__atomic_load_n(attached.sh,__ATOMIC_ACQUIRE)==0;i++)
  lpause(1000000);
 CHECK(__atomic_load_n(attached.sh,__ATOMIC_ACQUIRE)==1);
 CHECK(finish(&attached)==0);
 CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid&&
     ((status>>8)&255)==43);
 CHECK(finish(&source)==0);
#endif
 return 0;
}
static int
sqpoll_attach_crossabi_helper(const char *arg)
{
 struct params p;long fd=0,ret;
 while(*arg){CHECK(*arg>='0'&&*arg<='9');fd=fd*10+*arg++-'0';}
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=(u32)fd;
 ret=CALL(N_SETUP,8,&p,0);
 if(ret>=0)CALL(N_CLOSE,ret,0,0);
 CHECK(ret==-22);
 return 0;
}
static int
sqpoll_attach_crossabi_shared(void)
{
 struct ring source;const char *self=setup_self;char other[256],number[24],digits[24];
 u64 n=0,prefix;int d=0,status;long fd,pid;
 while(self[n])n++;
#ifdef LINUX_ABI
 CHECK(n>=5&&equal(self+n-5,"linux"));prefix=n-5;
 const char *other_suffix="native";
#else
 CHECK(n>=6&&equal(self+n-6,"native"));prefix=n-6;
 const char *other_suffix="linux";
#endif
 CHECK(prefix+7<sizeof(other));zero(other,sizeof(other));
 for(u64 i=0;i<prefix;i++)other[i]=self[i];
 for(u64 i=0;other_suffix[i];i++)other[prefix+i]=other_suffix[i];
 CHECK(init(&source,SSQPOLL,8)==0);
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){
  if(CALL(N_FCNTL,source.fd,2,0)!=0)CALL(N_EXIT,91,0,0);
  fd=source.fd;do{digits[d++]='0'+fd%10;fd/=10;}while(fd);
  for(int i=0;i<d;i++)number[i]=digits[d-1-i];number[d]=0;
  char *av[]={other,(char *)"sqpoll_attach_crossabi_helper",number,0};
  char *ev[]={0};
  sc(N_EXEC,(long)other,(long)av,(long)ev,0,0,0);
  CALL(N_EXIT,92,0,0);
 }
 CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid&&status==0);
 CHECK(finish(&source)==0);
 return 0;
}
static int
sqpoll_attach_worker_controls_shared(void)
{
 struct ring source,attached;u32 limits[2],values[2],query[2];struct cqe c;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 limits[0]=limits[1]=0;
 CHECK(sreg(&source,19,limits,2)==0&&limits[0]>0&&limits[1]>0);
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==limits[0]&&query[1]==limits[1]);
 values[0]=1;values[1]=2;
 CHECK(sreg(&source,19,values,2)==0&&values[0]==limits[0]&&values[1]==limits[1]);
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==1&&query[1]==2);
 values[0]=2;values[1]=1;
 CHECK(sreg(&attached,19,values,2)==0&&values[0]==1&&values[1]==2);
 CHECK(sreg(&attached,19,values,1)==-22);
 values[0]=0x80000000U;values[1]=1;
 CHECK(sreg(&attached,19,values,2)==-22);
 /* A blocked source request consumes the shared unbound worker slot. */
 int first[2],second[2];char a=0,b=0;
 CHECK(bpipe(first,0)==0&&bpipe(second,0)==0);
 values[0]=0;values[1]=1;
 CHECK(sreg(&attached,19,values,2)==0&&values[1]==1);
 lq(&source,22,16,first[0],(u64)&a,1,0,0x6a01);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 lpause(50000000);
 lq(&attached,22,16,second[0],(u64)&b,1,0,0x6a02);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(CALL(N_WRITE,second[1],"B",1)==1);
 lpause(50000000);
 CHECK(CALL(N_WRITE,first[1],"A",1)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x6a01&&c.res==1&&a=='A');
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6a02&&c.res==1&&b=='B');
 CHECK(CALL(N_CLOSE,first[0],0,0)==0&&CALL(N_CLOSE,first[1],0,0)==0);
 CHECK(CALL(N_CLOSE,second[0],0,0)==0&&CALL(N_CLOSE,second[1],0,0)==0);
 values[0]=0;values[1]=1;
 CHECK(sreg(&attached,19,values,2)==0&&values[1]==1);
 CHECK(finish(&source)==0);
 query[0]=query[1]=0;
 CHECK(sreg(&attached,19,query,2)==0&&query[0]==2&&query[1]==1);
 lq(&attached,0,0,-1,0,0,0,0x6a00);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6a00&&c.res==0);
 CHECK(finish(&attached)==0);
 return 0;
}
#ifndef LINUX_ABI
static int
native_squeue_worker_pinned(u32 cpu)
{
 struct kinfo_proc *procs;cpuset_t mask;size_t size,count;int found=0;
 int mib[3]={CTL_KERN,KERN_PROC,KERN_PROC_PROC|KERN_PROC_INC_THREAD};
 if(sysctl(mib,3,0,&size,0,0)!=0||size==0)return 1;
 procs=malloc(size*2);if(procs==0)return 2;size*=2;
 if(sysctl(mib,3,procs,&size,0,0)!=0){free(procs);return 3;}
 count=size/sizeof(*procs);
 for(size_t i=0;i<count;i++){
  if(strcmp(procs[i].ki_comm,"squeue")!=0&&
     strcmp(procs[i].ki_tdname,"squeue")!=0)continue;
  CPU_ZERO(&mask);
  if(cpuset_getaffinity(CPU_LEVEL_WHICH,CPU_WHICH_TID,
      procs[i].ki_tid,sizeof(mask),&mask)==0&&
      CPU_COUNT(&mask)==1&&CPU_ISSET(cpu,&mask)){found=1;break;}
 }
 free(procs);return found?0:4;
}
#endif
static int
sqpoll_attach_worker_affinity_shared(void)
{
 struct ring source,attached;struct cqe c;u64 mask[2];int fds[2];char byte=0;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 zero(mask,sizeof(mask));CHECK(sreg(&source,17,0,8)==-22);
 CHECK(sreg(&attached,17,mask,0)==-22);
 CHECK(sreg(&attached,17,(void *)1,8)==-14);
 CHECK(sreg(&source,18,(void *)1,0)==-22);
 mask[0]=1UL<<1;CHECK(sreg(&attached,17,mask,8)==0);
 for(u32 mode=0;mode<2;mode++){
  struct ring *ring=mode?&source:&attached;
  CHECK(bpipe(fds,0)==0);byte=0;
  lq(ring,22,16,fds[0],(u64)&byte,1,0,0x6d00+mode);
  CHECK(sc(N_ENTER,ring->fd,1,0,SQ_WAKEUP,0,0)==1);
  lpause(100000000);
#ifndef LINUX_ABI
  CHECK(native_squeue_worker_pinned(1)==0);
#endif
  CHECK(CALL(N_WRITE,fds[1],"A",1)==1);
  CHECK(lget(ring,&c,1)==0&&c.ud==0x6d00+mode&&c.res==1&&byte=='A');
  CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 }
 CHECK(sreg(&source,18,0,0)==0);
 CHECK(finish(&source)==0);
 CHECK(sreg(&attached,17,mask,8)==0);
 CHECK(bpipe(fds,0)==0);byte=0;
 lq(&attached,22,16,fds[0],(u64)&byte,1,0,0x6d02);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 lpause(100000000);
#ifndef LINUX_ABI
 CHECK(native_squeue_worker_pinned(1)==0);
#endif
 CHECK(CALL(N_WRITE,fds[1],"B",1)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6d02&&c.res==1&&byte=='B');
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0&&CALL(N_CLOSE,fds[1],0,0)==0);
 CHECK(sreg(&attached,18,0,0)==0&&sreg(&attached,18,0,0)==0);
 return finish(&attached);
}

static int
sqpoll_attach_owner_exit_shared(void)
{
 struct ring source,attached;int fds[2],status;long owner,consumer;char result=0xff;
 CHECK(bpipe(fds,0)==0);
 owner=fork_child();CHECK(owner>=0);
 if(owner==0){
  CALL(N_CLOSE,fds[0],0,0);
  if(init(&source,SSQPOLL,8)!=0||
     init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)!=0){
   result=1;CALL(N_WRITE,fds[1],&result,1);CALL(N_EXIT,0,0,0);
  }
  consumer=fork_child();
  if(consumer<0){result=2;CALL(N_WRITE,fds[1],&result,1);CALL(N_EXIT,0,0,0);}
  if(consumer!=0)CALL(N_EXIT,0,0,0);
  lpause(200000000);
  result=(sc(N_ENTER,source.fd,0,0,SQ_WAKEUP,0,0)==-SQ_OWNER_DEAD&&
      sc(N_ENTER,attached.fd,0,0,SQ_WAKEUP,0,0)==-SQ_OWNER_DEAD)?0:3;
  CALL(N_WRITE,fds[1],&result,1);
  finish(&attached);finish(&source);CALL(N_EXIT,0,0,0);
 }
 CALL(N_CLOSE,fds[1],0,0);
 CHECK(sc(N_WAIT,owner,(long)&status,0,0,0,0)==owner&&status==0);
 CHECK(CALL(N_READ,fds[0],&result,1)==1&&result==0);
 CHECK(CALL(N_CLOSE,fds[0],0,0)==0);
 return 0;
}
static int
sqpoll_attach_failed_exec_shared(void)
{
 struct ring source,attached;struct cqe c;
 char *av[]={(char *)"/no-such-sqpoll-attach-program",0};char *ev[]={0};
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 CHECK(sc(N_EXEC,(long)av[0],(long)av,(long)ev,0,0,0)==-2);
 lq(&source,0,0,-1,0,0,0,0x6900);
 lq(&attached,0,0,-1,0,0,0,0x6901);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x6900&&c.res==0);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6901&&c.res==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}
static int
sqpoll_attach_fork_shared(void)
{
 struct ring source,child;struct cqe c;long pid;int status;
 CHECK(init(&source,SSQPOLL,8)==0);
 pid=fork_child();CHECK(pid>=0);
 if(pid==0){
  if(init_ex_wq(&child,SSQPOLL|SATTACHWQ,8,0,source.fd)!=0)
   CALL(N_EXIT,1,0,0);
  lq(&child,0,0,-1,0,0,0,0x6800);
  if(sc(N_ENTER,child.fd,1,0,SQ_WAKEUP,0,0)!=1||
     lget(&child,&c,1)!=0||c.ud!=0x6800||c.res!=0||
     finish(&child)!=0)CALL(N_EXIT,2,0,0);
  CALL(N_EXIT,0,0,0);
 }
 CHECK(sc(N_WAIT,pid,(long)&status,0,0,0,0)==pid&&status==0);
 lq(&source,0,0,-1,0,0,0,0x6801);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x6801&&c.res==0);
 CHECK(finish(&source)==0);
 return 0;
}
static int
sqpoll_attach_idle_shared(void)
{
 struct ring source,attached;struct cqe c;int awake=0;
 CHECK(init(&source,SSQPOLL,8)==0);
 CHECK(init_ex_wq(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd)==0);
 for(int i=0;i<400;i++){
  if((__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1)!=0&&
     (__atomic_load_n(attached.sf,__ATOMIC_ACQUIRE)&1)!=0){awake=1;break;}
  lpause(10000000);
 }
 CHECK(awake==1);
 for(u32 i=0;i<8;i++)lq(&attached,0,0,-1,0,0,0,0x6700+i);
 CHECK(sc(N_ENTER,attached.fd,8,0,SQ_WAKEUP|SQ_WAIT,0,0)==8);
 for(u32 i=0;i<8;i++)CHECK(lget(&attached,&c,1)==0&&c.ud==0x6700+i&&c.res==0);
 CHECK(finish(&attached)==0&&finish(&source)==0);
 return 0;
}

static int
sqpoll_attach_group_idle_shared(void)
{
 struct ring source,attached;struct params p;struct cqe c;int asleep;
 CHECK(init_ex_wq_idle(&source,SSQPOLL,8,0,0,200)==0);
 zero(&p,sizeof(p));p.flags=SSQPOLL|SATTACHWQ;p.wq=9999;p.idle=2500;
 CHECK(CALL(N_SETUP,8,&p,0)==-6);
 asleep=0;
 for(int i=0;i<150;i++){
  if(__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1){asleep=1;break;}
  lpause(10000000);
 }
 CHECK(asleep==1);
 CHECK(init_ex_wq_idle(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd,2500)==0);
 CHECK(sc(N_ENTER,attached.fd,0,0,SQ_WAKEUP,0,0)==0);
 for(int i=0;i<150;i++){
  if((__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1)==0&&
     (__atomic_load_n(attached.sf,__ATOMIC_ACQUIRE)&1)==0)break;
  lpause(10000000);
 }
 CHECK((__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1)==0);
 CHECK((__atomic_load_n(attached.sf,__ATOMIC_ACQUIRE)&1)==0);
 lpause(700000000);
 CHECK((__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1)==0);
 CHECK((__atomic_load_n(attached.sf,__ATOMIC_ACQUIRE)&1)==0);
 CHECK(finish(&attached)==0);
 asleep=0;
 for(int i=0;i<150;i++){
  if(__atomic_load_n(source.sf,__ATOMIC_ACQUIRE)&1){asleep=1;break;}
  lpause(10000000);
 }
 CHECK(asleep==1);
 lq(&source,0,0,-1,0,0,0,0x6b00);
 CHECK(sc(N_ENTER,source.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&source,&c,1)==0&&c.ud==0x6b00&&c.res==0);
 CHECK(finish(&source)==0);
 CHECK(init_ex_wq_idle(&source,SSQPOLL,8,0,0,2500)==0);
 CHECK(init_ex_wq_idle(&attached,SSQPOLL|SATTACHWQ,8,0,source.fd,200)==0);
 CHECK(finish(&source)==0);
 asleep=0;
 for(int i=0;i<150;i++){
  if(__atomic_load_n(attached.sf,__ATOMIC_ACQUIRE)&1){asleep=1;break;}
  lpause(10000000);
 }
 CHECK(asleep==1);
 lq(&attached,0,0,-1,0,0,0,0x6b01);
 CHECK(sc(N_ENTER,attached.fd,1,0,SQ_WAKEUP,0,0)==1);
 CHECK(lget(&attached,&c,1)==0&&c.ud==0x6b01&&c.res==0);
 return finish(&attached);
}

static int
sqpoll_attach_nommap_shared(void)
{
 struct ring source,attached;struct params p;struct sqe q;struct cqe c;
 struct nommap_ring_update up;long mem,sqes,badmem,badsqes,fd;u32 flags;
 for(u32 mode=0;mode<2;mode++){
  CHECK(init(&source,SSQPOLL,8)==0);
  badmem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
  badsqes=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
  CHECK(badmem>=0&&badsqes>=0);
  zero(&p,sizeof(p));
  p.flags=SSQPOLL|SATTACHWQ|SNOMMAP|(mode?(1U<<15):0);
  p.so.addr=badsqes;p.co.addr=badmem;p.wq=9999;
  CHECK(CALL(N_SETUP,4,&p,0)==-6);
  mem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
  sqes=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
  CHECK(mem>=0&&sqes>=0);
  zero(&p,sizeof(p));
  p.flags=SSQPOLL|SATTACHWQ|SNOMMAP|(mode?(1U<<15):0);
  p.so.addr=sqes;p.co.addr=mem;p.wq=source.fd;
  fd=CALL(N_SETUP,4,&p,0);CHECK(fd>=0);
  zero(&attached,sizeof(attached));attached.p=p;attached.fd=fd;
  attached.mem=(char *)mem;attached.sqes=(struct sqe *)sqes;
  attached.rlen=65536;attached.slen=65536;
  attached.sh=(u32 *)(attached.mem+p.so.head);
  attached.st=(u32 *)(attached.mem+p.so.tail);
  attached.sf=(u32 *)(attached.mem+p.so.field4);
  attached.ch=(u32 *)(attached.mem+p.co.head);
  attached.ct=(u32 *)(attached.mem+p.co.tail);
  attached.cqes=(struct cqe *)(attached.mem+p.co.field5);
  attached.array=(u32 *)(attached.mem+p.so.field6);
  flags=SQ_WAKEUP|(mode?(1U<<4):0);
  CHECK(finish(&source)==0);
  for(u32 i=0;i<8;i++){
   zero(&q,sizeof(q));q.ud=0x6c00+mode*16+i;queue(&attached,q,0);
   CHECK(sc(N_ENTER,attached.fd,0,0,flags,0,0)==0);
   for(u32 j=0;j<2000&&
       __atomic_load_n(attached.ct,__ATOMIC_ACQUIRE)<=attached.ci;j++)
    lpause(1000000);
   CHECK(__atomic_load_n(attached.ct,__ATOMIC_ACQUIRE)>attached.ci);
   CHECK(lget(&attached,&c,1)==0&&c.ud==q.ud&&c.res==0);
  }
  if(mode){
   /* The slot number can also name an unrelated ambient descriptor. */
   CHECK(sc(N_ENTER,attached.fd,0,0,SQ_WAKEUP,0,0)<0);
   zero(&up,sizeof(up));up.offset=attached.fd;
   CHECK(sc(N_REGISTER,attached.fd,21U|(1U<<31),(long)&up,1,0,0)==1);
   CHECK(sc(N_ENTER,attached.fd,0,0,flags,0,0)==-9);
   CHECK(CALL(N_MUNMAP,attached.mem,attached.rlen,0)==0);
   CHECK(CALL(N_MUNMAP,attached.sqes,attached.slen,0)==0);
  }else CHECK(finish(&attached)==0);
  CHECK(CALL(N_MUNMAP,badmem,65536,0)==0);
  CHECK(CALL(N_MUNMAP,badsqes,65536,0)==0);
 }
 return 0;
}

static int
sqpoll_shared(void)
{
 struct params p;struct ring r;struct sqe q;struct cqe c;
 zero(&p,sizeof(p));p.flags=SSQ_AFF;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(init(&r,SSQPOLL,8)==0);
 for(u32 i=0;i<16;i++){
  zero(&q,sizeof(q));q.ud=0x5300+i;queue(&r,q,0);
  CHECK(sc(N_ENTER,r.fd,1,0,SQ_WAKEUP,0,0)==1);
  CHECK(lget(&r,&c,1)==0&&c.ud==0x5300+i&&c.res==0);
  CHECK(__atomic_load_n(r.sh,__ATOMIC_ACQUIRE)==i+1);
 }
 for(u32 i=0;i<8;i++){
  zero(&q,sizeof(q));q.ud=0x5400+i;queue(&r,q,0);
 }
 CHECK(sc(N_ENTER,r.fd,8,0,SQ_WAKEUP|SQ_WAIT,0,0)==8);
 for(u32 i=0;i<8;i++)CHECK(lget(&r,&c,1)==0&&c.ud==0x5400+i&&c.res==0);
 CHECK(__atomic_load_n(r.sh,__ATOMIC_ACQUIRE)==24);
 CHECK(sc(N_ENTER,r.fd,0,0,SQ_WAKEUP,0,0)==0);
 CHECK(finish(&r)==0);return 0;
}

#ifndef LINUX_ABI
static int
native_sqpoll_pinned(u32 cpu)
{
 struct kinfo_proc *procs;
 cpuset_t mask;
 size_t size, count;
 int mib[4]={CTL_KERN,KERN_PROC,KERN_PROC_PID|KERN_PROC_INC_THREAD,getpid()};
 int found=0, result=1;

 if(sysctl(mib,4,0,&size,0,0)!=0||size==0)return 1;
 procs=malloc(size*2);
 if(procs==0)return 2;
 size*=2;
 if(sysctl(mib,4,procs,&size,0,0)!=0){free(procs);return 3;}
 count=size/sizeof(*procs);
 for(size_t i=0;i<count;i++){
  if(strcmp(procs[i].ki_tdname,"squeue-sqpoll")!=0)continue;
  found++;
  CPU_ZERO(&mask);
  if(cpuset_getaffinity(CPU_LEVEL_WHICH,CPU_WHICH_TID,
      procs[i].ki_tid,sizeof(mask),&mask)!=0)result=4;
  else if(CPU_COUNT(&mask)!=1||!CPU_ISSET(cpu,&mask))result=5;
  else result=0;
 }
 free(procs);
 return found==1?result:6;
}
static int
native_cpuset_restriction(void)
{
 cpuset_t allowed, one, current;
 cpusetid_t setid;
 struct params p;
 struct ring r;
 pid_t child;
 int first=-1, second=-1, status;

 CPU_ZERO(&allowed);
 if(cpuset_getaffinity(CPU_LEVEL_CPUSET,CPU_WHICH_PID,-1,
     sizeof(allowed),&allowed)!=0)return 1;
 for(int cpu=0;cpu<CPU_SETSIZE;cpu++){
  if(!CPU_ISSET(cpu,&allowed))continue;
  if(first<0)first=cpu;
  else{second=cpu;break;}
 }
 if(second<0)return 2;
 child=fork();
 if(child<0)return 3;
 if(child==0){
  if(cpuset(&setid)!=0)_exit(4);
  CPU_ZERO(&one);CPU_SET(first,&one);
  if(cpuset_setaffinity(CPU_LEVEL_CPUSET,CPU_WHICH_CPUSET,
      setid,sizeof(one),&one)!=0)_exit(5);
  CPU_ZERO(&current);
  if(cpuset_getaffinity(CPU_LEVEL_CPUSET,CPU_WHICH_PID,-1,
      sizeof(current),&current)!=0||CPU_COUNT(&current)!=1||
      !CPU_ISSET(first,&current))_exit(6);
  zero(&p,sizeof(p));p.flags=SSQPOLL|SSQ_AFF;p.cpu=second;
  if(CALL(N_SETUP,8,&p,0)!=-22)_exit(7);
  if(init_ex(&r,SSQPOLL|SSQ_AFF,8,first)!=0)_exit(8);
  if(native_sqpoll_pinned(first)!=0)_exit(9);
  if(finish(&r)!=0)_exit(10);
  _exit(0);
 }
 if(waitpid(child,&status,0)!=child)return 11;
 return WIFEXITED(status)?WEXITSTATUS(status):12;
}
#endif
static int
sqpoll_affinity_shared(void)
{
 struct params p;struct ring r;struct sqe q;struct cqe c;
 zero(&p,sizeof(p));p.flags=SSQPOLL|SSQ_AFF;p.cpu=~0U;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 zero(&p,sizeof(p));p.flags=SSQ_AFF;
 CHECK(CALL(N_SETUP,8,&p,0)==-22);
 CHECK(init_ex(&r,SSQPOLL|SSQ_AFF,8,0)==0);
#ifndef LINUX_ABI
 CHECK(native_sqpoll_pinned(0)==0);
#endif
 zero(&q,sizeof(q));q.ud=0xaff;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,0,0,SQ_WAKEUP,0,0)==0);
 CHECK(lget(&r,&c,1)==0&&c.ud==0xaff&&c.res==0);
 CHECK(finish(&r)==0);
#ifndef LINUX_ABI
 CHECK(native_cpuset_restriction()==0);
#endif
 return 0;
}

static int
sqpoll_taskrun_shared(void)
{
 static const u32 flags[]={SSQPOLL|SCOOP,
     SSQPOLL|SCOOP|STASKRUN,
     SSQPOLL|(1U<<12)|SDEFER,
     SSQPOLL|SCOOP|(1U<<12)|SDEFER};
 struct params p;struct ring r;struct sqe q;struct cqe c;
 for(u32 i=0;i<16;i++){
  zero(&p,sizeof(p));p.flags=flags[i%4];
  CHECK(CALL(N_SETUP,8,&p,0)==-22);
 }
 CHECK(init(&r,SSQPOLL,8)==0);
 zero(&q,sizeof(q));q.ud=0x7472;queue(&r,q,0);
 CHECK(sc(N_ENTER,r.fd,0,0,SQ_WAKEUP,0,0)==0);
 CHECK(lget(&r,&c,1)==0&&c.ud==0x7472&&c.res==0);
 CHECK(finish(&r)==0);return 0;
}

static int
sqpoll_layout_shared(void)
{
 struct ring r;struct params p;struct sqe q;struct nommap_ring_update up;
 long mem,sqes,fd;u32 flags;
 for(u32 mode=0;mode<3;mode++){
  if(mode==0){
   CHECK(init(&r,SSQPOLL|SONE,4)==0);
  }else{
   mem=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
   sqes=sc(N_MMAP,0,65536,3,ANON_FLAGS,-1,0);
   CHECK(mem>=0&&sqes>=0);
   zero(&p,sizeof(p));p.flags=SSQPOLL|SNOMMAP|(mode==2?(1U<<15):0);
   p.so.addr=sqes;p.co.addr=mem;
   fd=CALL(N_SETUP,4,&p,0);CHECK(fd>=0);
   zero(&r,sizeof(r));r.p=p;r.fd=fd;r.mem=(char *)mem;
   r.sqes=(struct sqe *)sqes;r.rlen=65536;r.slen=65536;
   r.sh=(u32 *)(r.mem+r.p.so.head);r.st=(u32 *)(r.mem+r.p.so.tail);
   r.ch=(u32 *)(r.mem+r.p.co.head);r.ct=(u32 *)(r.mem+r.p.co.tail);
   r.cqes=(struct cqe *)(r.mem+r.p.co.field5);
   r.array=(u32 *)(r.mem+r.p.so.field6);
  }
  flags=SQ_WAKEUP|(mode==2?(1U<<4):0);
  for(u32 i=0;i<8;i++){
   zero(&q,sizeof(q));q.ud=0x7300+mode*16+i;queue(&r,q,0);
   CHECK(sc(N_ENTER,r.fd,0,0,flags,0,0)==0);
   for(u32 j=0;j<2000&&__atomic_load_n(r.ct,__ATOMIC_ACQUIRE)<=r.ci;j++)
    lpause(1000000);
   CHECK(__atomic_load_n(r.ct,__ATOMIC_ACQUIRE)>r.ci);
   CHECK(reap(&r,q.ud,0)==0);
  }
  if(mode==2){
   zero(&up,sizeof(up));up.offset=r.fd;
   CHECK(sc(N_REGISTER,r.fd,21U|(1U<<31),(long)&up,1,0,0)==1);
   CHECK(sc(N_ENTER,r.fd,0,0,flags,0,0)==-9);
   CHECK(CALL(N_MUNMAP,r.mem,r.rlen,0)==0);
   CHECK(CALL(N_MUNMAP,r.sqes,r.slen,0)==0);
  }else CHECK(finish(&r)==0);
 }
 return 0;
}
static const struct { const char *name; int (*fn)(void); } cases[]={
 {"resize_requires_defer_shared",resize_requires_defer_shared},
 {"resize_invalid_shared",resize_invalid_shared},
 {"resize_empty_shared",resize_empty_shared},
 {"resize_pending_sq_shared",resize_pending_sq_shared},
 {"resize_pending_cq_shared",resize_pending_cq_shared},
 {"resize_fault_rollback_shared",resize_fault_rollback_shared},
 {"resize_mapping_lifetime_shared",resize_mapping_lifetime_shared},
 {"resize_mmap_race_shared",resize_mmap_race_shared},
 {"resize_clamp_shared",resize_clamp_shared},
 {"resize_layout_shared",resize_layout_shared},
 {"resize_worker_completion_shared",resize_worker_completion_shared},
 {"nommap_shared",nommap_shared},
 {"nommap_fdonly_shared",nommap_fdonly_shared},
 {"param_region_mmap_shared",param_region_mmap_shared},
 {"param_region_invalid_shared",param_region_invalid_shared},
 {"param_region_wait_shared",param_region_wait_shared},
 {"param_region_user_shared",param_region_user_shared},
 {"min_wait_shared",min_wait_shared},
 {"eventfd_async_shared",eventfd_async_shared},
 {"register_clock_shared",register_clock_shared},
 {"fallocate_options_shared",fallocate_options_shared},
 {"fsync_options_shared",fsync_options_shared},
 {"fadvise_options_shared",fadvise_options_shared},
 {"fixed_fd_install_flags_shared",fixed_fd_install_flags_shared},
 {"nop_flags_shared",nop_flags_shared},
 {"msg_ring_shared",msg_ring_shared},
 {"register_msg_ring_shared",register_msg_ring_shared},
 {"enter_no_iowait_shared",enter_no_iowait_shared},
 {"extended_layout_shared",extended_layout_shared},
 {"cqe_mixed_shared",cqe_mixed_shared},
 {"sq_rewind_shared",sq_rewind_shared},
 {"sqpoll_nonfixed_shared",sqpoll_nonfixed_shared},
 {"sqpoll_shared",sqpoll_shared},
 {"sqpoll_attach_shared",sqpoll_attach_shared},
 {"sqpoll_attach_reverse_close_shared",sqpoll_attach_reverse_close_shared},
 {"sqpoll_attach_cq_overflow_shared",sqpoll_attach_cq_overflow_shared},
 {"sqpoll_attach_blocked_read_progress_shared",sqpoll_attach_blocked_read_progress_shared},
 {"sqpoll_attach_pbuf_read_shared",sqpoll_attach_pbuf_read_shared},
 {"async_pbuf_worker_shared",async_pbuf_worker_shared},
 {"sqpoll_pbuf_incremental_shared",sqpoll_pbuf_incremental_shared},
 {"sqpoll_pbuf_cancel_shared",sqpoll_pbuf_cancel_shared},
 {"sqpoll_pbuf_incremental_cancel_shared",sqpoll_pbuf_incremental_cancel_shared},
 {"sqpoll_attach_concurrent_close_shared",sqpoll_attach_concurrent_close_shared},
 {"sqpoll_attach_invalid_shared",sqpoll_attach_invalid_shared},
 {"sqpoll_attach_idle_shared",sqpoll_attach_idle_shared},
 {"sqpoll_attach_group_idle_shared",sqpoll_attach_group_idle_shared},
 {"sqpoll_attach_nommap_shared",sqpoll_attach_nommap_shared},
 {"sqpoll_attach_fork_shared",sqpoll_attach_fork_shared},
 {"sqpoll_attach_failed_exec_shared",sqpoll_attach_failed_exec_shared},
 {"sqpoll_attach_owner_exit_shared",sqpoll_attach_owner_exit_shared},
 {"sqpoll_attach_worker_controls_shared",sqpoll_attach_worker_controls_shared},
 {"sqpoll_attach_worker_affinity_shared",sqpoll_attach_worker_affinity_shared},
 {"sqpoll_attach_crossabi_shared",sqpoll_attach_crossabi_shared},
 {"sqpoll_attach_waitid_close_shared",sqpoll_attach_waitid_close_shared},
 {"sqpoll_affinity_shared",sqpoll_affinity_shared},
 {"sqpoll_taskrun_shared",sqpoll_taskrun_shared},
 {"sqpoll_layout_shared",sqpoll_layout_shared},
 {"pbuf_ring_shared",pbuf_ring_shared},
 {"pbuf_ring_incremental_shared",pbuf_ring_incremental_shared},
 {"provided_buffer_options_shared",provided_buffer_options_shared},
 {"provided_buffer_race_shared",provided_buffer_race_shared},
 {"prep_ioprio",prep_ioprio},
 {"prep_reserved_core",prep_reserved_core},
 {"prep_reserved_linux",prep_reserved_linux},
 {"prep_buffer_select",prep_buffer_select},
 {"prep_rwflags",prep_rwflags},
 {"prep_positive",prep_positive},
 {"prep_buffer_runtime",prep_buffer_runtime},
 {"prep_fixed_file",prep_fixed_file},
 {"prep_links",prep_links},

 {"files_cycles",files_cycles},
 {"files_update_cycles",files_update_cycles},
 {"files_skip",files_skip},
 {"files_partial",files_partial},
 {"files_faults",files_faults},
 {"files_validation",files_validation},
 {"files_lifetime",files_lifetime},
 {"files_update_alloc_shared",files_update_alloc_shared},
 {"files_race",files_race},
 {"files_read_race",files_read_race},
 {"files_permissions",files_permissions},
 {"files_caps",files_caps},
 {"files_exit",files_exit},
 {"files_v2_shared",files_v2_shared},
 {"close_direct_shared",close_direct_shared},
 {"buffers_v2_shared",buffers_v2_shared},
 {"feature_reg_ring_shared",feature_reg_ring_shared},
 {"clone_buffers_shared",clone_buffers_shared},
 {"personality_shared",personality_shared},
 {"iowq_controls_shared",iowq_controls_shared},
 {"bpf_filter_shared",bpf_filter_shared},
 {"napi_register_shared",napi_register_shared},

 {"setup_exec",setup_exec},
 {"sqe_mixed_shared",sqe_mixed_shared},
 {"attach_wq_shared",attach_wq_shared},
 {"setup_flags",setup_flags},
 {"setup_disabled",setup_disabled},
 {"setup_restrict_ops",setup_restrict_ops},
 {"setup_restrict_flags",setup_restrict_flags},
 {"setup_restrict_register",setup_restrict_register},
 {"setup_restrict_empty",setup_restrict_empty},
 {"setup_restrict_invalid",setup_restrict_invalid},
 {"setup_restrict_faults",setup_restrict_faults},
 {"setup_restrict_fixed",setup_restrict_fixed},
 {"setup_restrict_links",setup_restrict_links},
 {"setup_single",setup_single},
 {"setup_single_enable",setup_single_enable},
 {"setup_single_threads",setup_single_threads},
 {"setup_single_exit",setup_single_exit},
 {"setup_enable_race",setup_enable_race},
 {"setup_restrict_race",setup_restrict_race},
 {"setup_submit_all",setup_submit_all},
 {"setup_submit_errors",setup_submit_errors},
 {"setup_submit_links",setup_submit_links},
 {"setup_submit_indices",setup_submit_indices},
 {"setup_permissions",setup_permissions},

 {"links_queue_isolation",links_queue_isolation},

 {"links_io",links_io},

 {"links_poll_reuse",links_poll_reuse},
 {"links_cancel_race",links_cancel_race},

 {"links_hardlink",links_hardlink},
 {"links_deferred",links_deferred},
 {"links_rollback",links_rollback},
 {"links_queued",links_queued},

 {"links_success",links_success},
 {"links_expire",links_expire},
 {"links_absolute",links_absolute},
 {"links_invalid",links_invalid},
 {"links_cancel_target",links_cancel_target},
 {"links_cancel_timer",links_cancel_timer},
 {"links_remove_scope",links_remove_scope},
 {"links_duplicates",links_duplicates},
 {"links_cancel_all",links_cancel_all},
 {"cancel_modes_shared",cancel_modes_shared},
 {"sync_cancel_shared",sync_cancel_shared},
 {"file_alloc_range_shared",file_alloc_range_shared},
 {"poll_update_shared",poll_update_shared},
 {"poll_lifetime_shared",poll_lifetime_shared},
 {"poll_ring_target_shared",poll_ring_target_shared},
 {"poll_ring_deferred_close_shared",poll_ring_deferred_close_shared},
 {"poll_ring_sqpoll_self_close_shared",poll_ring_sqpoll_self_close_shared},
 {"poll_level_rejected_shared",poll_level_rejected_shared},
 {"timeout_modes_shared",timeout_modes_shared},
 {"timeout_immediate_shared",timeout_immediate_shared},
 {"timeout_reserved_shared",timeout_reserved_shared},
 {"links_worker",links_worker},
 {"links_race",links_race},
 {"links_close",links_close},

 {"buffers_vm_race",buffers_vm_race},
 {"buffers_cow",buffers_cow},{"buffers_mapped_file",buffers_mapped_file},
 {"buffers_register",buffers_register},
 {"buffers_faults",buffers_faults},
 {"buffers_ranges",buffers_ranges},
 {"buffers_vectors",buffers_vectors},
 {"buffers_remap",buffers_remap},
 {"buffers_protect",buffers_protect},
 {"buffers_retry",buffers_retry},
 {"buffers_async",buffers_async},
 {"buffers_fork",buffers_fork},
 {"buffers_limits",buffers_limits},
 {"buffers_links",buffers_links},
 {"buffers_churn",buffers_churn},


 {"rwf_retry",rwf_retry},
 {"rwf_nosignal",rwf_nosignal},
 {"rwf_memfd",rwf_memfd},
 {"rwf_unsupported",rwf_unsupported},{"rwf_memory_faults",rwf_memory_faults},{"rwf_fd_reuse",rwf_fd_reuse},
 {"rwf_sync",rwf_sync},{"rwf_reject",rwf_reject},{"rwf_append",rwf_append},{"rwf_faults",rwf_faults},{"rwf_links",rwf_links},{"rwf_fixed_file",rwf_fixed_file},{"rwf_concurrent",rwf_concurrent},
 {"probe_layout",probe_layout},{"probe_invalid",probe_invalid},
 {"probe_faults",probe_faults},{"probe_scope",probe_scope},
 {"probe_lifetime",probe_lifetime},{"probe_concurrent",probe_concurrent},
 {"probe_permissions",probe_permissions},
 {"layout",layout},{"wrap",wrap},{"legacy",legacy},{"invalid",invalid},
 {"io",io},{"allocation_zfs",allocation_zfs},{"validation",validation},{"lifetime",lifetime},{"concurrent",concurrent},{"fork_lifetime",fork_lifetime}
};
static int run(int argc,char **argv)
{
 setup_self=argv[0];
 if(argc==3&&equal(argv[1],"sqpoll_attach_crossabi_helper"))return sqpoll_attach_crossabi_helper(argv[2])!=0;
 if(argc==3&&equal(argv[1],"setup_exec_owner"))return setup_exec_helper(argv[2],1)!=0;
 if(argc==3&&equal(argv[1],"setup_exec_other"))return setup_exec_helper(argv[2],0)!=0;
#ifdef LINUX_ABI
 if(argc==2&&equal(argv[1],"bpf_task_exec"))return bpf_task_exec_helper()!=0;
#endif
 if(argc!=2)return 111;
 if(equal(argv[1],"durable_prepare"))return rwf_durable(0)!=0;
 if(equal(argv[1],"durable_write"))return rwf_durable(1)!=0;
 if(equal(argv[1],"durable_check"))return rwf_durable(2)!=0;
 for(u32 i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
  if(equal(argv[1],"-l")){put(cases[i].name);put("\n");}
  else if(equal(argv[1],cases[i].name)) {int r=cases[i].fn();if(r){char b[16];int n=0;unsigned v=r;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);put("SQUEUE_OPTIONS_FAIL ");put(cases[i].name);put(" line ");while(n)CALL(N_WRITE,1,&b[--n],1);put("\n");}return r!=0;}
 }
 return equal(argv[1],"-l")?0:112;
}
#ifdef LINUX_ABI
void start_c(long *sp) {int r=run((int)sp[0],(char **)(sp+1));CALL(N_EXIT,r,0,0);for(;;){} }
#else
int main(int argc,char **argv) {return run(argc,argv);}
#endif
