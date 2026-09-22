/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux amd64 rseq per-mm concurrency-ID contract, without libc. */
typedef unsigned long u64;
typedef unsigned int u32;
struct rseq {
	u32 cpu_id_start, cpu_id;
	u64 rseq_cs;
	u32 flags, node_id, mm_cid, pad;
} __attribute__((aligned(32)));
struct rseq parent_area, worker_area;
char worker_stack[65536] __attribute__((aligned(16)));
volatile int worker_ready, worker_go, worker_done, worker_error;
static long
call(long n, long a, long b, long c, long d)
{
	register long r10 __asm__("r10") = d, r8 __asm__("r8") = 0,
	    r9 __asm__("r9") = 0;
	long ret;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a),
	    "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) :
	    "rcx", "r11", "memory");
	return (ret);
}
static __attribute__((used)) int
worker(void)
{
	u64 mask = 2;

	if (call(203, 0, sizeof(mask), (long)&mask, 0) != 0)
		worker_error = 1;
	else if (call(334, (long)&worker_area, 32, 0, 0x53053053) != 0)
		worker_error = 2;
	else if (worker_area.cpu_id != 1 || worker_area.cpu_id_start != 1)
		worker_error = 3;
	__atomic_store_n(&worker_ready, 1, __ATOMIC_RELEASE);
	while (!__atomic_load_n(&worker_go, __ATOMIC_ACQUIRE))
		__asm__ volatile("pause");
	if (worker_error == 0 &&
	    call(334, (long)&worker_area, 32, 1, 0x53053053) != 0)
		worker_error = 4;
	__atomic_store_n(&worker_done, 1, __ATOMIC_RELEASE);
	return (worker_error);
}
__asm__(".globl start_worker\n"
    "start_worker:\n"
    " mov $0x10f00,%edi\n"
    " lea worker_stack+65536(%rip),%rsi\n"
    " xor %edx,%edx\n xor %r10d,%r10d\n xor %r8d,%r8d\n"
    " mov $56,%eax\n syscall\n"
    " test %rax,%rax\n jnz 1f\n"
    " and $-16,%rsp\n call worker\n"
    " mov %eax,%edi\n mov $60,%eax\n syscall\n hlt\n"
    "1: ret\n");
long start_worker(void);
static int
test(void)
{
	u64 mask = 1;
	long tid;
	int i;

	if (call(203, 0, sizeof(mask), (long)&mask, 0) != 0)
		return (1);
	if (call(334, (long)&parent_area, 32, 0, 0x53053053) != 0)
		return (2);
	tid = start_worker();
	if (tid <= 0)
		return (3);
	for (i = 0; i < 10000 &&
	    !__atomic_load_n(&worker_ready, __ATOMIC_ACQUIRE); i++)
		call(24, 0, 0, 0, 0);
	if (!worker_ready || worker_error != 0 ||
	    parent_area.cpu_id != 0 || worker_area.cpu_id != 1 ||
	    parent_area.mm_cid == worker_area.mm_cid)
		return (4);
	__atomic_store_n(&worker_go, 1, __ATOMIC_RELEASE);
	for (i = 0; i < 10000 &&
	    !__atomic_load_n(&worker_done, __ATOMIC_ACQUIRE); i++)
		call(24, 0, 0, 0, 0);
	if (!worker_done || worker_error != 0)
		return (5);
	if (call(334, (long)&parent_area, 32, 1, 0x53053053) != 0)
		return (6);
	return (0);
}
__attribute__((force_align_arg_pointer)) void
_start(void)
{
	call(231, test(), 0, 0, 0);
	__builtin_unreachable();
}
