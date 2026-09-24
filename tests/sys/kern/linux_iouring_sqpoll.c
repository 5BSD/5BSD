/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux 6.18 SQPOLL reference cases; candidate admission follows the oracle. */
#include "linux_test.h"

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_sched_setaffinity 203
#define SYS_sched_getaffinity 204
#define IORING_SETUP_SQPOLL (1U << 1)
#define IORING_SETUP_SQ_AFF (1U << 2)
#define IORING_SETUP_COOP_TASKRUN (1U << 8)
#define IORING_SETUP_TASKRUN_FLAG (1U << 9)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_SQ_WAIT (1U << 2)
#define IORING_SQ_NEED_WAKEUP (1U << 0)
#define IORING_OFF_SQES 0x10000000UL
#define IORING_OP_READ 22
#define EOWNERDEAD 130
struct sqoff { u32 head, tail, mask, entries, flags, dropped, array, resv; u64 addr; };
struct cqoff { u32 head, tail, mask, entries, overflow, cqes, flags, resv; u64 addr; };
struct params {
	u32 sq_entries, cq_entries, flags, cpu, idle, features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
struct cqe { u64 data; int res; u32 flags; };
struct ts { long sec, nsec; };
struct ring {
	struct params p;
	long fd;
	u8 *ctrl, *sqes;
};
static int
open_ring_ex(struct ring *r, u32 idle, u32 flags, u32 cpu)
{
	r->p = (struct params){0};
	r->p.flags = flags;
	r->p.cpu = cpu;
	r->p.idle = idle;
	r->fd = sys2(SYS_io_uring_setup, 4, &r->p);
	if (r->fd < 0)
		return (1);
	r->ctrl = (u8 *)sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_SHARED, r->fd, 0);
	r->sqes = (u8 *)sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_SHARED, r->fd, IORING_OFF_SQES);
	if ((long)r->ctrl < 0 || (long)r->sqes < 0)
		return (2);
	return (0);
}
static int
open_ring(struct ring *r, u32 idle)
{
	return (open_ring_ex(r, idle, IORING_SETUP_SQPOLL, 0));
}
static void
close_ring(struct ring *r)
{
	if ((long)r->ctrl >= 0)
		sys2(SYS_munmap, r->ctrl, PAGE);
	if ((long)r->sqes >= 0)
		sys2(SYS_munmap, r->sqes, PAGE);
	if (r->fd >= 0)
		sys1(SYS_close, r->fd);
}
static void
nop(struct ring *r, u64 data)
{
	u32 head = __atomic_load_n((u32 *)(r->ctrl + r->p.sq_off.tail),
	    __ATOMIC_RELAXED);
	u32 idx = head & (r->p.sq_entries - 1);
	u8 *sqe = r->sqes + idx * 64;
	int i;

	for (i = 0; i < 64; i++)
		sqe[i] = 0;
	*(u64 *)(sqe + 32) = data;
	*(u32 *)(r->ctrl + r->p.sq_off.array + idx * 4) = idx;
	__atomic_store_n((u32 *)(r->ctrl + r->p.sq_off.tail), head + 1,
	    __ATOMIC_RELEASE);
}
static void
read_sqe(struct ring *r, u32 idx, int fd, void *buf, u64 data)
{
	u8 *sqe = r->sqes + idx * 64;
	u32 tail = __atomic_load_n((u32 *)(r->ctrl + r->p.sq_off.tail),
	    __ATOMIC_RELAXED);
	int i;

	for (i = 0; i < 64; i++)
		sqe[i] = 0;
	sqe[0] = IORING_OP_READ;
	*(int *)(sqe + 4) = fd;
	*(u64 *)(sqe + 8) = (u64)-1;
	*(u64 *)(sqe + 16) = (u64)buf;
	*(u32 *)(sqe + 24) = 1;
	*(u64 *)(sqe + 32) = data;
	*(u32 *)(r->ctrl + r->p.sq_off.array +
	    (tail & (r->p.sq_entries - 1)) * 4) = idx;
	__atomic_store_n((u32 *)(r->ctrl + r->p.sq_off.tail), tail + 1,
	    __ATOMIC_RELEASE);
}
static int
await_cqe(struct ring *r, u32 index, u64 data, int expected)
{
	struct ts pause = {0, 1000000};
	u32 *tail = (u32 *)(r->ctrl + r->p.cq_off.tail);
	struct cqe *c = (struct cqe *)(r->ctrl + r->p.cq_off.cqes);
	int i;

	for (i = 0; i < 2000; i++) {
		if (__atomic_load_n(tail, __ATOMIC_ACQUIRE) > index)
			return (c[index].data == data &&
			    c[index].res == expected ? 0 : 1);
		sys2(SYS_nanosleep, &pause, 0);
	}
	return (2);
}
static int
auto_submit(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	struct ts pause = {0, 1000000};
	u32 *flags;
	int i, rc = open_ring(&r, 10000);

	if (rc != 0) {
		close_ring(&r);
		return (rc);
	}
	flags = (u32 *)(r.ctrl + r.p.sq_off.flags);
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0) { rc = 3; goto out; }
	for (i = 0; i < 1000; i++) {
		if ((__atomic_load_n(flags, __ATOMIC_ACQUIRE) &
		    IORING_SQ_NEED_WAKEUP) == 0)
			break;
		sys2(SYS_nanosleep, &pause, 0);
	}
	if (i == 1000) { rc = 4; goto out; }
	nop(&r, 0x1212);
	rc = await_cqe(&r, 0, 0x1212, 0);
	if (rc != 0)
		rc += 4;
out:
	close_ring(&r);
	return (rc);
}
static int
idle_wakeup(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	struct ts pause = {0, 10000000};
	u32 *flags;
	int i, rc = open_ring(&r, 10);

	if (rc != 0) {
		close_ring(&r);
		return (rc);
	}
	flags = (u32 *)(r.ctrl + r.p.sq_off.flags);
	for (i = 0; i < 100; i++) {
		if ((__atomic_load_n(flags, __ATOMIC_ACQUIRE) &
		    IORING_SQ_NEED_WAKEUP) != 0)
			break;
		sys2(SYS_nanosleep, &pause, 0);
	}
	if (i == 100) { rc = 3; goto out; }
	nop(&r, 0x3434);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if ((__atomic_load_n(flags, __ATOMIC_ACQUIRE) &
	    IORING_SQ_NEED_WAKEUP) == 0) { rc = 4; goto out; }
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0) { rc = 5; goto out; }
	rc = await_cqe(&r, 0, 0x3434, 0);
	if (rc != 0)
		rc += 5;
out:
	close_ring(&r);
	return (rc);
}
static int
sq_wait_space(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	int i, rc = open_ring(&r, 10);

	if (rc != 0) {
		close_ring(&r);
		return (rc);
	}
	for (i = 0; i < 4; i++)
		nop(&r, 0x4000 + i);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (sys6(SYS_io_uring_enter, r.fd, 4, 0,
	    IORING_ENTER_SQ_WAKEUP | IORING_ENTER_SQ_WAIT, 0, 0) != 4) {
		rc = 3;
		goto out;
	}
	for (i = 0; i < 4; i++) {
		rc = await_cqe(&r, i, 0x4000 + i, 0);
		if (rc != 0) {
			rc += 3;
			goto out;
		}
	}
out:
	close_ring(&r);
	return (rc);
}
static int
fd_context(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	int fds[2] = {-1, -1}, rc = open_ring(&r, 1000);
	char ch = 0, input = 'Q';

	if (rc != 0) {
		close_ring(&r);
		return (rc);
	}
	if (sys1(SYS_pipe, fds) != 0) { rc = 3; goto out; }
	if (sys3(SYS_write, fds[1], &input, 1) != 1) {
		rc = 4; goto out;
	}
	read_sqe(&r, 0, fds[0], &ch, 0x5151);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0) { rc = 5; goto out; }
	rc = await_cqe(&r, 0, 0x5151, 1);
	if (rc != 0 || ch != 'Q') { rc = 6; goto out; }
	read_sqe(&r, 1, -1, &ch, 0x5252);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0) { rc = 7; goto out; }
	rc = await_cqe(&r, 1, 0x5252, -EBADF);
	if (rc != 0)
		rc += 7;
out:
	if (fds[0] >= 0) sys1(SYS_close, fds[0]);
	if (fds[1] >= 0) sys1(SYS_close, fds[1]);
	close_ring(&r);
	return (rc);
}
static int
failed_exec_preserves_ring(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	char *argv[] = {"/no-such-sqpoll-executable", 0};
	char *envp[] = {0};
	int rc = open_ring(&r, 10);

	if (rc != 0) {
		close_ring(&r);
		return (rc);
	}
	if (sys3(SYS_execve, argv[0], argv, envp) != -ENOENT) {
		rc = 3; goto out;
	}
	nop(&r, 0x6666);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0) { rc = 4; goto out; }
	rc = await_cqe(&r, 0, 0x6666, 0);
	if (rc != 0)
		rc += 4;
out:
	close_ring(&r);
	return (rc);
}
static int
owner_exit_contract(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	struct ts pause = {0, 200000000};
	int fds[2] = {-1, -1}, status, rc;
	long owner, consumer;
	char result = 0xff;

	if (sys1(SYS_pipe, fds) != 0)
		return (1);
	owner = sys1(SYS_fork, 0);
	if (owner < 0) {
		sys1(SYS_close, fds[0]); sys1(SYS_close, fds[1]);
		return (2);
	}
	if (owner == 0) {
		sys1(SYS_close, fds[0]);
		rc = open_ring(&r, 10);
		if (rc != 0) {
			result = 3;
			sys3(SYS_write, fds[1], &result, 1);
			sys1(SYS_exit_group, 0);
		}
		consumer = sys1(SYS_fork, 0);
		if (consumer < 0) {
			result = 4;
			sys3(SYS_write, fds[1], &result, 1);
			sys1(SYS_exit_group, 0);
		}
		if (consumer != 0)
			sys1(SYS_exit_group, 0);
		/* Linux marks an inherited ring dead when its SQPOLL owner exits. */
		sys2(SYS_nanosleep, &pause, 0);
		nop(&r, 0x7575);
		result = sys6(SYS_io_uring_enter, r.fd, 0, 0,
		    IORING_ENTER_SQ_WAKEUP, 0, 0) == -EOWNERDEAD ? 0 : 5;
		sys3(SYS_write, fds[1], &result, 1);
		close_ring(&r);
		sys1(SYS_exit_group, 0);
	}
	sys1(SYS_close, fds[1]);
	status = 0;
	if (sys4(SYS_wait4, owner, &status, 0, 0) != owner || status != 0)
		rc = 6;
	else if (sys3(SYS_read, fds[0], &result, 1) != 1)
		rc = 7;
	else
		rc = result;
	sys1(SYS_close, fds[0]);
	return (rc);
}
static int
invalid_setup(void)
{
	struct params p = {0};
	long ret;

	p.flags = IORING_SETUP_SQ_AFF;
	ret = sys2(SYS_io_uring_setup, 4, &p);
	if (ret != -EINVAL) {
		if (ret >= 0) sys1(SYS_close, ret);
		return (1);
	}
	return (0);
}
static int
affinity_valid(void)
{
	struct ring r = {.fd = -1, .ctrl = (void *)-1, .sqes = (void *)-1};
	u8 mask[128] = {0};
	long n;
	u32 cpu;
	int rc;

	n = sys3(SYS_sched_getaffinity, 0, sizeof(mask), mask);
	if (n <= 0 || n > (long)sizeof(mask))
		return (1);
	for (cpu = 0; cpu < (u32)n * 8; cpu++)
		if ((mask[cpu / 8] & (1U << (cpu % 8))) != 0)
			break;
	if (cpu == (u32)n * 8)
		return (2);
	rc = open_ring_ex(&r, 1000,
	    IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF, cpu);
	if (rc != 0) {
		close_ring(&r);
		return (3);
	}
	nop(&r, 0xaff);
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
	    IORING_ENTER_SQ_WAKEUP, 0, 0) != 0)
		rc = 4;
	else if (await_cqe(&r, 0, 0xaff, 0) != 0)
		rc = 5;
	close_ring(&r);
	return (rc);
}
static int
affinity_mask_contract(void)
{
	struct params p = {0};
	u8 saved[128] = {0}, restricted[128] = {0};
	long n, ret;
	u32 first = ~0U, second = ~0U, cpu;
	int rc = 0;

	p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
	p.cpu = ~0U;
	ret = sys2(SYS_io_uring_setup, 4, &p);
	if (ret != -EINVAL) {
		if (ret >= 0) sys1(SYS_close, ret);
		return (1);
	}
	n = sys3(SYS_sched_getaffinity, 0, sizeof(saved), saved);
	if (n <= 0 || n > (long)sizeof(saved))
		return (2);
	for (cpu = 0; cpu < (u32)n * 8; cpu++) {
		if ((saved[cpu / 8] & (1U << (cpu % 8))) == 0)
			continue;
		if (first == ~0U)
			first = cpu;
		else { second = cpu; break; }
	}
	if (second == ~0U)
		return (3);
	restricted[second / 8] = 1U << (second % 8);
	if (sys3(SYS_sched_setaffinity, 0, sizeof(restricted), restricted) != 0)
		return (4);
	p = (struct params){0};
	p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF;
	p.cpu = first;
	ret = sys2(SYS_io_uring_setup, 4, &p);
	if (ret < 0)
		rc = 5;
	else
		sys1(SYS_close, ret);
	if (sys3(SYS_sched_setaffinity, 0, sizeof(saved), saved) != 0)
		return (6);
	return (rc);
}
static int
taskrun_incompatible(void)
{
	static const u32 flags[] = {
		IORING_SETUP_SQPOLL | IORING_SETUP_COOP_TASKRUN,
		IORING_SETUP_SQPOLL | IORING_SETUP_COOP_TASKRUN |
		    IORING_SETUP_TASKRUN_FLAG,
		IORING_SETUP_SQPOLL | IORING_SETUP_SINGLE_ISSUER |
		    IORING_SETUP_DEFER_TASKRUN,
		IORING_SETUP_SQPOLL | IORING_SETUP_COOP_TASKRUN |
		    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN,
	};
	struct params p;
	long ret;
	u32 i;

	for (i = 0; i < 16; i++) {
		p = (struct params){0};
		p.flags = flags[i % (sizeof(flags) / sizeof(flags[0]))];
		ret = sys2(SYS_io_uring_setup, 4, &p);
		if (ret != -EINVAL) {
			if (ret >= 0) sys1(SYS_close, ret);
			return (1 + i);
		}
	}
	p = (struct params){0};
	p.flags = IORING_SETUP_SQPOLL;
	ret = sys2(SYS_io_uring_setup, 4, &p);
	if (ret < 0)
		return (17);
	sys1(SYS_close, ret);
	return (0);
}
static int
single_issuer(void)
{
    struct ring r;
    int i, rc;

    for (i = 0; i < 8; i++) {
        r = (struct ring){.fd = -1, .ctrl = (void *)-1,
            .sqes = (void *)-1};
        rc = open_ring_ex(&r, 10, IORING_SETUP_SQPOLL |
            IORING_SETUP_SINGLE_ISSUER, 0);
        if (rc != 0) { close_ring(&r); return (1); }
        nop(&r, 0x5100 + i);
        if (sys6(SYS_io_uring_enter, r.fd, 0, 0,
            IORING_ENTER_SQ_WAKEUP, 0, 0) != 0 ||
            await_cqe(&r, 0, 0x5100 + i, 0) != 0) {
            close_ring(&r);
            return (2);
        }
        close_ring(&r);
    }
    return (0);
}
static const struct subtest cases[] = {
	{ "auto_submit", auto_submit },
	{ "idle_wakeup", idle_wakeup },
	{ "sq_wait_space", sq_wait_space },
	{ "fd_context", fd_context },
	{ "owner_exit_contract", owner_exit_contract },
	{ "failed_exec_preserves_ring", failed_exec_preserves_ring },
	{ "invalid_setup", invalid_setup },
	{ "affinity_valid", affinity_valid },
	{ "affinity_mask_contract", affinity_mask_contract },
	{ "taskrun_incompatible", taskrun_incompatible },
	{ "single_issuer", single_issuer },
};
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
