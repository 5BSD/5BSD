/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux 6.18 IORING_SETUP_NO_MMAP and registered-fd-only oracle contracts. */
#include "linux_test.h"

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define IORING_SETUP_SQPOLL (1U << 1)
#define IORING_SETUP_NO_MMAP (1U << 14)
#define IORING_SETUP_REGISTERED_FD_ONLY (1U << 15)
#define IORING_SETUP_NO_SQARRAY (1U << 16)
#define IORING_SETUP_SQE128 (1U << 10)
#define IORING_SETUP_CQE32 (1U << 11)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_REGISTER_RESIZE_RINGS 33
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_SQ_WAKEUP (1U << 1)
#define IORING_ENTER_REGISTERED_RING (1U << 4)
#define IORING_UNREGISTER_RING_FDS 21
#define IORING_REGISTER_USE_REGISTERED_RING (1U << 31)
#define USER_REGION (16 * PAGE)
struct sqoff { u32 head, tail, mask, entries, flags, dropped, array, resv; u64 addr; };
struct cqoff { u32 head, tail, mask, entries, overflow, cqes, flags, resv; u64 addr; };
struct params {
	u32 sq_entries, cq_entries, flags, cpu, idle, features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
struct cqe { u64 data; int res; u32 flags; };
static long
region(void)
{
	return (sys6(SYS_mmap, 0, USER_REGION, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
}
static long
make_ring(struct params *p, long sqes, long ring, u32 flags)
{
	*p = (struct params){0};
	p->flags = flags;
	p->sq_off.addr = (u64)sqes;
	p->cq_off.addr = (u64)ring;
	return (sys2(SYS_io_uring_setup, 4, p));
}
static int
basic_mode(u32 extra)
{
	struct params p;
	struct cqe *c;
	u8 *sqes, *ring;
	u32 *array, *tail, *cqhead, *cqtail;
	long a, b, fd, r;
	int rc = 0;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	sqes = (u8 *)a; ring = (u8 *)b;
	fd = make_ring(&p, a, b, IORING_SETUP_NO_MMAP | extra);
	if (fd < 0) { rc = 2; goto out; }
	if (p.sq_off.addr != (u64)a || p.cq_off.addr != (u64)b ||
	    p.sq_entries != 4 || p.cq_entries != 8) { rc = 3; goto close; }
	array = (u32 *)(ring + p.sq_off.array);
	tail = (u32 *)(ring + p.sq_off.tail);
	cqhead = (u32 *)(ring + p.cq_off.head);
	cqtail = (u32 *)(ring + p.cq_off.tail);
	c = (struct cqe *)(ring + p.cq_off.cqes);
	sqes[0] = 0; /* NOP */
	*(u64 *)(sqes + 32) = 0x12345678UL;
	if ((extra & IORING_SETUP_NO_SQARRAY) == 0)
		array[0] = 0;
	__atomic_store_n(tail, 1, __ATOMIC_RELEASE);
	r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 1) { rc = 4; goto close; }
	if (__atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 1 ||
	    c[0].data != 0x12345678UL || c[0].res != 0) { rc = 5; goto close; }
	__atomic_store_n(cqhead, 1, __ATOMIC_RELEASE);
	if (sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, 0) >= 0) { rc = 6; goto close; }
close:
	sys1(SYS_close, fd);
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
basic(void)
{
	return (basic_mode(0));
}
static int
layout_modes(void)
{
	if (basic_mode(IORING_SETUP_NO_SQARRAY) != 0)
		return (1);
	if (basic_mode(IORING_SETUP_SQE128) != 0)
		return (2);
	if (basic_mode(IORING_SETUP_CQE32) != 0)
		return (3);
	if (basic_mode(IORING_SETUP_NO_SQARRAY | IORING_SETUP_SQE128 |
	    IORING_SETUP_CQE32) != 0)
		return (4);
	return (0);
}
static int
read_only(void)
{
	struct params p;
	long a, b, r;
	int rc = 0;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	if (sys3(SYS_mprotect, (void *)b, USER_REGION, PROT_READ) != 0) {
		rc = 2; goto out;
	}
	r = make_ring(&p, a, b, IORING_SETUP_NO_MMAP);
	if (r != -EFAULT) { rc = 3; goto out; }
	if (sys3(SYS_mprotect, (void *)b, USER_REGION,
	    PROT_READ | PROT_WRITE) != 0 ||
	    sys3(SYS_mprotect, (void *)a, USER_REGION, PROT_READ) != 0) {
		rc = 4; goto out;
	}
	r = make_ring(&p, a, b, IORING_SETUP_NO_MMAP);
	if (r != -EFAULT) { rc = 5; goto out; }
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
unmap_lifetime(void)
{
	struct params p;
	struct cqe *c;
	u8 *sqes, *ring;
	u32 *array, *tail, *cqtail;
	long fds, fdr, a, b, alias_sq, alias_ring, fd, r;
	int rc = 0;

	fds = sys2(SYS_memfd_create, "nommap-sqes", 0);
	fdr = sys2(SYS_memfd_create, "nommap-ring", 0);
	if (fds < 0 || fdr < 0)
		return (1);
	if (sys2(SYS_ftruncate, fds, USER_REGION) != 0 ||
	    sys2(SYS_ftruncate, fdr, USER_REGION) != 0) {
		rc = 2; goto close_files;
	}
	a = sys6(SYS_mmap, 0, USER_REGION, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fds, 0);
	b = sys6(SYS_mmap, 0, USER_REGION, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fdr, 0);
	alias_sq = sys6(SYS_mmap, 0, USER_REGION, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fds, 0);
	alias_ring = sys6(SYS_mmap, 0, USER_REGION, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fdr, 0);
	if (a < 0 || b < 0 || alias_sq < 0 || alias_ring < 0) {
		rc = 3; goto close_files;
	}
	fd = make_ring(&p, a, b, IORING_SETUP_NO_MMAP);
	if (fd < 0) { rc = 4; goto close_files; }
	if (sys2(SYS_munmap, (void *)a, USER_REGION) != 0 ||
	    sys2(SYS_munmap, (void *)b, USER_REGION) != 0) {
		rc = 5; goto close_ring;
	}
	sqes = (u8 *)alias_sq; ring = (u8 *)alias_ring;
	array = (u32 *)(ring + p.sq_off.array);
	tail = (u32 *)(ring + p.sq_off.tail);
	cqtail = (u32 *)(ring + p.cq_off.tail);
	c = (struct cqe *)(ring + p.cq_off.cqes);
	sqes[0] = 0;
	*(u64 *)(sqes + 32) = 0xabcdefUL;
	array[0] = 0;
	__atomic_store_n(tail, 1, __ATOMIC_RELEASE);
	r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 1 || __atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 1 ||
	    c[0].data != 0xabcdefUL || c[0].res != 0)
		rc = 6;
close_ring:
	sys1(SYS_close, fd);
	sys2(SYS_munmap, (void *)alias_sq, USER_REGION);
	sys2(SYS_munmap, (void *)alias_ring, USER_REGION);
close_files:
	sys1(SYS_close, fds);
	sys1(SYS_close, fdr);
	return (rc);
}
static int
invalid_setup(void)
{
	struct params p;
	long a, b, r;
	int rc = 0;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	r = make_ring(&p, a, b, IORING_SETUP_REGISTERED_FD_ONLY);
	if (r != -EINVAL) { rc = 2; goto out; }
	r = make_ring(&p, 0, b, IORING_SETUP_NO_MMAP);
	if (r != -EFAULT) { rc = 3; goto out; }
	r = make_ring(&p, a, 0, IORING_SETUP_NO_MMAP);
	if (r != -EFAULT) { rc = 4; goto out; }
	r = make_ring(&p, a + 1, b, IORING_SETUP_NO_MMAP);
	if (r != -EINVAL) { rc = 5; goto out; }
	r = make_ring(&p, a, b + 1, IORING_SETUP_NO_MMAP);
	if (r != -EINVAL) { rc = 6; goto out; }
	r = make_ring(&p, 1, b, IORING_SETUP_NO_MMAP);
	if (r != -EINVAL && r != -EFAULT) { rc = 7; goto out; }
	if (sys3(SYS_mprotect, (void *)b, USER_REGION, PROT_NONE) != 0) {
		rc = 8; goto out;
	}
	r = make_ring(&p, a, b, IORING_SETUP_NO_MMAP);
	if (r != -EFAULT) { rc = 9; goto out; }
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
registered_only(void)
{
	struct params p;
	long a, b, idx, r;
	int rc = 0;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	idx = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_REGISTERED_FD_ONLY);
	if (idx < 0) { rc = 2; goto out; }
	/* The return value indexes the caller's registered ring table. */
	r = sys6(SYS_io_uring_enter, idx, 0, 0,
	    IORING_ENTER_REGISTERED_RING, 0, 0);
	if (r != 0) { rc = 3; goto out; }
	r = sys6(SYS_io_uring_enter, idx, 0, 0, 0, 0, 0);
	if (r != -EOPNOTSUPP) { rc = 4; goto out; }
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
resize_basic(void)
{
	struct params p, np;
	struct cqe *c;
	u8 *sqes, *ring;
	u32 *array, *tail, *cqtail;
	long a, b, na, nb, fd, r;
	int rc = 0;

	a = region(); b = region(); na = region(); nb = region();
	if (a < 0 || b < 0 || na < 0 || nb < 0)
		return (1);
	fd = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);
	if (fd < 0) { rc = 2; goto out; }
	np = (struct params){0};
	np.sq_entries = 8;
	np.sq_off.addr = na; np.cq_off.addr = nb;
	r = sys4(SYS_io_uring_register, fd, IORING_REGISTER_RESIZE_RINGS,
	    &np, 1);
	if (r != 0) { rc = 3; goto close_ring; }
	if (np.sq_entries != 8 || np.cq_entries != 16 ||
	    !(np.flags & IORING_SETUP_NO_MMAP) ||
	    np.sq_off.addr != (u64)na || np.cq_off.addr != (u64)nb) {
		rc = 4; goto close_ring;
	}
	sqes = (u8 *)na; ring = (u8 *)nb;
	array = (u32 *)(ring + np.sq_off.array);
	tail = (u32 *)(ring + np.sq_off.tail);
	cqtail = (u32 *)(ring + np.cq_off.tail);
	c = (struct cqe *)(ring + np.cq_off.cqes);
	sqes[0] = 0; *(u64 *)(sqes + 32) = 0x7711;
	array[0] = 0;
	__atomic_store_n(tail, 1, __ATOMIC_RELEASE);
	r = sys6(SYS_io_uring_enter, fd, 1, 1, IORING_ENTER_GETEVENTS, 0, 0);
	if (r != 1 || __atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 1 ||
	    c[0].data != 0x7711 || c[0].res != 0)
		rc = 5;
close_ring:
	sys1(SYS_close, fd);
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	sys2(SYS_munmap, (void *)na, USER_REGION);
	sys2(SYS_munmap, (void *)nb, USER_REGION);
	return (rc);
}
static int
resize_invalid(void)
{
	struct params p, np;
	long a, b, na, nb, fd, r;
	int rc = 0;

	a = region(); b = region(); na = region(); nb = region();
	if (a < 0 || b < 0 || na < 0 || nb < 0)
		return (1);
	fd = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN);
	if (fd < 0) { rc = 2; goto out; }
	np = (struct params){0};np.sq_entries = 8;
	np.sq_off.addr = na;np.cq_off.addr = nb;
	r = sys4(SYS_io_uring_register, fd, IORING_REGISTER_RESIZE_RINGS,
	    &np, 0);
	if (r != -EINVAL) { rc = 3; goto close_ring; }
	np.flags = IORING_SETUP_NO_MMAP;
	r = sys4(SYS_io_uring_register, fd, IORING_REGISTER_RESIZE_RINGS,
	    &np, 1);
	if (r != -EINVAL) { rc = 4; goto close_ring; }
	np.flags = 0; np.sq_off.addr = 0;
	r = sys4(SYS_io_uring_register, fd, IORING_REGISTER_RESIZE_RINGS,
	    &np, 1);
	if (r != -EFAULT) { rc = 5; goto close_ring; }
	np.sq_off.addr = na + 1;
	r = sys4(SYS_io_uring_register, fd, IORING_REGISTER_RESIZE_RINGS,
	    &np, 1);
	if (r != -EINVAL) { rc = 6; goto close_ring; }
	np.sq_off.addr = na;
close_ring:
	sys1(SYS_close, fd);
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	sys2(SYS_munmap, (void *)na, USER_REGION);
	sys2(SYS_munmap, (void *)nb, USER_REGION);
	return (rc);
}
struct ring_update { u32 offset, resv; u64 data; };
static long
unregister_slot(long caller, u32 slot)
{
	struct ring_update up = {slot, 0, 0};
	return (sys4(SYS_io_uring_register, caller,
	    IORING_UNREGISTER_RING_FDS |
	    IORING_REGISTER_USE_REGISTERED_RING, &up, 1));
}
static int
registered_lifecycle(void)
{
	struct params p;
	struct cqe *c;
	u8 *sqes, *ring;
	u32 *array, *tail, *cqtail;
	long a, b, idx, r;
	int rc = 0;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	idx = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_REGISTERED_FD_ONLY);
	if (idx < 0) { rc = 2; goto out; }
	sqes = (u8 *)a; ring = (u8 *)b;
	array = (u32 *)(ring + p.sq_off.array);
	tail = (u32 *)(ring + p.sq_off.tail);
	cqtail = (u32 *)(ring + p.cq_off.tail);
	c = (struct cqe *)(ring + p.cq_off.cqes);
	sqes[0] = 0; *(u64 *)(sqes + 32) = 0x3344;
	array[0] = 0;
	__atomic_store_n(tail, 1, __ATOMIC_RELEASE);
	r = sys6(SYS_io_uring_enter, idx, 1, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_REGISTERED_RING, 0, 0);
	if (r != 1 || __atomic_load_n(cqtail, __ATOMIC_ACQUIRE) != 1 ||
	    c[0].data != 0x3344 || c[0].res != 0) { rc = 3; goto out; }
	if (unregister_slot(idx, (u32)idx) != 1) { rc = 4; goto out; }
	if (sys6(SYS_io_uring_enter, idx, 0, 0,
	    IORING_ENTER_REGISTERED_RING, 0, 0) != -EBADF)
		rc = 5;
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
registered_exhaustion(void)
{
	struct params p;
	long a, b, idx[16], r;
	int rc = 0, i;

	a = region(); b = region();
	if (a < 0 || b < 0)
		return (1);
	for (i = 0; i < 16; i++) {
		idx[i] = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
		    IORING_SETUP_REGISTERED_FD_ONLY);
		if (idx[i] != i) { rc = 2; goto out; }
	}
	r = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_REGISTERED_FD_ONLY);
	if (r != -EBUSY) { rc = 3; goto out; }
	for (i = 15; i >= 0; i--)
		if (unregister_slot(idx[i], (u32)idx[i]) != 1) {
			rc = 4; goto out;
		}
	r = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_REGISTERED_FD_ONLY);
	if (r != 0) { rc = 5; goto out; }
	if (unregister_slot(r, (u32)r) != 1)
		rc = 6;
out:
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
copyout_rollback(void)
{
	struct params *p;
	long a, b, m, r;
	int rc = 0, i;

	a = region(); b = region();
	m = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (a < 0 || b < 0 || m < 0)
		return (1);
	p = (struct params *)m;
	*p = (struct params){0};
	p->flags = IORING_SETUP_NO_MMAP | IORING_SETUP_REGISTERED_FD_ONLY;
	p->sq_off.addr = (u64)a;
	p->cq_off.addr = (u64)b;
	if (sys3(SYS_mprotect, p, PAGE, PROT_READ) != 0) {
		rc = 2; goto out;
	}
	for (i = 0; i < 20; i++)
		if (sys2(SYS_io_uring_setup, 4, p) != -EFAULT) {
			rc = 3; goto out;
		}
	if (sys3(SYS_mprotect, p, PAGE,
	    PROT_READ | PROT_WRITE) != 0) { rc = 4; goto out; }
	r = make_ring(p, a, b, IORING_SETUP_NO_MMAP |
	    IORING_SETUP_REGISTERED_FD_ONLY);
	if (r != 0) { rc = 5; goto out; }
	if (unregister_slot(r, (u32)r) != 1)
		rc = 6;
out:
	sys2(SYS_munmap, (void *)m, PAGE);
	sys2(SYS_munmap, (void *)a, USER_REGION);
	sys2(SYS_munmap, (void *)b, USER_REGION);
	return (rc);
}
static int
sqpoll_mode(int registered)
{
    struct params p;
    struct cqe *cq;
    struct { long sec, nsec; } pause = {0, 1000000};
    u8 *sqes, *ring;
    u32 *array, *sqtail, *cqhead, *cqtail;
    long a, b, fd, r;
    int i, j, rc = 0;
    u32 enter_flags = IORING_ENTER_SQ_WAKEUP |
        (registered ? IORING_ENTER_REGISTERED_RING : 0);

    a = region(); b = region();
    if (a < 0 || b < 0)
        return (1);
    fd = make_ring(&p, a, b, IORING_SETUP_NO_MMAP |
        IORING_SETUP_SQPOLL |
        (registered ? IORING_SETUP_REGISTERED_FD_ONLY : 0));
    if (fd < 0) { rc = 2; goto out; }
    sqes = (u8 *)a; ring = (u8 *)b;
    array = (u32 *)(ring + p.sq_off.array);
    sqtail = (u32 *)(ring + p.sq_off.tail);
    cqhead = (u32 *)(ring + p.cq_off.head);
    cqtail = (u32 *)(ring + p.cq_off.tail);
    cq = (struct cqe *)(ring + p.cq_off.cqes);
    if (p.sq_entries != 4 || p.cq_entries != 8 ||
        p.sq_off.addr != (u64)a || p.cq_off.addr != (u64)b) {
        rc = 3; goto close;
    }
    for (i = 0; i < 8; i++) {
        u32 slot = (u32)i & (p.sq_entries - 1);
        u8 *sqe = sqes + slot * 64;
        int k;
        for (k = 0; k < 64; k++) sqe[k] = 0;
        *(u64 *)(sqe + 32) = 0x6200 + i;
        array[slot] = slot;
        __atomic_store_n(sqtail, i + 1, __ATOMIC_RELEASE);
        r = sys6(SYS_io_uring_enter, fd, 0, 0, enter_flags, 0, 0);
        if (r != 0) { rc = 4; goto close; }
        for (j = 0; j < 2000; j++) {
            if (__atomic_load_n(cqtail, __ATOMIC_ACQUIRE) > (u32)i)
                break;
            sys2(SYS_nanosleep, &pause, 0);
        }
        if (j == 2000 || cq[i & (p.cq_entries - 1)].data !=
            (u64)(0x6200 + i) ||
            cq[i & (p.cq_entries - 1)].res != 0) {
            rc = 5; goto close;
        }
        __atomic_store_n(cqhead, i + 1, __ATOMIC_RELEASE);
    }
    if (registered) {
        if (sys6(SYS_io_uring_enter, fd, 0, 0,
            IORING_ENTER_SQ_WAKEUP, 0, 0) != -EOPNOTSUPP)
            rc = 6;
    } else if (sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
        MAP_SHARED, fd, 0) >= 0)
        rc = 7;
close:
    if (registered) {
        if (unregister_slot(fd, (u32)fd) != 1 && rc == 0)
            rc = 8;
        if (sys6(SYS_io_uring_enter, fd, 0, 0, enter_flags, 0, 0) !=
            -EBADF && rc == 0)
            rc = 9;
    } else
        sys1(SYS_close, fd);
out:
    sys2(SYS_munmap, (void *)a, USER_REGION);
    sys2(SYS_munmap, (void *)b, USER_REGION);
    return (rc);
}
static int sqpoll_nommap(void) { return (sqpoll_mode(0)); }
static int sqpoll_registered_only(void) { return (sqpoll_mode(1)); }
static const struct subtest cases[] = {
	{ "basic", basic },
	{ "layout_modes", layout_modes },
	{ "read_only", read_only },
	{ "unmap_lifetime", unmap_lifetime },
	{ "invalid_setup", invalid_setup },
	{ "registered_only", registered_only },
	{ "registered_lifecycle", registered_lifecycle },
	{ "registered_exhaustion", registered_exhaustion },
	{ "copyout_rollback", copyout_rollback },
	{ "resize_basic", resize_basic },
	{ "resize_invalid", resize_invalid },
	{ "sqpoll_nommap", sqpoll_nommap },
	{ "sqpoll_registered_only", sqpoll_registered_only },
};
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
