/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Linux reference only: the 5BSD x86-64 table leaves io_uring unimplemented.
 * Adapted test ideas from Fuchsia Starnix io_uring_test.cc at commit
 * 8a938a3224e768f6254ee12d240b6492361ebccf: READV/WRITEV and the
 * COOP_TASKRUN, SINGLE_ISSUER and DEFER_TASKRUN setup flags. Run on a
 * permissive Linux 6.1+ guest before using these as a 5BSD conformance gate.
 */
#include "linux_test.h"

#if !defined(__x86_64__)
#error This reference probe targets Linux x86-64.
#endif

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define IORING_SETUP_COOP_TASKRUN (1U << 8)
#define IORING_SETUP_SINGLE_ISSUER (1U << 12)
#define IORING_SETUP_DEFER_TASKRUN (1U << 13)
#define IORING_FEAT_SINGLE_MMAP 1U
#define IORING_ENTER_GETEVENTS 1U
#define IORING_OFF_SQ_RING 0UL
#define IORING_OFF_CQ_RING 0x8000000UL
#define IORING_OFF_SQES 0x10000000UL
#define IORING_OP_READV 1
#define IORING_OP_WRITEV 2

struct io_sqring_offsets {
	u32 head, tail, ring_mask, ring_entries, flags, dropped, array, resv1;
	u64 user_addr;
};
struct io_cqring_offsets {
	u32 head, tail, ring_mask, ring_entries, overflow, cqes, flags, resv1;
	u64 user_addr;
};
struct io_uring_params {
	u32 sq_entries, cq_entries, flags, sq_thread_cpu, sq_thread_idle;
	u32 features, wq_fd, resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};
struct io_uring_sqe {
	u8 opcode, flags;
	u16 ioprio;
	int fd;
	u64 off, addr;
	u32 len, rw_flags;
	u64 user_data;
	u16 buf_index, personality;
	int splice_fd_in;
	u64 addr3, pad2;
};
struct io_uring_cqe {
	u64 user_data;
	int res;
	u32 flags;
};

_Static_assert(sizeof(struct io_uring_params) == 120, "params ABI");
_Static_assert(sizeof(struct io_uring_sqe) == 64, "SQE ABI");
_Static_assert(sizeof(struct io_uring_cqe) == 16, "CQE ABI");

static long
setup(u32 entries, struct io_uring_params *p)
{
	return (sys2(SYS_io_uring_setup, entries, p));
}

static int
setup_flags(void)
{
	struct io_uring_params p = { 0 };
	long fd;

	p.flags = IORING_SETUP_COOP_TASKRUN;
	fd = setup(1, &p);
	if (fd < 0)
		return (1);
	(void)sys1(SYS_close, fd);
	p = (struct io_uring_params){ 0 };
	p.flags = IORING_SETUP_SINGLE_ISSUER;
	fd = setup(1, &p);
	if (fd < 0)
		return (2);
	(void)sys1(SYS_close, fd);
	p = (struct io_uring_params){ 0 };
	p.flags = IORING_SETUP_DEFER_TASKRUN;
	if (setup(1, &p) != -EINVAL)
		return (3);
	p = (struct io_uring_params){ 0 };
	p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
	fd = setup(1, &p);
	if (fd < 0)
		return (4);
	(void)sys1(SYS_close, fd);
	return (0);
}

static int
invalid_setup(void)
{
	struct io_uring_params p = { 0 };

	if (setup(0, &p) != -EINVAL)
		return (1);
	p = (struct io_uring_params){ 0 };
	p.resv[0] = 1;
	if (setup(1, &p) != -EINVAL)
		return (2);
	return (0);
}

static int
submit_one(long ringfd, const struct io_uring_params *p, char *sq,
    char *cq, struct io_uring_sqe *sqes, u8 opcode, long fd,
    struct iovec *iov, u64 user_data)
{
	u32 *sq_tail, *sq_mask, *sq_array, *cq_head, *cq_tail, *cq_mask;
	struct io_uring_cqe *cqes;
	u32 tail, head, index;
	struct io_uring_sqe *sqe;

	sq_tail = (u32 *)(sq + p->sq_off.tail);
	sq_mask = (u32 *)(sq + p->sq_off.ring_mask);
	sq_array = (u32 *)(sq + p->sq_off.array);
	cq_head = (u32 *)(cq + p->cq_off.head);
	cq_tail = (u32 *)(cq + p->cq_off.tail);
	cq_mask = (u32 *)(cq + p->cq_off.ring_mask);
	cqes = (struct io_uring_cqe *)(cq + p->cq_off.cqes);
	tail = __atomic_load_n(sq_tail, __ATOMIC_ACQUIRE);
	index = tail & *sq_mask;
	sqe = &sqes[index];
	xmemset(sqe, 0, sizeof(*sqe));
	sqe->opcode = opcode;
	sqe->fd = (int)fd;
	sqe->addr = (u64)iov;
	sqe->len = 1;
	sqe->off = 0;
	sqe->user_data = user_data;
	sq_array[index] = index;
	__atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);
	if (sys6(SYS_io_uring_enter, ringfd, 1, 1,
	    IORING_ENTER_GETEVENTS, 0, 0) != 1)
		return (1);
	head = __atomic_load_n(cq_head, __ATOMIC_ACQUIRE);
	if (__atomic_load_n(cq_tail, __ATOMIC_ACQUIRE) - head != 1)
		return (2);
	index = head & *cq_mask;
	if (cqes[index].user_data != user_data ||
	    cqes[index].res != (int)iov->iov_len)
		return (3);
	__atomic_store_n(cq_head, head + 1, __ATOMIC_RELEASE);
	return (0);
}

static int
readv_writev(void)
{
	struct io_uring_params p = { 0 };
	struct io_uring_sqe *sqes;
	struct iovec wiov, riov;
	char written[] = "hello", readback[sizeof(written)];
	char *sq, *cq;
	long ringfd, memfd, sqaddr, cqaddr, sqeaddr;
	size_t sqlen, cqlen, sqelen;
	int rc;

	ringfd = setup(2, &p);
	if (ringfd < 0 || p.sq_entries < 2 || p.cq_entries < 2 ||
	    (p.features & IORING_FEAT_SINGLE_MMAP) == 0)
		return (1);
	memfd = sys2(SYS_memfd_create, "io-uring-reference", 0);
	if (memfd < 0)
		return (2);
	sqlen = p.sq_off.array + p.sq_entries * sizeof(u32);
	cqlen = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	sqelen = p.sq_entries * sizeof(struct io_uring_sqe);
	sqaddr = sys6(SYS_mmap, 0, sqlen, PROT_READ | PROT_WRITE,
	    MAP_SHARED, ringfd, IORING_OFF_SQ_RING);
	cqaddr = sys6(SYS_mmap, 0, cqlen, PROT_READ | PROT_WRITE,
	    MAP_SHARED, ringfd, IORING_OFF_CQ_RING);
	sqeaddr = sys6(SYS_mmap, 0, sqelen, PROT_READ | PROT_WRITE,
	    MAP_SHARED, ringfd, IORING_OFF_SQES);
	if (sqaddr < 0 || cqaddr < 0 || sqeaddr < 0)
		return (3);
	sq = (char *)sqaddr;
	cq = (char *)cqaddr;
	sqes = (struct io_uring_sqe *)sqeaddr;
	wiov = (struct iovec){ .iov_base = written,
	    .iov_len = sizeof(written) };
	riov = (struct iovec){ .iov_base = readback,
	    .iov_len = sizeof(readback) };
	rc = submit_one(ringfd, &p, sq, cq, sqes, IORING_OP_WRITEV,
	    memfd, &wiov, 1);
	if (rc != 0)
		return (4 + rc);
	xmemset(readback, 0, sizeof(readback));
	rc = submit_one(ringfd, &p, sq, cq, sqes, IORING_OP_READV,
	    memfd, &riov, 2);
	if (rc != 0)
		return (8 + rc);
	for (size_t i = 0; i < sizeof(written); i++)
		if (readback[i] != written[i])
			return (12);
	(void)sys2(SYS_munmap, (long)sq, sqlen);
	(void)sys2(SYS_munmap, (long)cq, cqlen);
	(void)sys2(SYS_munmap, (long)sqes, sqelen);
	(void)sys1(SYS_close, memfd);
	(void)sys1(SYS_close, ringfd);
	return (0);
}

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "setup_flags", setup_flags },
		{ "invalid_setup", invalid_setup },
		{ "readv_writev", readv_writev },
	};

	(void)envp;
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
