/* SPDX-License-Identifier: BSD-2-Clause */
/* Pinned Linux 6.18 IORING_REGISTER_QUERY ABI and failure contract. */
#include "linux_test.h"

#define SYS_io_uring_setup 425
#define SYS_io_uring_register 427
#define IORING_REGISTER_QUERY 35
#define EFAULT 14
#define EINVAL 22
#define EBADF 9
#define EOPNOTSUPP 95
#define ERANGE 34

struct query_hdr {
	u64 next_entry;
	u64 query_data;
	u32 query_op;
	u32 size;
	int result;
	u32 resv[3];
};
struct query_opcodes {
	u32 nr_request_opcodes;
	u32 nr_register_opcodes;
	u64 feature_flags;
	u64 ring_setup_flags;
	u64 enter_flags;
	u64 sqe_flags;
	u32 nr_query_opcodes;
	u32 pad;
};
struct sqoff { u32 head, tail, mask, entries, flags, dropped, array, resv; u64 addr; };
struct cqoff { u32 head, tail, mask, entries, overflow, cqes, flags, resv; u64 addr; };
struct params {
	u32 sq_entries, cq_entries, flags, cpu, idle, features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
_Static_assert(sizeof(struct query_hdr) == 40, "query header ABI");
_Static_assert(sizeof(struct query_opcodes) == 48, "query data ABI");
static long
query(long fd, struct query_hdr *hdr, u32 nr)
{
	return (sys4(SYS_io_uring_register, fd, IORING_REGISTER_QUERY,
	    hdr, nr));
}
static void
init_query(struct query_hdr *hdr, struct query_opcodes *out, u32 size)
{
	*hdr = (struct query_hdr){0};
	*out = (struct query_opcodes){0};
	hdr->query_data = (u64)out;
	hdr->size = size;
}
static int
blind_basic(void)
{
	struct query_hdr h;
	struct query_opcodes out;

	init_query(&h, &out, sizeof(out));
	if (query(-1, &h, 0) != 0 || h.result != 0 ||
	    h.size != sizeof(out) || out.nr_request_opcodes < 50 ||
	    out.nr_register_opcodes < 36 || out.nr_query_opcodes != 1 ||
	    out.pad != 0 || out.feature_flags == 0 ||
	    out.ring_setup_flags == 0 || out.enter_flags == 0 ||
	    out.sqe_flags == 0)
		return (1);
	return (0);
}
static int
fd_and_count(void)
{
	struct params p = {0};
	struct query_hdr h;
	struct query_opcodes out;
	long ring, regular;
	int error = 0;

	init_query(&h, &out, sizeof(out));
	if (query(-1, 0, 0) != 0 || query(-1, 0, 1) != -EINVAL)
		return (1);
	if (query(-1, &h, 1) != -EINVAL)
		return (2);
	ring = sys2(SYS_io_uring_setup, 4, &p);
	if (ring < 0)
		return (3);
	init_query(&h, &out, sizeof(out));
	if (query(ring, &h, 0) != 0 || h.result != 0 ||
	    h.size != sizeof(out))
		error = 4;
	if (query(ring, &h, 1) != -EINVAL)
		error = 5;
	if (query(999999, &h, 0) != -EBADF)
		error = 6;
	regular = sys3(SYS_openat, -100, ".", 0);
	if (regular < 0)
		error = 7;
	else {
		if (query(regular, &h, 0) != -EOPNOTSUPP)
			error = 8;
		sys1(SYS_close, regular);
	}
	sys1(SYS_close, ring);
	return (error);
}
static int
linked_headers(void)
{
	struct query_hdr a, b;
	struct query_opcodes x, y;

	init_query(&a, &x, sizeof(x));
	init_query(&b, &y, sizeof(y));
	a.next_entry = (u64)&b;
	if (query(-1, &a, 0) != 0 || a.result != 0 || b.result != 0 ||
	    a.size != sizeof(x) || b.size != sizeof(y) ||
	    x.nr_query_opcodes != 1 || y.nr_query_opcodes != 1 ||
	    x.nr_request_opcodes != y.nr_request_opcodes)
		return (1);
	return (0);
}
static int
invalid_entries(void)
{
	struct query_hdr h;
	struct query_opcodes out;

	init_query(&h, &out, sizeof(out));
	h.query_op = 1;
	out.nr_request_opcodes = 0xdeadbeef;
	if (query(-1, &h, 0) != 0 || h.result != -EOPNOTSUPP ||
	    h.size != 0 || out.nr_request_opcodes != 0)
		return (1);
	init_query(&h, &out, sizeof(out));
	h.resv[1] = 1;
	if (query(-1, &h, 0) != 0 || h.result != -EINVAL || h.size != 0)
		return (2);
	init_query(&h, &out, sizeof(out));
	h.result = 1;
	if (query(-1, &h, 0) != 0 || h.result != -EINVAL || h.size != 0)
		return (3);
	init_query(&h, &out, 0);
	if (query(-1, &h, 0) != 0 || h.result != -EINVAL || h.size != 0)
		return (4);
	return (0);
}
static int
sizes_and_faults(void)
{
	struct query_hdr h;
	struct query_opcodes out;
	u8 large[96];
	u8 oversized[8192];
	u32 *words = (u32 *)large;
	u32 i;

	init_query(&h, &out, sizeof(out));
	if (query(-1, (void *)1, 0) != -EFAULT)
		return (1);
	h.query_data = 1;
	if (query(-1, &h, 0) != -EFAULT)
		return (2);
	for (i = 0; i < sizeof(oversized); i++)
		oversized[i] = 0xa5;
	init_query(&h, &out, 4097);
	h.query_data = (u64)oversized;
	if (query(-1, &h, 0) != 0 || h.result != 0 ||
	    h.size != sizeof(out))
		return (3);
	for (i = sizeof(out); i < 4097; i++)
		if (oversized[i] != 0)
			return (7);
	init_query(&h, &out, 8);
	if (query(-1, &h, 0) != 0 || h.result != 0 || h.size != 8 ||
	    out.nr_request_opcodes < 50 || out.nr_register_opcodes < 36)
		return (4);
	for (i = 0; i < sizeof(large); i++)
		large[i] = 0xa5;
	h = (struct query_hdr){0};
	h.query_data = (u64)large;
	h.size = sizeof(large);
	if (query(-1, &h, 0) != 0 || h.result != 0 ||
	    h.size != sizeof(out) || words[0] < 50 || words[1] < 36)
		return (5);
	for (i = sizeof(out); i < sizeof(large); i++)
		if (large[i] != 0)
			return (6);
	return (0);
}
static int
cycle_limit(void)
{
	struct query_hdr h;
	struct query_opcodes out;

	init_query(&h, &out, sizeof(out));
	h.next_entry = (u64)&h;
	if (query(-1, &h, 0) != -ERANGE || h.result != 0 ||
	    h.size != sizeof(out))
		return (1);
	return (0);
}
static int
protected_pages(void)
{
	struct query_hdr *h;
	struct query_opcodes *out;
	u8 *pages;
	long addr;
	int rc;

	addr = sys6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0)
		return (1);
	pages = (u8 *)addr;
	h = (struct query_hdr *)(pages + PAGE);
	out = (struct query_opcodes *)pages;
	init_query(h, out, sizeof(*out));
	if (sys3(SYS_mprotect, pages, PAGE, PROT_READ) != 0) {
		rc = 2;
		goto done;
	}
	if (query(-1, h, 0) != -EFAULT || h->result != 0 ||
	    h->size != sizeof(*out)) {
		rc = 3;
		goto done;
	}
	if (sys3(SYS_mprotect, pages, PAGE, PROT_READ | PROT_WRITE) != 0) {
		rc = 4;
		goto done;
	}
	h = (struct query_hdr *)pages;
	out = (struct query_opcodes *)(pages + PAGE);
	init_query(h, out, sizeof(*out));
	if (sys3(SYS_mprotect, pages, PAGE, PROT_READ) != 0) {
		rc = 5;
		goto done;
	}
	if (query(-1, h, 0) != -EFAULT || h->size != sizeof(*out)) {
		rc = 6;
		goto done;
	}
	if (sys3(SYS_mprotect, pages, PAGE, PROT_READ | PROT_WRITE) != 0 ||
	    sys3(SYS_mprotect, pages + PAGE, PAGE, PROT_NONE) != 0) {
		rc = 7;
		goto done;
	}
	h = (struct query_hdr *)(pages + PAGE - sizeof(*h) / 2);
	if (query(-1, h, 0) != -EFAULT) {
		rc = 8;
		goto done;
	}
	h = (struct query_hdr *)pages;
	out = (struct query_opcodes *)(pages + PAGE - sizeof(*out) / 2);
	*h = (struct query_hdr){0};
	h->query_data = (u64)out;
	h->size = sizeof(*out);
	if (query(-1, h, 0) != -EFAULT) {
		rc = 9;
		goto done;
	}
	rc = 0;
done:
	sys2(SYS_munmap, pages, 2 * PAGE);
	return (rc);
}
static const struct subtest cases[] = {
	{ "blind_basic", blind_basic },
	{ "fd_and_count", fd_and_count },
	{ "linked_headers", linked_headers },
	{ "invalid_entries", invalid_entries },
	{ "sizes_and_faults", sizes_and_faults },
	{ "cycle_limit", cycle_limit },
	{ "protected_pages", protected_pages },
};
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
