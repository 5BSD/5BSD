/* SPDX-License-Identifier: BSD-2-Clause */
/* Pinned Linux 6.18 IORING_REGISTER_MEM_REGION contract. */
#include "linux_test.h"

#define SYS_io_uring_setup 425
#define SYS_io_uring_enter 426
#define SYS_io_uring_register 427
#define IORING_REGISTER_ENABLE_RINGS 12
#define IORING_REGISTER_MEM_REGION 34
#define IORING_SETUP_R_DISABLED (1U << 6)
#define IORING_ENTER_GETEVENTS (1U << 0)
#define IORING_ENTER_EXT_ARG (1U << 3)
#define IORING_ENTER_EXT_ARG_REG (1U << 6)
#define IORING_MEM_REGION_REG_WAIT_ARG 1
#define IORING_REG_WAIT_TS 1
#define ETIME 62

struct region_desc {
	u64 user_addr;
	u64 size;
	u32 flags;
	u32 id;
	u64 mmap_offset;
	u64 resv[4];
};
struct region_reg {
	u64 region_uptr;
	u64 flags;
	u64 resv[2];
};
struct kernel_timespec { long tv_sec, tv_nsec; };
struct reg_wait {
	struct kernel_timespec ts;
	u32 min_wait_usec, flags;
	u64 sigmask;
	u32 sigmask_sz, pad[3];
	u64 pad2[2];
};
struct sqoff { u32 head, tail, mask, entries, flags, dropped, array, resv; u64 addr; };
struct cqoff { u32 head, tail, mask, entries, overflow, cqes, flags, resv; u64 addr; };
struct params {
	u32 sq_entries, cq_entries, flags, cpu, idle, features, wq_fd, resv[3];
	struct sqoff sq_off;
	struct cqoff cq_off;
};
_Static_assert(sizeof(struct region_desc) == 64, "region desc ABI");
_Static_assert(sizeof(struct region_reg) == 32, "region reg ABI");
_Static_assert(sizeof(struct reg_wait) == 64, "registered wait ABI");

static long
setup(u32 flags)
{
	struct params p = {0};
	p.flags = flags;
	return (sys2(SYS_io_uring_setup, 4, &p));
}
static long
reg(long fd, struct region_reg *r, u32 nr)
{
	return (sys4(SYS_io_uring_register, fd,
	    IORING_REGISTER_MEM_REGION, r, nr));
}
static void
init_region(struct region_reg *r, struct region_desc *d, u64 flags)
{
	*r = (struct region_reg){0};
	*d = (struct region_desc){0};
	r->region_uptr = (u64)d;
	r->flags = flags;
	d->size = PAGE;
}
static int
invalid_registration(void)
{
	struct region_reg r;
	struct region_desc d;
	long fd;
	int rc = 0;

	fd = setup(0);
	if (fd < 0)
		return (1);
	init_region(&r, &d, 0);
	if (reg(fd, 0, 1) != -EINVAL || reg(fd, &r, 0) != -EINVAL ||
	    reg(fd, &r, 2) != -EINVAL) {
		rc = 2;
		goto done;
	}
	r.region_uptr = 1;
	if (reg(fd, &r, 1) != -EFAULT) {
		rc = 3;
		goto done;
	}
	init_region(&r, &d, 0);
	r.resv[0] = 1;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 4;
		goto done;
	}
	init_region(&r, &d, 0);
	r.flags = 2;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 5;
		goto done;
	}
	init_region(&r, &d, IORING_MEM_REGION_REG_WAIT_ARG);
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 6;
		goto done;
	}
	init_region(&r, &d, 0);
	d.flags = 2;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 7;
		goto done;
	}
	init_region(&r, &d, 0);
	d.id = 1;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 8;
		goto done;
	}
	init_region(&r, &d, 0);
	d.resv[0] = 1;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 9;
		goto done;
	}
	init_region(&r, &d, 0);
	d.size = 0;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 10;
		goto done;
	}
	init_region(&r, &d, 0);
	d.size = 1;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 11;
		goto done;
	}
	init_region(&r, &d, 0);
	d.size = PAGE + 1;
	if (reg(fd, &r, 1) != -EINVAL) {
		rc = 12;
		goto done;
	}
	init_region(&r, &d, 0);
	d.user_addr = 1;
	if (reg(fd, &r, 1) != -EFAULT) {
		rc = 13;
		goto done;
	}
	init_region(&r, &d, 0);
	d.flags = 1;
	if (reg(fd, &r, 1) != -EFAULT) {
		rc = 14;
		goto done;
	}
	init_region(&r, &d, 0);
	if (reg(fd, &r, 1) != 0)
		rc = 15;
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
basic_mapping(void)
{
	struct region_reg r;
	struct region_desc d;
	volatile u64 *map;
	long fd, ret;
	int rc = 0;

	fd = setup(0);
	if (fd < 0)
		return (1);
	init_region(&r, &d, 0);
	if (reg(fd, &r, 1) != 0) {
		rc = 2;
		goto done;
	}
	if (d.mmap_offset == 0 || d.size != PAGE || d.id != 0) {
		rc = 3;
		goto done;
	}
	ret = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, d.mmap_offset);
	if (ret < 0) {
		rc = 4;
		goto done;
	}
	map = (volatile u64 *)ret;
	map[0] = 0x123456789abcdef0UL;
	map[PAGE / sizeof(*map) - 1] = 0xfedcba9876543210UL;
	if (map[0] != 0x123456789abcdef0UL ||
	    map[PAGE / sizeof(*map) - 1] != 0xfedcba9876543210UL)
		rc = 5;
	sys2(SYS_munmap, map, PAGE);
	if (reg(fd, &r, 1) != -EBUSY)
		rc = 6;
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
wait_region(void)
{
	struct region_reg r;
	struct region_desc d;
	struct reg_wait *w;
	long fd, addr, ret;
	int rc = 0;

	fd = setup(IORING_SETUP_R_DISABLED);
	if (fd < 0)
		return (1);
	init_region(&r, &d, IORING_MEM_REGION_REG_WAIT_ARG);
	if (reg(fd, &r, 1) != 0) {
		rc = 2;
		goto done;
	}
	addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, d.mmap_offset);
	if (addr < 0) {
		rc = 3;
		goto done;
	}
	w = (struct reg_wait *)addr;
	*w = (struct reg_wait){0};
	w->flags = IORING_REG_WAIT_TS;
	w->ts.tv_nsec = 1000000;
	ret = sys4(SYS_io_uring_register, fd, IORING_REGISTER_ENABLE_RINGS,
	    0, 0);
	if (ret != 0)
		rc = 4;
	else {
		ret = sys6(SYS_io_uring_enter, fd, 0, 1,
		    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
		    IORING_ENTER_EXT_ARG_REG, 0, sizeof(*w));
		if (ret != -ETIME)
			rc = 5;
	}
	sys2(SYS_munmap, w, PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
user_backing(void)
{
	struct region_reg r;
	struct region_desc d;
	struct reg_wait *w;
	long fd, addr, ret;
	int rc = 0;

	fd = setup(IORING_SETUP_R_DISABLED);
	if (fd < 0)
		return (1);
	addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0) {
		rc = 2;
		goto done;
	}
	init_region(&r, &d, IORING_MEM_REGION_REG_WAIT_ARG);
	d.flags = 1;
	d.user_addr = addr;
	if (reg(fd, &r, 1) != 0 || d.mmap_offset != 0) {
		rc = 3;
		goto unmap;
	}
	w = (struct reg_wait *)addr;
	*w = (struct reg_wait){0};
	w->flags = IORING_REG_WAIT_TS;
	w->ts.tv_nsec = 1000000;
	if (sys4(SYS_io_uring_register, fd,
	    IORING_REGISTER_ENABLE_RINGS, 0, 0) != 0) {
		rc = 4;
		goto unmap;
	}
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, 0, sizeof(*w));
	if (ret != -ETIME)
		rc = 5;
unmap:
	sys2(SYS_munmap, (void *)addr, PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
copyout_rollback(void)
{
	struct region_reg r;
	struct region_desc *d;
	long fd, addr;
	int rc = 0;

	fd = setup(0);
	if (fd < 0)
		return (1);
	addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0) {
		rc = 2;
		goto done;
	}
	d = (struct region_desc *)addr;
	init_region(&r, d, 0);
	if (sys3(SYS_mprotect, d, PAGE, PROT_READ) != 0) {
		rc = 3;
		goto unmap;
	}
	if (reg(fd, &r, 1) != -EFAULT) {
		rc = 4;
		goto unmap;
	}
	if (sys3(SYS_mprotect, d, PAGE, PROT_READ | PROT_WRITE) != 0) {
		rc = 5;
		goto unmap;
	}
	if (reg(fd, &r, 1) != 0 || d->mmap_offset == 0)
		rc = 6;
unmap:
	sys2(SYS_munmap, (void *)addr, PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
wait_invalid(void)
{
	struct region_reg r;
	struct region_desc d;
	struct reg_wait *w;
	long fd, addr, ret;
	int rc = 0;

	fd = setup(IORING_SETUP_R_DISABLED);
	if (fd < 0)
		return (1);
	init_region(&r, &d, IORING_MEM_REGION_REG_WAIT_ARG);
	if (reg(fd, &r, 1) != 0) {
		rc = 2;
		goto done;
	}
	addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, d.mmap_offset);
	if (addr < 0) {
		rc = 3;
		goto done;
	}
	w = (struct reg_wait *)addr;
	*w = (struct reg_wait){0};
	w->flags = 2;
	if (sys4(SYS_io_uring_register, fd,
	    IORING_REGISTER_ENABLE_RINGS, 0, 0) != 0) {
		rc = 4;
		goto unmap;
	}
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, 0, sizeof(*w));
	if (ret != -EINVAL) {
		rc = 5;
		goto unmap;
	}
	w->flags = IORING_REG_WAIT_TS;
	w->ts.tv_nsec = 1000000;
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, 0, 0);
	if (ret != -EINVAL) {
		rc = 6;
		goto unmap;
	}
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, 1, sizeof(*w));
	if (ret != -EFAULT) {
		rc = 7;
		goto unmap;
	}
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, PAGE, sizeof(*w));
	if (ret != -EFAULT)
		rc = 8;
unmap:
	sys2(SYS_munmap, w, PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
user_unmap_lifetime(void)
{
	struct region_reg r;
	struct region_desc d;
	struct reg_wait *w;
	long fd, addr, ret;
	int rc = 0;

	fd = setup(IORING_SETUP_R_DISABLED);
	if (fd < 0)
		return (1);
	addr = sys6(SYS_mmap, 0, PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0) {
		rc = 2;
		goto done;
	}
	w = (struct reg_wait *)addr;
	*w = (struct reg_wait){0};
	w->flags = IORING_REG_WAIT_TS;
	w->ts.tv_nsec = 1000000;
	init_region(&r, &d, IORING_MEM_REGION_REG_WAIT_ARG);
	d.flags = 1;
	d.user_addr = addr;
	if (reg(fd, &r, 1) != 0) {
		rc = 3;
		goto unmap;
	}
	if (sys2(SYS_munmap, (void *)addr, PAGE) != 0) {
		rc = 4;
		goto done;
	}
	if (sys4(SYS_io_uring_register, fd,
	    IORING_REGISTER_ENABLE_RINGS, 0, 0) != 0) {
		rc = 5;
		goto done;
	}
	ret = sys6(SYS_io_uring_enter, fd, 0, 1,
	    IORING_ENTER_GETEVENTS | IORING_ENTER_EXT_ARG |
	    IORING_ENTER_EXT_ARG_REG, 0, sizeof(*w));
	if (ret != -ETIME)
		rc = 6;
	goto done;
unmap:
	sys2(SYS_munmap, (void *)addr, PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static int
protected_inputs(void)
{
	struct region_reg *r;
	struct region_desc *d;
	u8 *pages;
	long fd, addr;
	int rc = 0;

	fd = setup(0);
	if (fd < 0)
		return (1);
	addr = sys6(SYS_mmap, 0, 2 * PAGE, PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (addr < 0) {
		rc = 2;
		goto done;
	}
	pages = (u8 *)addr;
	r = (struct region_reg *)pages;
	d = (struct region_desc *)(pages + PAGE - sizeof(*d) / 2);
	*r = (struct region_reg){0};
	r->region_uptr = (u64)d;
	if (sys3(SYS_mprotect, pages + PAGE, PAGE, PROT_NONE) != 0) {
		rc = 3;
		goto unmap;
	}
	if (reg(fd, r, 1) != -EFAULT) {
		rc = 4;
		goto unmap;
	}
	r = (struct region_reg *)(pages + PAGE - sizeof(*r) / 2);
	if (reg(fd, r, 1) != -EFAULT)
		rc = 5;
unmap:
	sys2(SYS_munmap, pages, 2 * PAGE);
done:
	sys1(SYS_close, fd);
	return (rc);
}
static const struct subtest cases[] = {
	{ "basic_mapping", basic_mapping },
	{ "wait_region", wait_region },
	{ "invalid_registration", invalid_registration },
	{ "user_backing", user_backing },
	{ "copyout_rollback", copyout_rollback },
	{ "wait_invalid", wait_invalid },
	{ "user_unmap_lifetime", user_unmap_lifetime },
	{ "protected_inputs", protected_inputs },
};
static int
test(int argc, char **argv, char **envp __attribute__((unused)))
{
	return (run_subtests(argc, argv, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
