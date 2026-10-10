/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Binder reference tests, rewritten from Starnix binder_test.cc at
 * 8a938a3224e768f6254ee12d240b6492361ebccf. No Binder backend exists in
 * 5BSD yet. Run against a dedicated device in a disposable Linux binderfs
 * mount: probe DEVICE CASE. Never takes ownership of the context manager.
 */
#include "linux_test.h"

#if !defined(__x86_64__)
#error This reference probe targets the 64-bit Linux Binder ABI.
#endif

#define BINDER_WRITE_READ 0xc0306201UL
#define BINDER_VERSION 0xc0046209UL
#define BC_ENTER_LOOPER 0x630cU
#define MAP_LENGTH (128UL * 1024)

struct binder_write_read {
	u64 write_size, write_consumed, write_buffer;
	u64 read_size, read_consumed, read_buffer;
};
_Static_assert(sizeof(struct binder_write_read) == 48, "Binder64 write/read");
static const char *device;

static long
open_binder(void)
{
	return (sys3(SYS_open, device, O_RDWR | O_CLOEXEC, 0));
}

static int
version(void)
{
	long fd = open_binder();
	int protocol = -1, rc;

	if (fd < 0)
		return (1);
	rc = sys3(SYS_ioctl, fd, BINDER_VERSION, &protocol) == 0 &&
	    protocol == 8 ? 0 : 2;
	(void)sys1(SYS_close, fd);
	return (rc);
}

static int
commands(int mode)
{
	u32 buffer[2] = { ~0U, BC_ENTER_LOOPER };
	struct binder_write_read bwr = { 0 };
	long fd = open_binder(), result;
	int rc = 0;

	if (fd < 0)
		return (1);
	bwr.write_buffer = (u64)buffer;
	bwr.write_size = mode == 0 ? sizeof(u32) : sizeof(buffer);
	if (mode == 1) {
		buffer[0] = BC_ENTER_LOOPER;
		buffer[1] = ~0U;
	} else if (mode == 2)
		bwr.write_consumed = sizeof(u32);
	result = sys3(SYS_ioctl, fd, BINDER_WRITE_READ, &bwr);
	if (mode < 2) {
		if (result != -EINVAL || bwr.write_consumed !=
		    (mode == 0 ? 0 : sizeof(u32)))
			rc = 2;
	} else {
		if (result != 0 || bwr.write_consumed != sizeof(buffer) ||
		    bwr.write_size != sizeof(buffer))
			rc = 3;
		else if (sys3(SYS_ioctl, fd, BINDER_WRITE_READ, &bwr) != 0 ||
		    bwr.write_consumed != sizeof(buffer))
			rc = 4;
	}
	(void)sys1(SYS_close, fd);
	return (rc);
}

static int invalid_command(void) { return (commands(0)); }
static int valid_then_invalid(void) { return (commands(1)); }
static int already_consumed(void) { return (commands(2)); }

static int
mapping(int protect)
{
	long fd = open_binder(), addr;
	int rc = 0;

	if (fd < 0)
		return (1);
	addr = sys6(SYS_mmap, 0, MAP_LENGTH,
	    PROT_READ | (protect ? 0 : PROT_WRITE), MAP_PRIVATE, fd, 0);
	if (protect) {
		if (addr < 0)
			rc = 2;
		else if (sys3(SYS_mprotect, addr, MAP_LENGTH,
		    PROT_READ | PROT_WRITE) != -EACCES)
			rc = 3;
	} else if (addr != -EPERM)
		rc = 4;
	if (addr >= 0)
		(void)sys2(SYS_munmap, addr, MAP_LENGTH);
	(void)sys1(SYS_close, fd);
	return (rc);
}
static int mmap_write(void) { return (mapping(0)); }
static int mprotect_write(void) { return (mapping(1)); }

static int
inherited(int query)
{
	long fd, child, addr, waited;
	int status, rc = 0, protocol;

	for (int shared = 0; shared < (query ? 1 : 2); shared++) {
		int flags = shared ? MAP_SHARED : MAP_PRIVATE;
		fd = open_binder();
		if (fd < 0)
			return (1);
		child = sys0(SYS_fork);
		if (child == 0) {
			if (query) {
				protocol = -1;
				rc = sys3(SYS_ioctl, fd, BINDER_VERSION, &protocol) == 0 &&
				    protocol == 8 ? 0 : 2;
			} else {
				addr = sys6(SYS_mmap, 0, MAP_LENGTH, PROT_READ,
				    flags, fd, 0);
				rc = addr == -EINVAL ? 0 : 3;
				if (addr >= 0)
					(void)sys2(SYS_munmap, addr, MAP_LENGTH);
			}
			(void)sys1(SYS_exit_group, rc);
			__builtin_unreachable();
		}
		if (child < 0)
			rc = 4;
		else {
			do {
				waited = sys4(SYS_wait4, child, &status, 0, 0);
			} while (waited == -EINTR);
			if (waited != child || status != 0)
				rc = 5;
		}
		if (!query && rc == 0) {
			addr = sys6(SYS_mmap, 0, MAP_LENGTH, PROT_READ, flags, fd, 0);
			if (addr < 0)
				rc = 6;
			else
				(void)sys2(SYS_munmap, addr, MAP_LENGTH);
		}
		(void)sys1(SYS_close, fd);
		if (rc != 0)
			break;
	}
	return (rc);
}
static int inherited_mmap(void) { return (inherited(0)); }
static int inherited_ioctl(void) { return (inherited(1)); }

static int
test(int argc, char **argv, char **envp)
{
	static const struct subtest cases[] = {
		{ "version", version },
		{ "invalid_command", invalid_command },
		{ "valid_then_invalid", valid_then_invalid },
		{ "already_consumed", already_consumed },
		{ "mmap_write", mmap_write },
		{ "mprotect_write", mprotect_write },
		{ "inherited_mmap", inherited_mmap },
		{ "inherited_ioctl", inherited_ioctl },
	};
	(void)envp;
	if (argc != 3)
		return (100);
	device = argv[1];
	return (run_subtests(argc - 1, argv + 1, cases,
	    sizeof(cases) / sizeof(cases[0])));
}
