/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Guest child ledger (dtraced_child_ledger.cc, actual object) with real
 * pdfork(2) children. Kernel interfaces the host may lack are injected:
 * kern.boot_id, PDIOC_GET_BIRTH_IDENTITY and pdopenpid(2) answer from a
 * table describing this test's own children, so a "reused PID" or "other
 * boot" is simulated without touching unrelated processes.
 *
 * Oracles: after recover_guest_children() each recorded child is dead
 * exactly when its record matches the live birth identity from this boot;
 * a mismatched (reused) or earlier-boot record never signals the process;
 * every resolved record is removed; the empty ledger marker exists only
 * after a complete recovery; malformed ledgers fail closed with EPROTO and
 * leave every child alive.
 */
#include <sys/procdesc.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <cstdarg>
#include <map>
#include <string>
#include <vector>
#include "daemon-harness.h"
#include "dtraced_child_ledger.h"

using namespace dtraced;

struct child_info {
	int pd = -1;
	uint64_t start_sec = 0, start_usec = 0;
	int birth_errno = 0;	/* PDIOC_GET_BIRTH_IDENTITY failure */
};
static std::map<pid_t, child_info> table;
static uint8_t boot_id[16] = {0xb0, 0x07};
static int boot_mode;	/* 0 normal, 1 sysctl fails, 2 short */
static int pdopen_busy;	/* EBUSY answers before the descriptor */
static int pdopen_errno;	/* forced pdopenpid failure */

extern "C" int __real_sysctlbyname(const char *, void *, size_t *,
    const void *, size_t);
extern "C" int
__wrap_sysctlbyname(const char *name, void *old, size_t *len, const void *n,
    size_t nl)
{
	if (strcmp(name, "kern.boot_id") != 0)
		return (__real_sysctlbyname(name, old, len, n, nl));
	if (boot_mode == 1) {
		errno = ENOENT;
		return (-1);
	}
	size_t give = boot_mode == 2 ? 8 : 16;
	memcpy(old, boot_id, give);
	*len = give;
	return (0);
}

extern "C" int
__wrap_pdopenpid(pid_t pid, int)
{
	if (pdopen_errno) {
		errno = pdopen_errno;
		return (-1);
	}
	if (pdopen_busy > 0) {
		--pdopen_busy;
		errno = EBUSY;
		return (-1);
	}
	auto it = table.find(pid);
	if (it == table.end() || it->second.pd < 0) {
		errno = ESRCH;
		return (-1);
	}
	return (fcntl(it->second.pd, F_DUPFD_CLOEXEC, 0));
}

extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int
__wrap_ioctl(int fd, unsigned long request, ...)
{
	va_list ap;
	va_start(ap, request);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (request != PDIOC_GET_BIRTH_IDENTITY)
		return (__real_ioctl(fd, request, arg));
	pid_t pid;
	if (pdgetpid(fd, &pid) != 0)
		return (-1);
	auto it = table.find(pid);
	if (it == table.end()) {
		errno = ESRCH;
		return (-1);
	}
	if (it->second.birth_errno) {
		errno = it->second.birth_errno;
		return (-1);
	}
	auto *b = static_cast<pd_birth_identity *>(arg);
	*b = {pid, 0, it->second.start_sec, it->second.start_usec};
	return (0);
}

static pid_t
spawn(uint64_t sec = 1000, uint64_t usec = 5)
{
	int pd;
	fflush(nullptr);
	pid_t pid = pdfork(&pd, PD_CLOEXEC);
	CHECK(pid >= 0);
	if (pid == 0) {
		sleep(30);
		_exit(0);
	}
	table[pid] = {pd, sec, usec, 0};
	return (pid);
}

static bool
alive(pid_t pid)
{
	return (kill(pid, 0) == 0);
}

static void
reap_all()
{
	for (auto &[pid, c] : table) {
		if (c.pd >= 0) {
			(void)pdkill(c.pd, SIGKILL);
			int st;
			(void)pdwait(c.pd, &st, WEXITED, nullptr, nullptr);
			close(c.pd);
		}
	}
	table.clear();
}

static bool
exists(int dirfd, const std::string &name)
{
	struct stat st;
	return (fstatat(dirfd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) == 0);
}

static std::string
child_file(pid_t pid)
{
	return (".child." + std::to_string(pid));
}

struct ledger {
	temp_tree tree{"child-ledger"};
	int fd;
	ledger() { fd = open(tree.sub("inbound").c_str(), O_RDONLY | O_DIRECTORY); CHECK(fd >= 0); }
	~ledger() { close(fd); reap_all(); }
	void raw(const std::string &name, const void *data, size_t n)
	{
		int f = openat(fd, name.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
		CHECK(f >= 0 && write(f, data, n) == (ssize_t)n && close(f) == 0);
	}
	void marker() { raw(".child-ledger-v1", "", 0); }
};

/* The fixed 48-byte record, written independently. */
static std::vector<uint8_t>
record_bytes(pid_t pid, uint64_t sec, uint64_t usec, const uint8_t boot[16],
    uint64_t magic = UINT64_C(0x31444c4948435444), uint32_t reserved = 0)
{
	std::vector<uint8_t> r(48, 0);
	memcpy(&r[0], &magic, 8);
	memcpy(&r[8], boot, 16);
	memcpy(&r[24], &pid, 4);
	memcpy(&r[28], &reserved, 4);
	memcpy(&r[32], &sec, 8);
	memcpy(&r[40], &usec, 8);
	return (r);
}

static void
test_record_and_recover()
{
	ledger l;
	pid_t a = spawn(), b = spawn(2000, 7);
	CHECK(record_guest_child(l.fd, table[a].pd, a));
	CHECK(record_guest_child(l.fd, table[b].pd, b));
	/* The written record matches the independent layout exactly. */
	{
		int f = openat(l.fd, child_file(a).c_str(), O_RDONLY);
		uint8_t got[64];
		CHECK(f >= 0 && read(f, got, sizeof(got)) == 48 && close(f) == 0);
		CHECK(memcmp(got, record_bytes(a, 1000, 5, boot_id).data(), 48) == 0);
	}
	/* A record cannot be created twice. */
	errno = 0;
	CHECK(!record_guest_child(l.fd, table[a].pd, a) && errno == EEXIST);
	/* b's PID is "reused" by a different process birth. */
	table[b].start_usec = 8;
	pdopen_busy = 3;	/* an exiting old child is reported busy first */
	CHECK(recover_guest_children(l.fd, true) == false && errno == EBUSY);
	pdopen_busy = 3;
	l.marker();
	CHECK(recover_guest_children(l.fd, true));
	CHECK(!alive(a) && alive(b));
	CHECK(!exists(l.fd, child_file(a)) && !exists(l.fd, child_file(b)));
	CHECK(exists(l.fd, ".child-ledger-v1"));
	/* A clean ledger recovers trivially and creates its marker. */
	ledger m;
	CHECK(recover_guest_children(m.fd, false) && exists(m.fd, ".child-ledger-v1"));
	CHECK(recover_guest_children(m.fd, true));
}

static void
test_other_boot_and_gone()
{
	ledger l;
	pid_t a = spawn();
	uint8_t other[16] = {0xee};
	auto rec = record_bytes(a, 1000, 5, other);
	l.raw(child_file(a), rec.data(), rec.size());
	/* a child recorded under another boot is never probed or signalled */
	pid_t gone = 999999;
	auto rec2 = record_bytes(gone, 1, 1, boot_id);
	l.raw(child_file(gone), rec2.data(), rec2.size());	/* no such process */
	CHECK(recover_guest_children(l.fd, false));
	CHECK(alive(a) && !exists(l.fd, child_file(a)) &&
	    !exists(l.fd, child_file(gone)));
}

static void
test_probe_failures()
{
	{	/* descriptor query fails for a reason other than ESRCH */
		ledger l;
		pid_t a = spawn();
		CHECK(record_guest_child(l.fd, table[a].pd, a));
		table[a].birth_errno = EPERM;
		errno = 0;
		CHECK(!recover_guest_children(l.fd, false) && errno == EPERM);
		CHECK(alive(a) && exists(l.fd, child_file(a)) &&
		    !exists(l.fd, ".child-ledger-v1"));
	}
	{	/* identity query reports the child already exited */
		ledger l;
		pid_t a = spawn();
		CHECK(record_guest_child(l.fd, table[a].pd, a));
		CHECK(pdkill(table[a].pd, SIGKILL) == 0);
		table[a].birth_errno = ESRCH;
		CHECK(recover_guest_children(l.fd, false));
		CHECK(!exists(l.fd, child_file(a)));
	}
	{	/* pdopenpid fails hard / keeps reporting busy */
		for (int mode = 0; mode < 2; ++mode) {
			ledger l;
			pid_t a = spawn();
			CHECK(record_guest_child(l.fd, table[a].pd, a));
			if (mode == 0)
				pdopen_errno = EPERM;
			else
				pdopen_busy = 1000;
			errno = 0;
			CHECK(!recover_guest_children(l.fd, false) &&
			    errno == (mode == 0 ? EPERM : EBUSY));
			pdopen_errno = 0;
			pdopen_busy = 0;
			CHECK(alive(a) && exists(l.fd, child_file(a)));
		}
	}
	{	/* boot identity unavailable or malformed */
		for (int mode = 1; mode <= 2; ++mode) {
			ledger l;
			pid_t a = spawn();
			boot_mode = mode;
			errno = 0;
			CHECK(!record_guest_child(l.fd, table[a].pd, a));
			CHECK(errno == (mode == 1 ? ENOENT : EPROTO));
			CHECK(!recover_guest_children(l.fd, false));
			boot_mode = 0;
			CHECK(!exists(l.fd, child_file(a)) &&
			    !exists(l.fd, ".child-ledger-v1"));
		}
	}
	{	/* recording: identity query failure and inconsistent identity */
		ledger l;
		pid_t a = spawn();
		table[a].birth_errno = EOPNOTSUPP;
		CHECK(!record_guest_child(l.fd, table[a].pd, a) && errno == EOPNOTSUPP);
		table[a].birth_errno = 0;
		table[a].start_usec = 1000000;
		CHECK(!record_guest_child(l.fd, table[a].pd, a) && errno == EPROTO);
		table[a].start_usec = 5;
		CHECK(!record_guest_child(l.fd, table[a].pd, a + 1) && errno == EPROTO);
		CHECK(!record_guest_child(l.fd, table[a].pd, 1) && errno == EINVAL);
		CHECK(!exists(l.fd, child_file(a)));
		/* unwritable ledger */
		CHECK(fchmod(l.fd, 0500) == 0);
		CHECK(!record_guest_child(l.fd, table[a].pd, a) && errno == EACCES);
		CHECK(fchmod(l.fd, 0700) == 0);
	}
	{	/* retire: absent is fine, unremovable is an error */
		ledger l;
		CHECK(retire_guest_child(l.fd, 4321));
		CHECK(!retire_guest_child(l.fd, 1) && errno == EINVAL);
		l.raw(child_file(4321), "x", 1);
		CHECK(fchmod(l.fd, 0500) == 0);
		CHECK(!retire_guest_child(l.fd, 4321) && errno == EACCES);
		CHECK(fchmod(l.fd, 0700) == 0);
		CHECK(retire_guest_child(l.fd, 4321) && !exists(l.fd, child_file(4321)));
	}
}

static void
test_malformed_ledgers()
{
	struct { const char *name; std::vector<uint8_t> bytes; } bad[] = {
		{".child.0", record_bytes(0, 1, 1, boot_id)},
		{".child.1", record_bytes(1, 1, 1, boot_id)},
		{".child.012", record_bytes(12, 1, 1, boot_id)},
		{".child.12x", record_bytes(12, 1, 1, boot_id)},
		{".child.99999999999", record_bytes(5, 1, 1, boot_id)},
		{".child.", {}},
	};
	for (auto &b : bad) {
		ledger l;
		pid_t a = spawn();
		CHECK(record_guest_child(l.fd, table[a].pd, a));
		l.raw(b.name, b.bytes.data(), b.bytes.size());
		errno = 0;
		CHECK(!recover_guest_children(l.fd, false) && errno == EPROTO);
		CHECK(alive(a) && exists(l.fd, child_file(a)));
	}
	/* record content damage */
	pid_t fake = 424242;
	struct { std::vector<uint8_t> bytes; } content[] = {
		{record_bytes(fake, 1, 1, boot_id, 7)},		/* magic */
		{record_bytes(fake + 1, 1, 1, boot_id)},	/* pid */
		{record_bytes(fake, 1, 1, boot_id, UINT64_C(0x31444c4948435444), 1)},
		{record_bytes(fake, 1, 1000000, boot_id)},	/* usec */
		{std::vector<uint8_t>(47, 0)},			/* short */
		{std::vector<uint8_t>(49, 0)},			/* long */
	};
	for (auto &c : content) {
		ledger l;
		l.raw(child_file(fake), c.bytes.data(), c.bytes.size());
		errno = 0;
		CHECK(!recover_guest_children(l.fd, false) && errno == EPROTO);
		CHECK(exists(l.fd, child_file(fake)));
	}
	{	/* a hard-linked record is not trusted */
		ledger l;
		auto r = record_bytes(fake, 1, 1, boot_id);
		l.raw(child_file(fake), r.data(), r.size());
		CHECK(linkat(l.fd, child_file(fake).c_str(), l.fd, "alias", 0) == 0);
		CHECK(!recover_guest_children(l.fd, false) && errno == EPROTO);
	}
	{	/* marker must be an empty, single-link regular file */
		ledger l;
		l.raw(".child-ledger-v1", "x", 1);
		CHECK(!recover_guest_children(l.fd, false) && errno == EPROTO);
		ledger m;
		CHECK(mkdirat(m.fd, ".child-ledger-v1", 0700) == 0);
		CHECK(!recover_guest_children(m.fd, false) && errno == EPROTO);
	}
	{	/* unreadable directory */
		ledger l;
		CHECK(fchmod(l.fd, 0300) == 0);
		CHECK(!recover_guest_children(l.fd, false) && errno == EACCES);
		CHECK(fchmod(l.fd, 0700) == 0);
	}
}

int
main()
{
	alarm(200);
	test_record_and_recover();
	test_other_boot_and_gone();
	test_probe_failures();
	test_malformed_ledgers();
	printf("child-ledger-recovery: %u checks passed\n", harness_checks);
	return (0);
}
