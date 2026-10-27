/* SPDX-License-Identifier: BSD-2-Clause */
/* Ordinary unsigned files on an executable, writable test filesystem. */
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdlib.h>
#include <atf-c.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static size_t
page_size(void)
{
	long size = sysconf(_SC_PAGESIZE);

	ATF_REQUIRE(size > 0);
	return ((size_t)size);
}

static int
create(const char *name, unsigned char value, size_t length)
{
	unsigned char buffer[4096];
	size_t done, take;
	int fd;

	fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
	ATF_REQUIRE(fd >= 0);
	memset(buffer, value, sizeof(buffer));
	for (done = 0; done < length; done += take) {
		take = length - done;
		if (take > sizeof(buffer))
			take = sizeof(buffer);
		ATF_REQUIRE(pwrite(fd, buffer, take, done) == (ssize_t)take);
	}
	return (fd);
}

static void
check_bytes(const void *mapping, unsigned char value, size_t length)
{
	const unsigned char *bytes = mapping;

	for (size_t i = 0; i < length; i++)
		ATF_REQUIRE_MSG(bytes[i] == value, "wrong byte at %zu", i);
}

ATF_TC(repeated_read_mapping);
ATF_TC_HEAD(repeated_read_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr", "Unsigned read mappings do not text-pin ordinary data");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(repeated_read_mapping, tc)
{
	void *maps[32];
	size_t page = page_size();
	unsigned char changed = 0x42;
	int fd, writer;

	(void)tc;
	fd = create("data", 0x31, page * 8);
	ATF_REQUIRE(close(fd) == 0);
	fd = open("data", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	for (unsigned i = 0; i < 32; i++) {
		maps[i] = mmap(NULL, page, PROT_READ, MAP_SHARED, fd,
		    (i % 8) * page);
		ATF_REQUIRE(maps[i] != MAP_FAILED);
		check_bytes(maps[i], 0x31, page);
	}
	/* A mistaken executable text pin would reject this ordinary writer. */
	writer = open("data", O_WRONLY);
	ATF_REQUIRE(writer >= 0);
	ATF_REQUIRE(pwrite(writer, &changed, 1, 0) == 1);
	ATF_REQUIRE(close(writer) == 0);
	for (unsigned i = 0; i < 32; i++) {
		if (i % 8 == 0)
			ATF_REQUIRE(*(volatile unsigned char *)maps[i] == changed);
		ATF_REQUIRE(munmap(maps[i], page) == 0);
	}
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(replacement_keeps_old_mapping);
ATF_TC_HEAD(replacement_keeps_old_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr", "Rename replacement does not rebind a live mapping to new bytes");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(replacement_keeps_old_mapping, tc)
{
	size_t page = page_size();
	void *old, *fresh;
	int fd, replacement;

	(void)tc;
	fd = create("data", 0x31, page);
	old = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE(old != MAP_FAILED);
	ATF_REQUIRE(close(fd) == 0);
	replacement = create("replacement", 0x42, page);
	ATF_REQUIRE(close(replacement) == 0);
	ATF_REQUIRE(rename("replacement", "data") == 0);
	fd = open("data", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	fresh = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE(fresh != MAP_FAILED);
	ATF_REQUIRE(close(fd) == 0);
	check_bytes(old, 0x31, page);
	check_bytes(fresh, 0x42, page);
	ATF_REQUIRE(munmap(old, page) == 0);
	ATF_REQUIRE(munmap(fresh, page) == 0);
}

ATF_TC(unlinked_mapping_survives);
ATF_TC_HEAD(unlinked_mapping_survives, tc)
{
	atf_tc_set_md_var(tc, "descr", "Mapping and new fd-based mappings survive unlink of unsigned data");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(unlinked_mapping_survives, tc)
{
	size_t page = page_size();
	void *first, *second;
	int fd;

	(void)tc;
	fd = create("data", 0x31, page);
	first = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE(first != MAP_FAILED);
	ATF_REQUIRE(unlink("data") == 0);
	second = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE(second != MAP_FAILED);
	ATF_REQUIRE(close(fd) == 0);
	check_bytes(first, 0x31, page);
	check_bytes(second, 0x31, page);
	ATF_REQUIRE(munmap(first, page) == 0);
	ATF_REQUIRE(munmap(second, page) == 0);
}

ATF_TC(unsigned_exec_promotion);
ATF_TC_HEAD(unsigned_exec_promotion, tc)
{
	atf_tc_set_md_var(tc, "descr", "Unsigned private read mapping can become RX on an executable test filesystem");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(unsigned_exec_promotion, tc)
{
	size_t page = page_size();
	void *mapping;
	int fd;

	(void)tc;
	fd = create("data", 0x31, page);
	ATF_REQUIRE(close(fd) == 0);
	fd = open("data", O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	mapping = mmap(NULL, page, PROT_READ, MAP_PRIVATE, fd, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(mprotect(mapping, page, PROT_READ | PROT_EXEC) == 0);
	check_bytes(mapping, 0x31, page);
	ATF_REQUIRE(mprotect(mapping, page, PROT_READ) == 0);
	ATF_REQUIRE(munmap(mapping, page) == 0);
}

static void
bus_error(int signal)
{

	_exit(signal == SIGBUS ? 0 : 1);
}

ATF_TC(truncate_invalidates_mapping);
ATF_TC_HEAD(truncate_invalidates_mapping, tc)
{
	atf_tc_set_md_var(tc, "descr", "Truncation removes mapped pages instead of exposing stale bytes beyond EOF");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(truncate_invalidates_mapping, tc)
{
	struct sigaction action;
	size_t page = page_size();
	void *mapping;
	pid_t child;
	int fd, status;

	(void)tc;
	fd = create("data", 0x31, page);
	mapping = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	ATF_REQUIRE(mapping != MAP_FAILED);
	ATF_REQUIRE(*(volatile unsigned char *)mapping == 0x31);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		memset(&action, 0, sizeof(action));
		action.sa_handler = bus_error;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGBUS, &action, NULL) != 0 || ftruncate(fd, 0) != 0)
			_exit(2);
		(void)*(volatile unsigned char *)mapping;
		_exit(3); /* Access beyond the new EOF must have raised SIGBUS. */
	}
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	ATF_REQUIRE(munmap(mapping, page) == 0);
	ATF_REQUIRE(close(fd) == 0);
}

ATF_TC(cross_process_replacement);
ATF_TC_HEAD(cross_process_replacement, tc)
{
	atf_tc_set_md_var(tc, "descr", "Coordinated replacement across processes preserves old mapping and new pathname identities");
	atf_tc_set_md_var(tc, "timeout", "30");
}
ATF_TC_BODY(cross_process_replacement, tc)
{
	size_t page = page_size();
	int ready[2], replaced[2], fd, status;
	pid_t child;
	char token;

	(void)tc;
	fd = create("data", 1, page);
	ATF_REQUIRE(close(fd) == 0);
	ATF_REQUIRE(pipe(ready) == 0);
	ATF_REQUIRE(pipe(replaced) == 0);
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		close(ready[0]);
		close(replaced[1]);
		for (unsigned i = 1; i <= 64; i++) {
			void *old, *fresh;

			fd = open("data", O_RDONLY);
			ATF_REQUIRE(fd >= 0);
			old = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
			ATF_REQUIRE(old != MAP_FAILED);
			ATF_REQUIRE(close(fd) == 0);
			ATF_REQUIRE(write(ready[1], "r", 1) == 1);
			ATF_REQUIRE(read(replaced[0], &token, 1) == 1);
			check_bytes(old, i, page);
			fd = open("data", O_RDONLY);
			ATF_REQUIRE(fd >= 0);
			fresh = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
			ATF_REQUIRE(fresh != MAP_FAILED);
			ATF_REQUIRE(close(fd) == 0);
			check_bytes(fresh, i + 1, page);
			ATF_REQUIRE(munmap(old, page) == 0);
			ATF_REQUIRE(munmap(fresh, page) == 0);
		}
		_exit(0);
	}
	ATF_REQUIRE(close(ready[1]) == 0);
	ATF_REQUIRE(close(replaced[0]) == 0);
	for (unsigned i = 1; i <= 64; i++) {
		ATF_REQUIRE(read(ready[0], &token, 1) == 1);
		fd = create("replacement", i + 1, page);
		ATF_REQUIRE(close(fd) == 0);
		ATF_REQUIRE(rename("replacement", "data") == 0);
		ATF_REQUIRE(write(replaced[1], "d", 1) == 1);
	}
	ATF_REQUIRE(close(ready[0]) == 0);
	ATF_REQUIRE(close(replaced[1]) == 0);
	ATF_REQUIRE(waitpid(child, &status, 0) == child);
	ATF_REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, repeated_read_mapping);
	ATF_TP_ADD_TC(tp, replacement_keeps_old_mapping);
	ATF_TP_ADD_TC(tp, unlinked_mapping_survives);
	ATF_TP_ADD_TC(tp, unsigned_exec_promotion);
	ATF_TP_ADD_TC(tp, truncate_invalidates_mapping);
	ATF_TP_ADD_TC(tp, cross_process_replacement);
	return (atf_no_error());
}
