/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <errno.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shmring.h"

ATF_TC(stream);
ATF_TC_HEAD(stream, tc)
{
	atf_tc_set_md_var(tc, "descr", "stream rings preserve bytes and wrap");
}
ATF_TC_BODY(stream, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	char in[5000], out[5000];

	memset(in, 0x5a, sizeof(in));
	ATF_REQUIRE(shmring_create(4096, SHMRING_MODE_STREAM, 0, 42,
	    &pfds, &cfds) == 0);
	ATF_REQUIRE(shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER) == 0);
	ATF_REQUIRE(shmring_open(&consumer, &cfds,
	    SHMRING_ROLE_CONSUMER) == 0);
	ATF_CHECK_EQ(shmring_generation(producer), 42);
	ATF_CHECK_EQ(shmring_write(producer, in, 3000), 3000);
	ATF_CHECK_EQ(shmring_read(consumer, out, 2000), 2000);
	ATF_CHECK_EQ(memcmp(in, out, 2000), 0);
	ATF_CHECK_EQ(shmring_write(producer, in + 3000, 2000), 2000);
	ATF_CHECK_EQ(shmring_read(consumer, out, 3000), 3000);
	ATF_CHECK_EQ(memcmp(in + 2000, out, 3000), 0);
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(record);
ATF_TC_HEAD(record, tc)
{
	atf_tc_set_md_var(tc, "descr", "record rings preserve boundaries");
}
ATF_TC_BODY(record, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	char out[32];

	ATF_REQUIRE(shmring_create(4096, SHMRING_MODE_RECORD, 512, 7,
	    &pfds, &cfds) == 0);
	ATF_REQUIRE(shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER) == 0);
	ATF_REQUIRE(shmring_open(&consumer, &cfds,
	    SHMRING_ROLE_CONSUMER) == 0);
	ATF_REQUIRE(shmring_write_record(producer, "one", 3) == 0);
	ATF_REQUIRE(shmring_write_record(producer, "second", 6) == 0);
	ATF_CHECK_EQ(shmring_read_record(consumer, out, 2), -1);
	ATF_CHECK_EQ(errno, EMSGSIZE);
	ATF_CHECK_EQ(shmring_read_record(consumer, out, sizeof(out)), 3);
	ATF_CHECK_EQ(memcmp(out, "one", 3), 0);
	ATF_CHECK_EQ(shmring_read_record(consumer, out, sizeof(out)), 6);
	ATF_CHECK_EQ(memcmp(out, "second", 6), 0);
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(invalid);
ATF_TC_HEAD(invalid, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ring creation and endpoint metadata fail closed");
}
ATF_TC_BODY(invalid, tc)
{
	struct shmring_fds pfds, cfds, forged;
	struct shmring *ring;

	ATF_CHECK_EQ(-1, shmring_create(1, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, shmring_create(5000, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, shmring_create(4096, 99, 0, 0, &pfds, &cfds));
	ATF_CHECK_EQ(EINVAL, errno);
	ATF_CHECK_EQ(-1, shmring_create(4096, SHMRING_MODE_STREAM, 1, 0,
	    &pfds, &cfds));
	ATF_CHECK_EQ(EINVAL, errno);

	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	forged = pfds;
	forged.head_fd = pfds.data_fd;
	ATF_CHECK_EQ(-1, shmring_open(&ring, &forged,
	    SHMRING_ROLE_PRODUCER));
	ATF_CHECK_EQ(EPROTO, errno);
	ATF_CHECK_EQ(-1, shmring_open(&ring, &pfds,
	    SHMRING_ROLE_CONSUMER));
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(rights);
ATF_TC_HEAD(rights, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "producer and consumer descriptors cannot map peer-owned state");
}
ATF_TC_BODY(rights, tc)
{
	struct shmring_fds pfds, cfds;
	void *mapping;

	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	mapping = mmap(NULL, 4096, PROT_READ, MAP_SHARED, pfds.data_fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, mapping);
	mapping = mmap(NULL, sizeof(uint64_t), PROT_WRITE, MAP_SHARED,
	    pfds.tail_fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, mapping);
	mapping = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, cfds.data_fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, mapping);
	mapping = mmap(NULL, sizeof(uint64_t), PROT_WRITE, MAP_SHARED,
	    cfds.head_fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, mapping);
	mapping = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, cfds.config_fd, 0);
	ATF_CHECK_EQ(MAP_FAILED, mapping);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(forged_objects);
ATF_TC_HEAD(forged_objects, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "undersized and mutable configuration objects fail without SIGBUS");
}
ATF_TC_BODY(forged_objects, tc)
{
	struct shmring_fds pfds, cfds, forged;
	struct shmring *ring;
	struct stat sb;
	int fd;

	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	ATF_REQUIRE_EQ(0, fstat(pfds.config_fd, &sb));

	fd = memfd_create("mutable-ring-config",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, sb.st_size));
	forged = pfds;
	forged.config_fd = fd;
	errno = 0;
	ATF_CHECK_EQ(-1, shmring_open(&ring, &forged,
	    SHMRING_ROLE_PRODUCER));
	ATF_CHECK_EQ(EPROTO, errno);
	close(fd);

	fd = memfd_create("short-ring-config",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(0, ftruncate(fd, sb.st_size - 1));
	ATF_REQUIRE_EQ(0, fcntl(fd, F_ADD_SEALS, F_SEAL_GROW |
	    F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL));
	forged.config_fd = fd;
	errno = 0;
	ATF_CHECK_EQ(-1, shmring_open(&ring, &forged,
	    SHMRING_ROLE_PRODUCER));
	ATF_CHECK_EQ(EPROTO, errno);
	close(fd);

	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(capability_mode);
ATF_TC_HEAD(capability_mode, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ring creation, mapping, and transfer work after cap_enter");
}
ATF_TC_BODY(capability_mode, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	pid_t pid;
	int status;
	char out[4];

	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (cap_enter() == -1 ||
		    shmring_create(4096, SHMRING_MODE_STREAM, 0, 9,
		    &pfds, &cfds) == -1 ||
		    shmring_open(&producer, &pfds,
		    SHMRING_ROLE_PRODUCER) == -1 ||
		    shmring_open(&consumer, &cfds,
		    SHMRING_ROLE_CONSUMER) == -1 ||
		    shmring_write(producer, "cap", 3) != 3 ||
		    shmring_read(consumer, out, sizeof(out)) != 3 ||
		    memcmp(out, "cap", 3) != 0)
			_exit(1);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
}

ATF_TC(full_empty);
ATF_TC_HEAD(full_empty, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "full and empty rings report nonblocking backpressure");
}
ATF_TC_BODY(full_empty, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	char buf[4096];

	memset(buf, 0xa5, sizeof(buf));
	ATF_REQUIRE_EQ(0, shmring_create(sizeof(buf), SHMRING_MODE_STREAM, 0,
	    0, &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	ATF_REQUIRE_EQ(0, shmring_open(&consumer, &cfds,
	    SHMRING_ROLE_CONSUMER));
	ATF_CHECK_EQ(sizeof(buf), shmring_writable(producer));
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf),
	    shmring_write(producer, buf, sizeof(buf)));
	ATF_CHECK_EQ(0, shmring_writable(producer));
	ATF_CHECK_EQ(-1, shmring_write(producer, buf, 1));
	ATF_CHECK_EQ(EAGAIN, errno);
	ATF_REQUIRE_EQ((ssize_t)sizeof(buf),
	    shmring_read(consumer, buf, sizeof(buf)));
	ATF_CHECK_EQ(0, shmring_readable(consumer));
	ATF_CHECK_EQ(-1, shmring_read(consumer, buf, 1));
	ATF_CHECK_EQ(EAGAIN, errno);
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(concurrent);
ATF_TC_HEAD(concurrent, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "separate processes preserve four MiB across repeated wraps");
}
ATF_TC_BODY(concurrent, tc)
{
	const size_t total = 4 * 1024 * 1024;
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	unsigned char buf[997];
	size_t offset, i;
	ssize_t n;
	pid_t pid;
	int status;

	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		if (shmring_open(&consumer, &cfds,
		    SHMRING_ROLE_CONSUMER) == -1)
			_exit(10);
		offset = 0;
		while (offset < total) {
			n = shmring_read(consumer, buf, sizeof(buf));
			if (n == -1) {
				if (errno == EAGAIN) {
					sched_yield();
					continue;
				}
				_exit(11);
			}
			for (i = 0; i < (size_t)n; i++)
				if (buf[i] != (unsigned char)(offset + i))
					_exit(12);
			offset += (size_t)n;
		}
		_exit(0);
	}
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	offset = 0;
	while (offset < total) {
		size_t chunk;

		chunk = MIN(sizeof(buf), total - offset);
		for (i = 0; i < chunk; i++)
			buf[i] = (unsigned char)(offset + i);
		n = shmring_write(producer, buf, chunk);
		if (n == -1) {
			ATF_REQUIRE_EQ(EAGAIN, errno);
			sched_yield();
			continue;
		}
		offset += (size_t)n;
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	shmring_close(producer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stream);
	ATF_TP_ADD_TC(tp, record);
	ATF_TP_ADD_TC(tp, invalid);
	ATF_TP_ADD_TC(tp, rights);
	ATF_TP_ADD_TC(tp, forged_objects);
	ATF_TP_ADD_TC(tp, capability_mode);
	ATF_TP_ADD_TC(tp, full_empty);
	ATF_TP_ADD_TC(tp, concurrent);
	return (atf_no_error());
}
