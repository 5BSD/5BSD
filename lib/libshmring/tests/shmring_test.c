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
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shmring.h"

#define TEST_SHMRING_MAGIC 0x53484d52494e4731ULL

struct test_shmring_config {
	uint64_t magic;
	uint32_t version;
	uint32_t mode;
	uint64_t capacity;
	uint32_t max_record;
	uint32_t shape;
	uint64_t generation;
	uint64_t low_watermark;
	uint64_t high_watermark;
};

static int
create_test_config(const struct test_shmring_config *config, bool limit_rights)
{
	cap_rights_t rights;
	int fd;

	fd = memfd_create("forged-ring-config",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (fd == -1)
		return (-1);
	if (ftruncate(fd, sizeof(*config)) == -1 ||
	    pwrite(fd, config, sizeof(*config), 0) != sizeof(*config) ||
	    fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK |
	    F_SEAL_WRITE | F_SEAL_SEAL) == -1)
		goto fail;
	if (limit_rights) {
		cap_rights_init(&rights, CAP_FSTAT, CAP_MMAP_R);
		if (cap_rights_limit(fd, &rights) == -1)
			goto fail;
	}
	return (fd);
fail:
	close(fd);
	return (-1);
}

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

ATF_TC(forged_aliases);
ATF_TC_HEAD(forged_aliases, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "ring metadata descriptors must name distinct objects with exact rights");
}

ATF_TC(forged_metadata);
ATF_TC_HEAD(forged_metadata, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "sealed metadata and endpoint rights are validated independently");
}
ATF_TC_BODY(forged_metadata, tc)
{
	struct test_shmring_config config = {
		.magic = TEST_SHMRING_MAGIC,
		.version = SHMRING_ABI_VERSION,
		.mode = SHMRING_MODE_STREAM,
		.capacity = 4096,
		.shape = SHMRING_SHAPE_COMPACT_SPSC,
		.high_watermark = 4096,
	};
	struct shmring_fds pfds, cfds, forged;
	struct shmring *ring;
	int fd;

	(void)tc;
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));

	/* A valid sealed object with excess rights is not an endpoint. */
	fd = create_test_config(&config, false);
	ATF_REQUIRE(fd >= 0);
	forged = pfds;
	forged.config_fd = fd;
	ATF_CHECK_ERRNO(EPROTO,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	close(fd);

	config.magic++;
	fd = create_test_config(&config, true);
	ATF_REQUIRE(fd >= 0);
	forged.config_fd = fd;
	ATF_CHECK_ERRNO(EPROTO,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	close(fd);
	config.magic = TEST_SHMRING_MAGIC;

	config.shape = SHMRING_SHAPE_TRUSTED_MPSC;
	fd = create_test_config(&config, true);
	ATF_REQUIRE(fd >= 0);
	forged.config_fd = fd;
	ATF_CHECK_ERRNO(EPROTO,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	close(fd);
	config.shape = SHMRING_SHAPE_COMPACT_SPSC;

	config.low_watermark = 4097;
	fd = create_test_config(&config, true);
	ATF_REQUIRE(fd >= 0);
	forged.config_fd = fd;
	ATF_CHECK_ERRNO(EPROTO,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	close(fd);

	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}
ATF_TC_BODY(forged_aliases, tc)
{
	struct shmring_fds pfds, cfds, forged;
	struct shmring *ring;
	cap_rights_t rights;
	int alias;

	(void)tc;
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	alias = fcntl(pfds.head_fd, F_DUPFD_CLOEXEC, 0);
	ATF_REQUIRE(alias >= 0);
	cap_rights_init(&rights, CAP_FSTAT, CAP_MMAP_R);
	ATF_REQUIRE_EQ(0, cap_rights_limit(alias, &rights));
	forged = pfds;
	forged.tail_fd = alias;
	ATF_CHECK_ERRNO(EPROTO,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	close(alias);

	forged = pfds;
	forged.config_fd = -1;
	ATF_CHECK_ERRNO(EBADF,
	    shmring_open(&ring, &forged, SHMRING_ROLE_PRODUCER) == -1);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC(counter_overflow);
ATF_TC_HEAD(counter_overflow, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "monotonic positions fail closed instead of wrapping at UINT64_MAX");
}

ATF_TC(corrupt_positions);
ATF_TC_HEAD(corrupt_positions, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "availability queries distinguish corrupt positions from empty rings");
}
ATF_TC_BODY(corrupt_positions, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer, *consumer;
	uint64_t *head;

	(void)tc;
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	ATF_REQUIRE_EQ(0, shmring_open(&consumer, &cfds,
	    SHMRING_ROLE_CONSUMER));
	head = mmap(NULL, sizeof(*head), PROT_READ | PROT_WRITE, MAP_SHARED,
	    pfds.head_fd, 0);
	ATF_REQUIRE(head != MAP_FAILED);
	*head = 4097;
	ATF_CHECK_ERRNO(EPROTO, shmring_readable(consumer) == -1);
	ATF_CHECK_ERRNO(EPROTO, shmring_writable(producer) == -1);
	*head = 0;
	munmap(head, sizeof(*head));
	shmring_close(producer);
	shmring_close(consumer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}
ATF_TC_BODY(counter_overflow, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer;
	uint64_t *head, *tail;

	(void)tc;
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 0,
	    &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	head = mmap(NULL, sizeof(*head), PROT_READ | PROT_WRITE, MAP_SHARED,
	    pfds.head_fd, 0);
	tail = mmap(NULL, sizeof(*tail), PROT_READ | PROT_WRITE, MAP_SHARED,
	    cfds.tail_fd, 0);
	ATF_REQUIRE(head != MAP_FAILED);
	ATF_REQUIRE(tail != MAP_FAILED);
	*head = UINT64_MAX - 1;
	*tail = UINT64_MAX - 1;
	ATF_CHECK_ERRNO(EOVERFLOW,
	    shmring_write(producer, "xx", 2) == -1);
	ATF_CHECK_EQ(UINT64_MAX - 1, *head);
	munmap(head, sizeof(*head));
	munmap(tail, sizeof(*tail));
	shmring_close(producer);
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

ATF_TC(fork_revocation);
ATF_TC_HEAD(fork_revocation, tc)
{
	atf_tc_set_md_var(tc, "descr",
	    "opened ring mappings and API authority are not inherited across fork");
}
ATF_TC_BODY(fork_revocation, tc)
{
	struct shmring_fds pfds, cfds;
	struct shmring *producer;
	pid_t pid;
	int status;

	(void)tc;
	ATF_REQUIRE_EQ(0, shmring_create(4096, SHMRING_MODE_STREAM, 0, 17,
	    &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	pid = fork();
	ATF_REQUIRE(pid >= 0);
	if (pid == 0) {
		errno = 0;
		if (shmring_write(producer, "x", 1) != -1 || errno != ECHILD)
			_exit(10);
		errno = 0;
		if (shmring_generation(producer) != 0 || errno != ECHILD)
			_exit(11);
		shmring_close(producer);
		_exit(0);
	}
	ATF_REQUIRE_EQ(pid, waitpid(pid, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	ATF_CHECK_EQ(1, shmring_write(producer, "x", 1));
	shmring_close(producer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);
}

ATF_TC_WITHOUT_HEAD(shapes_and_watermarks);
ATF_TC_BODY(shapes_and_watermarks, tc)
{
	struct shmring_options options = SHMRING_OPTIONS_INITIALIZER(
	    SHMRING_SHAPE_COMPACT_SPSC, SHMRING_MODE_RECORD, 16U * 1024U);
	struct shmring_fds pfds, cfds;
	struct shmring *producer;

	(void)tc;
	options.max_record = 4096;
	options.low_watermark = 4096;
	options.high_watermark = 12U * 1024U;
	options.generation = 91;
	ATF_REQUIRE_EQ(0, shmring_create_with_options(&options, &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	ATF_CHECK_EQ(SHMRING_SHAPE_COMPACT_SPSC, shmring_shape(producer));
	ATF_CHECK_EQ(4096, shmring_low_watermark(producer));
	ATF_CHECK_EQ(12U * 1024U, shmring_high_watermark(producer));
	shmring_close(producer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);

	options.shape = SHMRING_SHAPE_BULK_SPSC;
	options.capacity = SHMRING_BULK_MIN_CAPACITY;
	options.low_watermark = 16U * 1024U;
	options.high_watermark = 48U * 1024U;
	ATF_REQUIRE_EQ(0, shmring_create_with_options(&options, &pfds, &cfds));
	ATF_REQUIRE_EQ(0, shmring_open(&producer, &pfds,
	    SHMRING_ROLE_PRODUCER));
	ATF_CHECK_EQ(SHMRING_SHAPE_BULK_SPSC, shmring_shape(producer));
	shmring_close(producer);
	shmring_fds_close(&pfds);
	shmring_fds_close(&cfds);

	options.shape = SHMRING_SHAPE_COMPACT_SPSC;
	options.capacity = 128U * 1024U;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.shape = SHMRING_SHAPE_BULK_SPSC;
	options.capacity = 16U * 1024U;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.shape = SHMRING_SHAPE_TRUSTED_MPSC;
	options.capacity = 64U * 1024U;
	ATF_CHECK_ERRNO(ENOTSUP,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.shape = SHMRING_SHAPE_COMPACT_SPSC;
	options.capacity = 16U * 1024U;
	options.low_watermark = 12U * 1024U;
	options.high_watermark = 8U * 1024U;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.low_watermark = 0;
	options.high_watermark = options.capacity + 1;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.high_watermark = 0;
	options.reserved = 1;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
	options.reserved = 0;
	options.size--;
	ATF_CHECK_ERRNO(EINVAL,
	    shmring_create_with_options(&options, &pfds, &cfds) == -1);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, stream);
	ATF_TP_ADD_TC(tp, record);
	ATF_TP_ADD_TC(tp, invalid);
	ATF_TP_ADD_TC(tp, rights);
	ATF_TP_ADD_TC(tp, forged_objects);
	ATF_TP_ADD_TC(tp, forged_aliases);
	ATF_TP_ADD_TC(tp, forged_metadata);
	ATF_TP_ADD_TC(tp, counter_overflow);
	ATF_TP_ADD_TC(tp, corrupt_positions);
	ATF_TP_ADD_TC(tp, capability_mode);
	ATF_TP_ADD_TC(tp, full_empty);
	ATF_TP_ADD_TC(tp, concurrent);
	ATF_TP_ADD_TC(tp, fork_revocation);
	ATF_TP_ADD_TC(tp, shapes_and_watermarks);
	return (atf_no_error());
}
