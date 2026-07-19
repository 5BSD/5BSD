/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Atomic persistence failure-boundary tests for meshd(8).
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/stat.h>

#include <atf-c.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mesh_test_heap.h"
#include "meshd.h"
#include "meshd_persist.h"

static int fail_write;
static int fail_rename;
static int fail_fsync_call;
static int fsync_calls;

ssize_t __real_write(int, const void *, size_t);
int __real_fsync(int);
int __real_rename(const char *, const char *);
ssize_t __wrap_write(int, const void *, size_t);
int __wrap_fsync(int);
int __wrap_rename(const char *, const char *);

ssize_t
__wrap_write(int fd, const void *buf, size_t len)
{

	if (fail_write) {
		errno = EIO;
		return (-1);
	}
	return (__real_write(fd, buf, len));
}

int
__wrap_fsync(int fd)
{

	fsync_calls++;
	if (fail_fsync_call != 0 && fsync_calls == fail_fsync_call) {
		errno = EIO;
		return (-1);
	}
	return (__real_fsync(fd));
}

int
__wrap_rename(const char *from, const char *to)
{

	if (fail_rename) {
		errno = EIO;
		return (-1);
	}
	return (__real_rename(from, to));
}

static const uint8_t netkey[16] = {
	0x7d, 0xd7, 0x36, 0x4c, 0xd8, 0x42, 0xad, 0x18,
	0xc1, 0x7c, 0x2b, 0x82, 0x0c, 0x84, 0xc3, 0xd6
};
static const uint8_t appkey[16] = {
	0x63, 0x96, 0x47, 0x71, 0x73, 0x4f, 0xbd, 0x76,
	0xe3, 0xb4, 0x05, 0x19, 0xd1, 0xd9, 0x4a, 0x48
};

static void
fresh_node(struct meshd_node *nd)
{
	struct meshd_config cfg;

	meshd_config_defaults(&cfg);
	memcpy(cfg.netkey, netkey, sizeof(netkey));
	memcpy(cfg.appkey, appkey, sizeof(appkey));
	cfg.have_netkey = 1;
	cfg.have_appkey = 1;
	cfg.unicast_addr = 1;
	ATF_REQUIRE_EQ(0, meshd_node_init(nd, &cfg));
}

static void
reset_faults(void)
{

	fail_write = 0;
	fail_rename = 0;
	fail_fsync_call = 0;
	fsync_calls = 0;
}

static uint32_t
test_crc32(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t i;
	int k;

	crc = ~crc;
	for (i = 0; i < len; i++) {
		crc ^= p[i];
		for (k = 0; k < 8; k++)
			crc = (crc >> 1) ^
			    (0xEDB88320u & (~(crc & 1) + 1));
	}
	return (~crc);
}

static void
write_blob(const char *path, const uint8_t *buf, size_t len)
{
	int fd;
	size_t off;
	ssize_t n;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	ATF_REQUIRE(fd >= 0);
	for (off = 0; off < len; off += (size_t)n) {
		n = __real_write(fd, buf + off, len - off);
		ATF_REQUIRE(n > 0);
	}
	ATF_REQUIRE_EQ(0, close(fd));
}

static void
make_baseline(const char *path, struct meshd_node *nd,
    struct meshd_persist *ps)
{

	(void)unlink(path);
	fresh_node(nd);
	meshd_persist_init(ps, path, 100);
	ps->reserved = 100;
	mesh_gen_level_srv_set_present(&nd->app->level, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_save(ps, nd));
}

static int16_t
load_level(const char *path)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;
	int16_t level;

	fresh_node(nd);
	meshd_persist_init(&ps, path, 100);
	ATF_REQUIRE_EQ(0, meshd_persist_load(&ps, nd));
	level = nd->app->level.present;
	return (level);
}

static void
assert_precommit_failure(int which, const char *path)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;

	reset_faults();
	make_baseline(path, nd, &ps);
	mesh_gen_level_srv_set_present(&nd->app->level, 200);
	meshd_persist_mark_dirty(&ps, 10);
	fsync_calls = 0;
	if (which == 1)
		fail_write = 1;
	else if (which == 2)
		fail_fsync_call = 1;
	else
		fail_rename = 1;
	ATF_CHECK_EQ(-1, meshd_persist_flush(&ps, nd, 10, 1));
	ATF_CHECK_EQ(1, ps.dirty);
	ATF_CHECK_EQ(1, ps.write_errors);
	ATF_CHECK_EQ(EIO, ps.last_errno);
	ATF_CHECK_EQ(10 + MESHD_PERSIST_RETRY_MS, ps.due_ms);
	reset_faults();
	ATF_CHECK_EQ(100, load_level(path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(write_failure_preserves_old_commit);
ATF_TC_BODY(write_failure_preserves_old_commit, tc)
{

	assert_precommit_failure(1, "meshd-fault-write.state");
}

ATF_TC_WITHOUT_HEAD(file_fsync_failure_preserves_old_commit);
ATF_TC_BODY(file_fsync_failure_preserves_old_commit, tc)
{

	assert_precommit_failure(2, "meshd-fault-fsync.state");
}

ATF_TC_WITHOUT_HEAD(rename_failure_preserves_old_commit);
ATF_TC_BODY(rename_failure_preserves_old_commit, tc)
{

	assert_precommit_failure(3, "meshd-fault-rename.state");
}

ATF_TC_WITHOUT_HEAD(directory_fsync_failure_is_valid_but_dirty);
ATF_TC_BODY(directory_fsync_failure_is_valid_but_dirty, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;
	const char *path = "meshd-fault-dirfsync.state";

	reset_faults();
	make_baseline(path, nd, &ps);
	mesh_gen_level_srv_set_present(&nd->app->level, 200);
	meshd_persist_mark_dirty(&ps, 20);
	fsync_calls = 0;
	fail_fsync_call = 2;
	ATF_CHECK_EQ(-1, meshd_persist_flush(&ps, nd, 20, 1));
	ATF_CHECK_EQ(1, ps.dirty);
	ATF_CHECK_EQ(1, ps.write_errors);
	reset_faults();
	ATF_CHECK_EQ(200, load_level(path));
	(void)unlink(path);
}

ATF_TC_WITHOUT_HEAD(unique_temp_ignores_fixed_symlink);
ATF_TC_BODY(unique_temp_ignores_fixed_symlink, tc)
{
	MESH_HEAP(struct meshd_node, nd);
	struct meshd_persist ps;
	const char *path = "meshd-unique-temp.state";
	const char *fixed = "meshd-unique-temp.state.tmp";
	const char *victim = "meshd-unique-temp.victim";
	FILE *f;
	char buf[8] = { 0 };

	reset_faults();
	(void)unlink(path);
	(void)unlink(fixed);
	(void)unlink(victim);
	f = fopen(victim, "w");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(4, fwrite("keep", 1, 4, f));
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_REQUIRE_EQ(0, symlink(victim, fixed));
	fresh_node(nd);
	meshd_persist_init(&ps, path, 100);
	ps.reserved = 100;
	ATF_REQUIRE_EQ(0, meshd_persist_save(&ps, nd));
	f = fopen(victim, "r");
	ATF_REQUIRE(f != NULL);
	ATF_REQUIRE_EQ(4, fread(buf, 1, 4, f));
	ATF_REQUIRE_EQ(0, fclose(f));
	ATF_CHECK_EQ(0, memcmp(buf, "keep", 4));
	(void)unlink(path);
	(void)unlink(fixed);
	(void)unlink(victim);
}

ATF_TC_WITHOUT_HEAD(crc_valid_body_mutation_matrix);
ATF_TC_BODY(crc_valid_body_mutation_matrix, tc)
{
	MESH_HEAP(struct meshd_node, baseline);
	struct meshd_persist ps;
	struct stat sb;
	uint8_t *original, *work;
	const char *path = "meshd-crc-valid-mutations.state";
	size_t i;
	int fd;

	reset_faults();
	make_baseline(path, baseline, &ps);
	ATF_REQUIRE_EQ(0, stat(path, &sb));
	ATF_REQUIRE(sb.st_size > 20);
	original = malloc((size_t)sb.st_size);
	work = malloc((size_t)sb.st_size);
	ATF_REQUIRE(original != NULL);
	ATF_REQUIRE(work != NULL);
	fd = open(path, O_RDONLY);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE_EQ(sb.st_size, read(fd, original, (size_t)sb.st_size));
	ATF_REQUIRE_EQ(0, close(fd));

	/* Mutate every body octet while retaining a valid frame CRC.  This gets
	 * beyond the framing guard and systematically exercises the decoder's
	 * bounds, enum, address, key-index and counted-section invariants. */
	for (i = 20; i < (size_t)sb.st_size; i++) {
		struct meshd_node *nd;
		uint32_t crc;
		int rc;

		memcpy(work, original, (size_t)sb.st_size);
		work[i] ^= (uint8_t)(0x5aU + (uint8_t)i);
		memset(work + 16, 0, 4);
		crc = test_crc32(0, work, (size_t)sb.st_size);
		le32enc(work + 16, crc);
		write_blob(path, work, (size_t)sb.st_size);

		nd = calloc(1, sizeof(*nd));
		ATF_REQUIRE(nd != NULL);
		fresh_node(nd);
		meshd_persist_init(&ps, path, 100);
		rc = meshd_persist_load(&ps, nd);
		ATF_CHECK(rc == 0 || rc == -1);
		meshd_node_fini(nd);
		free(nd);
	}

	/* Repeat with every CRC-valid body prefix.  Each cut point reaches the
	 * next bounded-cursor read before failing, covering underrun cleanup for
	 * all fixed and counted records rather than only the outer short-file
	 * check. */
	for (i = 20; i < (size_t)sb.st_size; i++) {
		struct meshd_node *nd;
		uint32_t crc;
		int rc;

		memcpy(work, original, i);
		memset(work + 16, 0, 4);
		crc = test_crc32(0, work, i);
		le32enc(work + 16, crc);
		write_blob(path, work, i);
		nd = calloc(1, sizeof(*nd));
		ATF_REQUIRE(nd != NULL);
		fresh_node(nd);
		meshd_persist_init(&ps, path, 100);
		rc = meshd_persist_load(&ps, nd);
		ATF_CHECK(rc == 0 || rc == -1);
		meshd_node_fini(nd);
		free(nd);
	}

	free(work);
	free(original);
	(void)unlink(path);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, write_failure_preserves_old_commit);
	ATF_TP_ADD_TC(tp, file_fsync_failure_preserves_old_commit);
	ATF_TP_ADD_TC(tp, rename_failure_preserves_old_commit);
	ATF_TP_ADD_TC(tp, directory_fsync_failure_is_valid_but_dirty);
	ATF_TP_ADD_TC(tp, unique_temp_ignores_fixed_symlink);
	ATF_TP_ADD_TC(tp, crc_valid_body_mutation_matrix);
	return (atf_no_error());
}
