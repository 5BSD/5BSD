/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019 The FreeBSD Foundation
 *
 * This software was developed by BFF Storage Systems, LLC under sponsorship
 * from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

extern "C" {
#include <dirent.h>
#include <fcntl.h>
#include <sys/mount.h>
}

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;
using namespace std;

class Readdir: public FuseTest {
public:
void expect_lookup(const char *relpath, uint64_t ino)
{
	FuseTest::expect_lookup(relpath, ino, S_IFDIR | 0755, 0, 1);
}
};

class Readdir_7_8: public Readdir {
public:
virtual void SetUp() {
	m_kernel_minor_version = 8;
	Readdir::SetUp();
}

void expect_lookup(const char *relpath, uint64_t ino)
{
	FuseTest::expect_lookup_7_8(relpath, ino, S_IFDIR | 0755, 0, 1);
}
};

struct PlusEntry {
	string name;
	uint64_t nodeid;
	uint32_t nlink = 1;
	uint64_t entry_valid = UINT64_MAX;
	uint64_t attr_valid = UINT64_MAX;
	uint32_t entry_valid_nsec = 0;
};

class ReaddirPlus: public Readdir {
public:
void SetUp() override {
	m_init_flags |= FUSE_DO_READDIRPLUS;
	Readdir::SetUp();
}

void expect_plus(uint64_t off, vector<PlusEntry> entries,
    sem_t *pending = nullptr, sem_t *resume = nullptr)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIRPLUS &&
			    in.header.nodeid == 42 &&
			    in.body.readdir.offset == off);
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([=](auto in, auto& out) {
		size_t size = 0;
		uint64_t cookie = off;

		for (const auto &entry : entries) {
			struct fuse_direntplus plus = {};

			plus.entry_out.nodeid = entry.nodeid;
			plus.entry_out.attr.ino = entry.nodeid;
			plus.entry_out.attr.mode = S_IFREG | 0644;
			plus.entry_out.attr.nlink = entry.nlink;
			plus.entry_out.attr_valid = entry.attr_valid;
			plus.entry_out.entry_valid = entry.entry_valid;
			plus.entry_out.entry_valid_nsec = entry.entry_valid_nsec;
			plus.dirent.ino = entry.nodeid;
			plus.dirent.off = ++cookie;
			plus.dirent.namelen = entry.name.size();
			plus.dirent.type = DT_REG;
			size_t len = FUSE_DIRENTPLUS_SIZE(&plus);
			ASSERT_LE(size + len, in.body.readdir.size);
			memset(out.body.bytes + size, 0, len);
			memcpy(out.body.bytes + size, &plus,
			    FUSE_NAME_OFFSET_DIRENTPLUS);
			memcpy(out.body.bytes + size + FUSE_NAME_OFFSET_DIRENTPLUS,
			    entry.name.data(), entry.name.size());
			size += len;
		}
		out.header.error = 0;
		out.header.len = sizeof(out.header) + size;
		if (pending != nullptr)
			sem_post(pending);
		if (resume != nullptr) {
			while (sem_wait(resume) != 0 && errno == EINTR)
				;
		}
	}))).RetiresOnSaturation();
}

int open_dir()
{
	expect_lookup("some_dir", 42);
	expect_opendir(42);
	int fd = open("mountpoint/some_dir", O_RDONLY | O_DIRECTORY);
	leak(fd);
	return (fd);
}
};

class ReaddirPlusAuto: public ReaddirPlus {
public:
void SetUp() override {
	m_init_flags |= FUSE_READDIRPLUS_AUTO;
	ReaddirPlus::SetUp();
}
};

class ReaddirPlusOld: public ReaddirPlus {
public:
void SetUp() override {
	m_kernel_minor_version = 20;
	ReaddirPlus::SetUp();
}
};

class ReaddirPlusCache: public ReaddirPlus, public WithParamInterface<int> {};

/* Race optional cache population, including entries beyond user capacity. */
TEST_F(ReaddirPlus, forced_unmount_pending_reply)
{
	sem_t pending, resume, unmount_started;
	pthread_t reader, unmounter;
	void *read_result, *unmount_result;
	struct statfs fs;
	int fd = open_dir();
	struct ReaderState {
		int fd;
		sem_t *pending;
	} reader_state = {fd, &pending};

	ASSERT_LE(0, fd);
	ASSERT_EQ(0, sem_init(&pending, 0, 0));
	ASSERT_EQ(0, sem_init(&resume, 0, 0));
	ASSERT_EQ(0, sem_init(&unmount_started, 0, 0));
	/* Fill most of the user buffer, then hold a valid second wire reply. */
	expect_plus(0, {{string(MAXNAMLEN, 'x'), 99}});
	expect_plus(1, {{"next_entry_alpha", 100}, {"next_entry_bravo", 101}},
	    &pending, &resume);
	/* Native forced purge ends the session before reclaiming its nodes. */
	m_mock->m_expect_unmount = true;
	ASSERT_EQ(0, pthread_create(&reader, nullptr, [](void *arg) -> void * {
		auto state = static_cast<ReaderState *>(arg);
		/* Native FUSE requires at least sizeof(struct dirent). */
		char buf[sizeof(struct dirent) + 32];
		ssize_t count = getdirentries(state->fd, buf, sizeof(buf), nullptr);
		int error = count < 0 ? errno : 0;
		/* An early read failure must not strand the coordinator. */
		sem_post(state->pending);
		if (count >= 0) {
			EXPECT_GT(count, 0);
			if (count > 0)
				EXPECT_EQ(string(MAXNAMLEN, 'x'),
				    ((struct dirent *)buf)->d_name);
		}
		return ((void *)(intptr_t)error);
	}, &reader_state));
	while (sem_wait(&pending) != 0 && errno == EINTR)
		;
	ASSERT_EQ(0, pthread_create(&unmounter, nullptr, [](void *arg) -> void * {
		sem_post(static_cast<sem_t *>(arg));
		int error = ::unmount("mountpoint", MNT_FORCE) == 0 ? 0 : errno;
		return ((void *)(intptr_t)error);
	}, &unmount_started));
	while (sem_wait(&unmount_started) != 0 && errno == EINTR)
		;
	sem_post(&resume);
	ASSERT_EQ(0, pthread_join(reader, &read_result));
	ASSERT_EQ(0, pthread_join(unmounter, &unmount_result));
	/* The daemon must leave its semaphore wait before we destroy it. */
	m_mock->join_daemon();
	EXPECT_TRUE((intptr_t)read_result == 0 ||
	    (intptr_t)read_result == ENOTCONN) << (intptr_t)read_result;
	EXPECT_EQ(0, (intptr_t)unmount_result);
	ASSERT_EQ(0, statfs("mountpoint", &fs)) << strerror(errno);
	EXPECT_STRNE("fusefs", fs.f_fstypename);
	EXPECT_EQ(0, sem_destroy(&pending));
	EXPECT_EQ(0, sem_destroy(&resume));
	EXPECT_EQ(0, sem_destroy(&unmount_started));
}

TEST_P(ReaddirPlusCache, honors_cache_lifetimes)
{
	char buf[4096];
	struct stat sb;
	PlusEntry entry{"item", 43};
	const bool attrs_expired = GetParam() == 0;
	const uint64_t expected_ino = attrs_expired ? 43 : 44;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	if (attrs_expired)
		entry.attr_valid = 0;
	else {
		entry.entry_valid = 0;
		if (GetParam() == 2)
			entry.entry_valid_nsec = NAP_NS / 2;
	}
	expect_plus(0, {entry});
	expect_plus(1, {});
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	if (GetParam() == 2)
		nap();
	if (attrs_expired) {
		EXPECT_CALL(*m_mock, process(
			ResultOf([](auto in) {
				return (in.header.opcode == FUSE_GETATTR &&
				    in.header.nodeid == 43);
			}, Eq(true)), _))
		.WillOnce(Invoke(ReturnImmediate([](auto in __unused, auto& out) {
			SET_OUT_HEADER_LEN(out, attr);
			out.body.attr.attr_valid = UINT64_MAX;
			out.body.attr.attr.ino = 43;
			out.body.attr.attr.mode = S_IFREG | 0644;
			out.body.attr.attr.nlink = 7;
		})));
	} else {
		/* Expired names must permit the daemon to replace the inode. */
		EXPECT_LOOKUP(42, "item")
		.WillOnce(Invoke(ReturnImmediate([](auto in __unused, auto& out) {
			SET_OUT_HEADER_LEN(out, entry);
			out.body.entry.nodeid = 44;
			out.body.entry.entry_valid = UINT64_MAX;
			out.body.entry.attr_valid = UINT64_MAX;
			out.body.entry.attr.ino = 44;
			out.body.entry.attr.mode = S_IFREG | 0644;
			out.body.entry.attr.nlink = 7;
		})));
	}
	expect_forget(43, 1);
	if (!attrs_expired)
		expect_forget(44, 1);
	for (int i = 0; i < 2; i++) {
		ASSERT_EQ(0, fstatat(fd, "item", &sb, 0));
		EXPECT_EQ(expected_ino, sb.st_ino);
		EXPECT_EQ(7ul, sb.st_nlink);
	}
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

INSTANTIATE_TEST_SUITE_P(Timeouts, ReaddirPlusCache, Values(0, 1, 2));

TEST_F(ReaddirPlus, cached_aliases_and_forget)
{
	char buf[4096];
	struct stat sb;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{"first", 43, 1}, {"second", 43, 2}});
	expect_plus(2, {});
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_EQ(0, fstatat(fd, "first", &sb, 0));
	EXPECT_EQ(2ul, sb.st_nlink);
	ASSERT_EQ(0, fstatat(fd, "second", &sb, 0));
	EXPECT_EQ(2ul, sb.st_nlink);
	expect_forget(43, 2);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

TEST_F(ReaddirPlus, busy_vnode_returns_reference_without_waiting)
{
	char buf[4096];
	sem_t blocked;
	pthread_t worker;
	uint64_t unique = 0;
	void *result;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, sem_init(&blocked, 0, 0));
	FuseTest::expect_lookup("busy", 43, S_IFREG | 0644, 0, 1, 0);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return (in.header.opcode == FUSE_GETATTR &&
			    in.header.nodeid == 43);
		}, Eq(true)), _))
	.WillOnce(Invoke([&](auto in, auto &out __unused) {
		unique = in.header.unique;
		sem_post(&blocked);
	}));
	expect_plus(0, {{"busy", 43}});
	expect_forget(43, 1);
	expect_plus(1, {});
	ASSERT_EQ(0, pthread_create(&worker, nullptr, [](void *) -> void * {
		struct stat sb;
		int error = stat("mountpoint/busy", &sb) == 0 ? 0 : errno;
		return ((void *)(intptr_t)error);
	}, nullptr));
	while (sem_wait(&blocked) != 0 && errno == EINTR)
		;
	/* The pending GETATTR holds a vnode lock until we reply below. */
	ssize_t count = getdirentries(fd, buf, sizeof(buf), nullptr);
	int read_error = errno;
	std::unique_ptr<mockfs_buf_out> reply(new mockfs_buf_out{});
	reply->header.unique = unique;
	SET_OUT_HEADER_LEN(*reply, attr);
	reply->body.attr.attr.ino = 43;
	reply->body.attr.attr.mode = S_IFREG | 0644;
	reply->body.attr.attr.nlink = 1;
	m_mock->write_response(*reply);
	ASSERT_EQ(0, pthread_join(worker, &result));
	EXPECT_EQ(0, (intptr_t)result);
	ASSERT_LT(0, count) << strerror(read_error);
	EXPECT_STREQ("busy", ((struct dirent *)buf)->d_name);
	/* Only the original LOOKUP reference remains after skipped prefetch. */
	expect_forget(43, 1);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
	EXPECT_EQ(0, sem_destroy(&blocked));
}

TEST_F(ReaddirPlus, dots_and_zero_nodeid_do_not_acquire_lookups)
{
	char buf[4096];
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{".", 42}, {"..", FUSE_ROOT_ID}, {"uncached", 0}});
	expect_plus(3, {});
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	/* Keep another vnode busy while reclaiming the directory under test. */
	expect_lookup("held", 99);
	expect_opendir(99);
	int held = open("mountpoint/held", O_RDONLY | O_DIRECTORY);
	ASSERT_LE(0, held);
	leak(held);
	expect_releasedir(42, ReturnErrno(0));
	ASSERT_EQ(0, close(fd));
	expect_forget(42, 1);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

TEST_F(ReaddirPlus, enosys_falls_back)
{
	char buf[4096];
	vector<struct dirent> empty;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return (in.header.opcode == FUSE_READDIRPLUS &&
			    in.body.readdir.offset == 0);
		}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(ENOSYS)));
	expect_readdir(42, 0, empty);
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
}

TEST_F(ReaddirPlusAuto, plain_readdir_after_first_cookie)
{
	char buf[4096];
	vector<struct dirent> empty;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{"first", 43}});
	expect_readdir(42, 1, empty);
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
}

TEST_F(ReaddirPlusOld, ignores_unsupported_negotiation)
{
	char buf[4096];
	vector<struct dirent> empty;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_readdir(42, 0, empty);
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
}

TEST_F(ReaddirPlus, cache_entries_beyond_user_buffer)
{
	char buf[sizeof(struct dirent) + 32];
	struct stat sb;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{string(MAXNAMLEN, 'x'), 43}});
	expect_plus(1, {{"next_entry_alpha", 44}, {"next_entry_bravo", 45}});
	ASSERT_EQ((ssize_t)sizeof(struct dirent),
	    getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_EQ(1, ((struct dirent *)buf)->d_off);
	ASSERT_EQ(0, fstatat(fd, "next_entry_alpha", &sb, 0));
	ASSERT_EQ(0, fstatat(fd, "next_entry_bravo", &sb, 0));
	expect_plus(1, {{"next_entry_alpha", 44}, {"next_entry_bravo", 45}});
	expect_plus(3, {});
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_STREQ("next_entry_alpha", ((struct dirent *)buf)->d_name);
	expect_forget(43, 1);
	expect_forget(44, 2);
	expect_forget(45, 2);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

TEST_F(ReaddirPlus, copyout_fault_still_accounts_for_all_entries)
{
	char buf[4096];
	struct stat sb;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{"first", 43}, {"second", 44}});
	ASSERT_EQ(-1, getdirentries(fd, nullptr, sizeof(buf), nullptr));
	ASSERT_EQ(EFAULT, errno);
	ASSERT_EQ(0, fstatat(fd, "first", &sb, 0));
	ASSERT_EQ(0, fstatat(fd, "second", &sb, 0));
	expect_plus(0, {});
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	expect_forget(43, 1);
	expect_forget(44, 1);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

TEST_F(ReaddirPlus, invalid_cache_name_returns_lookup_reference)
{
	char buf[4096];
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{"bad/name", 43}});
	expect_forget(43, 1);
	expect_plus(1, {});
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_STREQ("bad/name", ((struct dirent *)buf)->d_name);
}

TEST_F(ReaddirPlus, invalid_length_still_accounts_for_following_entries)
{
	char buf[4096];
	struct stat sb;
	int fd = open_dir();
	ASSERT_LE(0, fd);
	expect_plus(0, {{string(MAXNAMLEN + 1, 'x'), 43}, {"valid", 44}});
	expect_forget(43, 1);
	ASSERT_EQ(-1, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(0, fstatat(fd, "valid", &sb, 0));
	expect_plus(0, {});
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	expect_forget(44, 1);
	ASSERT_EQ(-1, unmount("mountpoint", 0));
	ASSERT_EQ(EBUSY, errno);
	nap();
}

class ReaddirPlusBounds: public ReaddirPlus,
	public WithParamInterface<tuple<uint32_t, size_t>> {};

TEST_P(ReaddirPlusBounds, rejects_incomplete_records)
{
	const uint32_t namelen = get<0>(GetParam());
	const size_t reply_size = get<1>(GetParam());
	char buf[4096];
	int fd = open_dir();
	ASSERT_LE(0, fd);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return (in.header.opcode == FUSE_READDIRPLUS &&
			    in.body.readdir.offset == 0);
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		struct fuse_direntplus plus = {};

		plus.dirent.namelen = namelen;
		memset(out.body.bytes, 0, reply_size);
		memcpy(out.body.bytes, &plus,
		    min(reply_size, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS));
		out.header.error = 0;
		out.header.len = sizeof(out.header) + reply_size;
	}))).RetiresOnSaturation();
	ASSERT_EQ(-1, getdirentries(fd, buf, sizeof(buf), nullptr));
	ASSERT_EQ(EINVAL, errno);
	expect_plus(0, {});
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
}

INSTANTIATE_TEST_SUITE_P(Lengths, ReaddirPlusBounds, Values(
	make_tuple(0U, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS),
	make_tuple((uint32_t)MAXNAMLEN + 1, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS),
	make_tuple(UINT32_MAX, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS),
	make_tuple(1U, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS - 1),
	make_tuple(2U, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS + 1),
	make_tuple(1U, (size_t)FUSE_NAME_OFFSET_DIRENTPLUS + 1)
));

const char dot[] = ".";
const char dotdot[] = "..";

class ReaddirBounds: public Readdir,
	public WithParamInterface<tuple<uint32_t, size_t, int>> {};

/*
 * Validate lengths before calculating an aligned wire size.  A partial record
 * remains a short read under the native FUSE contract; an impossible name
 * length is an error.  Neither may consume the unreturned directory cookie.
 */
TEST_P(ReaddirBounds, malformed_record_does_not_advance)
{
	const uint64_t ino = 42;
	const uint32_t namelen = get<0>(GetParam());
	const size_t reply_size = get<1>(GetParam());
	const int expected_error = get<2>(GetParam());
	char buf[8192];
	int fd;

	expect_lookup("some_dir", ino);
	expect_opendir(ino);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
			    in.header.nodeid == ino &&
			    in.body.readdir.offset == 0);
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		struct fuse_dirent entry = {};

		entry.ino = 43;
		entry.off = 1234;
		entry.type = DT_REG;
		entry.namelen = namelen;
		memset(out.body.bytes, 'x', reply_size);
		memcpy(out.body.bytes, &entry,
		    min(reply_size, (size_t)FUSE_NAME_OFFSET));
		out.header.error = 0;
		out.header.len = sizeof(out.header) + reply_size;
	})))
	.WillOnce(Invoke(ReturnImmediate([](auto in __unused, auto& out) {
		out.header.error = 0;
		out.header.len = sizeof(out.header);
	})));

	fd = open("mountpoint/some_dir", O_RDONLY | O_DIRECTORY);
	ASSERT_LE(0, fd) << strerror(errno);
	leak(fd);
	errno = 0;
	if (expected_error != 0) {
		ASSERT_EQ(-1, getdirentries(fd, buf, sizeof(buf), nullptr));
		ASSERT_EQ(expected_error, errno);
	} else {
		ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	}
	ASSERT_EQ(0, getdirentries(fd, buf, sizeof(buf), nullptr));
}

INSTANTIATE_TEST_SUITE_P(Lengths, ReaddirBounds, Values(
	make_tuple(0U, (size_t)FUSE_NAME_OFFSET, EINVAL),
	make_tuple((uint32_t)MAXNAMLEN + 1, (size_t)FUSE_NAME_OFFSET, EINVAL),
	make_tuple(UINT32_MAX, (size_t)FUSE_NAME_OFFSET, EINVAL),
	make_tuple(1U, (size_t)FUSE_NAME_OFFSET - 1, 0),
	make_tuple(2U, (size_t)FUSE_NAME_OFFSET + 1, 0),
	make_tuple(1U, (size_t)FUSE_NAME_OFFSET + 1, 0)
));

TEST_F(Readdir, maximum_name_length)
{
	const uint64_t ino = 42;
	vector<struct dirent> ents(1);
	vector<struct dirent> empty;
	char buf[8192];
	struct dirent *de;
	int fd;

	expect_lookup("some_dir", ino);
	expect_opendir(ino);
	ents[0].d_fileno = 43;
	ents[0].d_off = 1234;
	ents[0].d_type = DT_REG;
	ents[0].d_namlen = MAXNAMLEN;
	memset(ents[0].d_name, 'x', MAXNAMLEN);
	ents[0].d_name[MAXNAMLEN] = '\0';
	expect_readdir(ino, 0, ents);
	expect_readdir(ino, 1234, empty);

	fd = open("mountpoint/some_dir", O_RDONLY | O_DIRECTORY);
	ASSERT_LE(0, fd) << strerror(errno);
	leak(fd);
	ASSERT_LT(0, getdirentries(fd, buf, sizeof(buf), nullptr));
	de = (struct dirent *)buf;
	EXPECT_EQ(43ul, de->d_fileno);
	EXPECT_EQ(1234, de->d_off);
	ASSERT_EQ(MAXNAMLEN, de->d_namlen);
	EXPECT_EQ(0, memcmp(de->d_name, ents[0].d_name, MAXNAMLEN + 1));
}

/* FUSE_READDIR returns nothing but "." and ".." */
TEST_F(Readdir, dots)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	vector<struct dirent> ents(2);
	vector<struct dirent> empty_ents(0);

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	ents[0].d_fileno = 2;
	ents[0].d_off = 2000;
	ents[0].d_namlen = sizeof(dotdot);
	ents[0].d_type = DT_DIR;
	strncpy(ents[0].d_name, dotdot, ents[0].d_namlen);
	ents[1].d_fileno = 3;
	ents[1].d_off = 3000;
	ents[1].d_namlen = sizeof(dot);
	ents[1].d_type = DT_DIR;
	strncpy(ents[1].d_name, dot, ents[1].d_namlen);
	expect_readdir(ino, 0, ents);
	expect_readdir(ino, 3000, empty_ents);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(nullptr, de) << strerror(errno);
	EXPECT_EQ(2ul, de->d_fileno);
	EXPECT_EQ(DT_DIR, de->d_type);
	EXPECT_EQ(sizeof(dotdot), de->d_namlen);
	EXPECT_EQ(0, strcmp(dotdot, de->d_name));

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(nullptr, de) << strerror(errno);
	EXPECT_EQ(3ul, de->d_fileno);
	EXPECT_EQ(DT_DIR, de->d_type);
	EXPECT_EQ(sizeof(dot), de->d_namlen);
	EXPECT_EQ(0, strcmp(dot, de->d_name));

	ASSERT_EQ(nullptr, readdir(dir));
	ASSERT_EQ(0, errno);

	leakdir(dir);
}

TEST_F(Readdir, eio)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
				in.header.nodeid == ino &&
				in.body.readdir.offset == 0);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(EIO)));

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_EQ(nullptr, de);
	ASSERT_EQ(EIO, errno);

	leakdir(dir);
}

/*
 * getdirentries(2) can use a larger buffer size than readdir(3).  It also has
 * some additional non-standardized fields in the returned dirent.
 */
TEST_F(Readdir, getdirentries_empty)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	int fd;
	char buf[8192];
	ssize_t r;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
				in.header.nodeid == ino &&
				in.body.readdir.size == 8192);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		out.header.error = 0;
		out.header.len = sizeof(out.header);
	})));

	fd = open(FULLPATH, O_DIRECTORY);
	ASSERT_LE(0, fd) << strerror(errno);
	r = getdirentries(fd, buf, sizeof(buf), 0);
	ASSERT_EQ(0, r) << strerror(errno);

	leak(fd);
}

/*
 * The dirent.d_off field can be used with lseek to position the directory so
 * that getdirentries will return the subsequent dirent.
 */
TEST_F(Readdir, getdirentries_seek)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	vector<struct dirent> ents0(2);
	vector<struct dirent> ents1(1);
	uint64_t ino = 42;
	int fd;
	const size_t bufsize = 8192;
	char buf[bufsize];
	struct dirent *de0, *de1;
	ssize_t r;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	ents0[0].d_fileno = 2;
	ents0[0].d_off = 2000;
	ents0[0].d_namlen = sizeof(dotdot);
	ents0[0].d_type = DT_DIR;
	strncpy(ents0[0].d_name, dotdot, ents0[0].d_namlen);
	expect_readdir(ino, 0, ents0);
	ents0[1].d_fileno = 3;
	ents0[1].d_off = 3000;
	ents0[1].d_namlen = sizeof(dot);
	ents0[1].d_type = DT_DIR;
	ents1[0].d_fileno = 3;
	ents1[0].d_off = 3000;
	ents1[0].d_namlen = sizeof(dot);
	ents1[0].d_type = DT_DIR;
	strncpy(ents1[0].d_name, dot, ents1[0].d_namlen);
	expect_readdir(ino, 0, ents0);
	expect_readdir(ino, 2000, ents1);

	fd = open(FULLPATH, O_DIRECTORY);
	ASSERT_LE(0, fd) << strerror(errno);
	r = getdirentries(fd, buf, sizeof(buf), 0);
	ASSERT_LT(0, r) << strerror(errno);
	de0 = (struct dirent*)&buf[0];
	ASSERT_EQ(2000, de0->d_off);
	ASSERT_LT(de0->d_reclen + offsetof(struct dirent, d_fileno), bufsize);
	de1 = (struct dirent*)(&(buf[de0->d_reclen]));
	ASSERT_EQ(3ul, de1->d_fileno);

	r = lseek(fd, de0->d_off, SEEK_SET);
	ASSERT_LE(0, r);
	r = getdirentries(fd, buf, sizeof(buf), 0);
	ASSERT_LT(0, r) << strerror(errno);
	de0 = (struct dirent*)&buf[0];
	ASSERT_EQ(3000, de0->d_off);
}

/* 
 * Nothing bad should happen if getdirentries is called on two file descriptors
 * which were concurrently open, but one has already been closed.
 * This is a regression test for a specific bug dating from r238402.
 */
TEST_F(Readdir, getdirentries_concurrent)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	int fd0, fd1;
	char buf[8192];
	ssize_t r;

	FuseTest::expect_lookup(RELPATH, ino, S_IFDIR | 0755, 0, 2);
	expect_opendir(ino);

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
				in.header.nodeid == ino &&
				in.body.readdir.size == 8192);
		}, Eq(true)),
		_)
	).Times(2)
	.WillRepeatedly(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		out.header.error = 0;
		out.header.len = sizeof(out.header);
	})));

	fd0 = open(FULLPATH, O_DIRECTORY);
	ASSERT_LE(0, fd0) << strerror(errno);

	fd1 = open(FULLPATH, O_DIRECTORY);
	ASSERT_LE(0, fd1) << strerror(errno);

	r = getdirentries(fd0, buf, sizeof(buf), 0);
	ASSERT_EQ(0, r) << strerror(errno);

	EXPECT_EQ(0, close(fd0)) << strerror(errno);

	r = getdirentries(fd1, buf, sizeof(buf), 0);
	ASSERT_EQ(0, r) << strerror(errno);

	leak(fd0);
	leak(fd1);
}

/*
 * FUSE_READDIR returns nothing, not even "." and "..".  This is legal, though
 * the filesystem obviously won't be fully functional.
 */
TEST_F(Readdir, nodots)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
				in.header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		out.header.error = 0;
		out.header.len = sizeof(out.header);
	})));

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);
	errno = 0;
	ASSERT_EQ(nullptr, readdir(dir));
	ASSERT_EQ(0, errno);

	leakdir(dir);
}

/*
 * FUSE_READDIR returns a path with an embedded NUL. Obviously illegal, but
 * nothing bad should happen.
 */
TEST_F(Readdir, nul)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	vector<struct dirent> ents(1);
	vector<struct dirent> empty_ents(0);
	const char nul[] = "foo\0bar";

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	ents[0].d_fileno = 4;
	ents[0].d_off = 4000;
	ents[0].d_namlen = sizeof(nul);
	ents[0].d_type = DT_REG;
	strncpy(ents[0].d_name, nul, ents[0].d_namlen);
	expect_readdir(ino, 0, ents);
	expect_readdir(ino, 4000, empty_ents);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(nullptr, de) << strerror(errno);
	EXPECT_EQ(4ul, de->d_fileno);
	EXPECT_EQ(DT_REG, de->d_type);
	EXPECT_EQ(sizeof(nul), de->d_namlen);
	EXPECT_EQ(0, strcmp(nul, de->d_name));

	ASSERT_EQ(nullptr, readdir(dir));
	ASSERT_EQ(0, errno);

	leakdir(dir);
}


/* telldir(3) and seekdir(3) should work with fuse */
TEST_F(Readdir, seekdir)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	/*
	 * use enough entries to be > 4096 bytes, so getdirentries must be
	 * called
	 * multiple times.
	 */
	vector<struct dirent> ents0(122), ents1(102), ents2(30);
	long bookmark;
	int i = 0;

	for (auto& it: ents0) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}
	for (auto& it: ents1) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}
	for (auto& it: ents2) {
		snprintf(it.d_name, MAXNAMLEN, "file.%d", i);
		it.d_fileno = 2 + i;
		it.d_off = (2 + i) * 1000;
		it.d_namlen = strlen(it.d_name);
		it.d_type = DT_REG;
		i++;
	}

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	expect_readdir(ino, 0, ents0);
	expect_readdir(ino, 123000, ents1);
	expect_readdir(ino, 225000, ents2);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);

	for (i=0; i < 128; i++) {
		errno = 0;
		de = readdir(dir);
		ASSERT_NE(nullptr, de) << strerror(errno);
		EXPECT_EQ(2 + (ino_t)i, de->d_fileno);
	}
	bookmark = telldir(dir);

	for (; i < 232; i++) {
		errno = 0;
		de = readdir(dir);
		ASSERT_NE(nullptr, de) << strerror(errno);
		EXPECT_EQ(2 + (ino_t)i, de->d_fileno);
	}

	seekdir(dir, bookmark);
	de = readdir(dir);
	ASSERT_NE(nullptr, de) << strerror(errno);
	EXPECT_EQ(130ul, de->d_fileno);

	leakdir(dir);
}

/*
 * FUSE_READDIR returns a path with an embedded /. Obviously illegal, but
 * nothing bad should happen.
 */
TEST_F(Readdir, slash)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;
	struct dirent *de;
	vector<struct dirent> ents(1);
	vector<struct dirent> empty_ents(0);
	const char foobar[] = "foo/bar";

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);
	ents[0].d_fileno = 4;
	ents[0].d_off = 4000;
	ents[0].d_namlen = sizeof(foobar);
	ents[0].d_type = DT_REG;
	strncpy(ents[0].d_name, foobar, ents[0].d_namlen);
	expect_readdir(ino, 0, ents);
	expect_readdir(ino, 4000, empty_ents);

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);

	errno = 0;
	de = readdir(dir);
	ASSERT_NE(nullptr, de) << strerror(errno);
	EXPECT_EQ(4ul, de->d_fileno);
	EXPECT_EQ(DT_REG, de->d_type);
	EXPECT_EQ(sizeof(foobar), de->d_namlen);
	EXPECT_EQ(0, strcmp(foobar, de->d_name));

	ASSERT_EQ(nullptr, readdir(dir));
	ASSERT_EQ(0, errno);

	leakdir(dir);
}

TEST_F(Readdir_7_8, nodots)
{
	const char FULLPATH[] = "mountpoint/some_dir";
	const char RELPATH[] = "some_dir";
	uint64_t ino = 42;
	DIR *dir;

	expect_lookup(RELPATH, ino);
	expect_opendir(ino);

	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_READDIR &&
				in.header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		out.header.error = 0;
		out.header.len = sizeof(out.header);
	})));

	errno = 0;
	dir = opendir(FULLPATH);
	ASSERT_NE(nullptr, dir) << strerror(errno);
	errno = 0;
	ASSERT_EQ(nullptr, readdir(dir));
	ASSERT_EQ(0, errno);

	leakdir(dir);
}
