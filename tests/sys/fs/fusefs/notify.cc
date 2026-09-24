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
#include <sys/types.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
}

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;

/*
 * FUSE asynchonous notification
 *
 * FUSE servers can send unprompted notification messages for things like cache
 * invalidation.  This file tests our client's handling of those messages.
 */

class Notify: public FuseTest,
	      public WithParamInterface<int>
{
public:
virtual void SetUp() {
	m_init_flags |= GetParam();
	FuseTest::SetUp();
}

/* Ignore an optional FUSE_FSYNC */
void maybe_expect_fsync(uint64_t ino)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_FSYNC &&
				in.header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(0)));
}

void expect_lookup(uint64_t parent, const char *relpath, uint64_t ino,
	off_t size, Sequence &seq)
{
	EXPECT_LOOKUP(parent, relpath)
	.InSequence(seq)
	.WillOnce(Invoke(
		ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, entry);
		out.body.entry.attr.mode = S_IFREG | 0644;
		out.body.entry.nodeid = ino;
		out.body.entry.attr.ino = ino;
		out.body.entry.attr.nlink = 1;
		out.body.entry.attr.size = size;
		out.body.entry.attr_valid = UINT64_MAX;
		out.body.entry.entry_valid = UINT64_MAX;
	})));
}
};

class NotifyWriteback: public Notify {
public:
virtual void SetUp() {
	m_init_flags |= FUSE_WRITEBACK_CACHE;
	m_async = true;
	Notify::SetUp();
	if (IsSkipped())
		return;
}

void expect_write(uint64_t ino, uint64_t offset, uint64_t size,
	const void *contents)
{
	FuseTest::expect_write(ino, offset, size, size, 0, 0, contents);
}

};

struct inval_entry_args {
	MockFS		*mock;
	ino_t		parent;
	const char	*name;
	size_t		namelen;
};

static void* inval_entry(void* arg) {
	const struct inval_entry_args *iea = (struct inval_entry_args*)arg;
	ssize_t r;

	r = iea->mock->notify_inval_entry(iea->parent, iea->name, iea->namelen);
	if (r >= 0)
		return 0;
	else
		return (void*)(intptr_t)errno;
}

struct inval_inode_args {
	MockFS		*mock;
	ino_t		ino;
	off_t		off;
	ssize_t		len;
};

struct store_args {
	MockFS		*mock;
	ino_t		nodeid;
	off_t		offset;
	ssize_t		size;
	const void*	data;
};

static void* inval_inode(void* arg) {
	const struct inval_inode_args *iia = (struct inval_inode_args*)arg;
	ssize_t r;

	r = iia->mock->notify_inval_inode(iia->ino, iia->off, iia->len);
	if (r >= 0)
		return 0;
	else
		return (void*)(intptr_t)errno;
}

static void* store(void* arg) {
	const struct store_args *sa = (struct store_args*)arg;
	ssize_t r;

	r = sa->mock->notify_store(sa->nodeid, sa->offset, sa->data, sa->size);
	if (r >= 0)
		return 0;
	else
		return (void*)(intptr_t)errno;
}

/* Invalidate a nonexistent entry */
TEST_P(Notify, inval_entry_nonexistent)
{
	const static char *name = "foo";
	struct inval_entry_args iea;
	void *thr0_value;
	pthread_t th0;

	iea.mock = m_mock;
	iea.parent = FUSE_ROOT_ID;
	iea.name = name;
	iea.namelen = strlen(name);
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_entry, &iea))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	/* It's not an error for an entry to not be cached */
	EXPECT_EQ(0, (intptr_t)thr0_value);
}

/* Invalidate a cached entry */
TEST_P(Notify, inval_entry)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	struct inval_entry_args iea;
	struct stat sb;
	void *thr0_value;
	uint64_t ino0 = 42;
	uint64_t ino1 = 43;
	Sequence seq;
	pthread_t th0;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino0, 0, seq);
	expect_lookup(FUSE_ROOT_ID, RELPATH, ino1, 0, seq);

	/* Fill the entry cache */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(ino0, sb.st_ino);

	/* Now invalidate the entry */
	iea.mock = m_mock;
	iea.parent = FUSE_ROOT_ID;
	iea.name = RELPATH;
	iea.namelen = strlen(RELPATH);
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_entry, &iea))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* The second lookup should return the alternate ino */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(ino1, sb.st_ino);
}

/*
 * Invalidate a cached entry beneath the root, which uses a slightly different
 * code path.
 */
TEST_P(Notify, inval_entry_below_root)
{
	const static char FULLPATH[] = "mountpoint/some_dir/foo";
	const static char DNAME[] = "some_dir";
	const static char FNAME[] = "foo";
	struct inval_entry_args iea;
	struct stat sb;
	void *thr0_value;
	uint64_t dir_ino = 41;
	uint64_t ino0 = 42;
	uint64_t ino1 = 43;
	Sequence seq;
	pthread_t th0;

	EXPECT_LOOKUP(FUSE_ROOT_ID, DNAME)
	.WillOnce(Invoke(
		ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, entry);
		out.body.entry.attr.mode = S_IFDIR | 0755;
		out.body.entry.nodeid = dir_ino;
		out.body.entry.attr.nlink = 2;
		out.body.entry.attr_valid = UINT64_MAX;
		out.body.entry.entry_valid = UINT64_MAX;
	})));
	expect_lookup(dir_ino, FNAME, ino0, 0, seq);
	expect_lookup(dir_ino, FNAME, ino1, 0, seq);

	/* Fill the entry cache */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(ino0, sb.st_ino);

	/* Now invalidate the entry */
	iea.mock = m_mock;
	iea.parent = dir_ino;
	iea.name = FNAME;
	iea.namelen = strlen(FNAME);
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_entry, &iea))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* The second lookup should return the alternate ino */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(ino1, sb.st_ino);
}

/* Invalidating an entry invalidates the parent directory's attributes */
TEST_P(Notify, inval_entry_invalidates_parent_attrs)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	struct inval_entry_args iea;
	struct stat sb;
	void *thr0_value;
	uint64_t ino = 42;
	Sequence seq;
	pthread_t th0;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino, 0, seq);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETATTR &&
				in.header.nodeid == FUSE_ROOT_ID);
		}, Eq(true)),
		_)
	).Times(2)
	.WillRepeatedly(Invoke(ReturnImmediate([=](auto i __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, attr);
		out.body.attr.attr.mode = S_IFDIR | 0755;
		out.body.attr.attr_valid = UINT64_MAX;
	})));

	/* Fill the attr and entry cache */
	ASSERT_EQ(0, stat("mountpoint", &sb)) << strerror(errno);
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);

	/* Now invalidate the entry */
	iea.mock = m_mock;
	iea.parent = FUSE_ROOT_ID;
	iea.name = RELPATH;
	iea.namelen = strlen(RELPATH);
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_entry, &iea))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* /'s attribute cache should be cleared */
	ASSERT_EQ(0, stat("mountpoint", &sb)) << strerror(errno);
}


TEST_P(Notify, inval_inode_nonexistent)
{
	struct inval_inode_args iia;
	ino_t ino = 42;
	void *thr0_value;
	pthread_t th0;

	iia.mock = m_mock;
	iia.ino = ino;
	iia.off = 0;
	iia.len = 0;
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_inode, &iia))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	/* It's not an error for an inode to not be cached */
	EXPECT_EQ(0, (intptr_t)thr0_value);
}

TEST_P(Notify, inval_inode_with_clean_cache)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	const char CONTENTS0[] = "abcdefgh";
	const char CONTENTS1[] = "ijklmnopqrstuvwxyz";
	struct inval_inode_args iia;
	struct stat sb;
	ino_t ino = 42;
	void *thr0_value;
	Sequence seq;
	uid_t uid = 12345;
	pthread_t th0;
	ssize_t size0 = sizeof(CONTENTS0);
	ssize_t size1 = sizeof(CONTENTS1);
	char buf[80];
	int fd;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino, size0, seq);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETATTR &&
				in.header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto i __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, attr);
		out.body.attr.attr.mode = S_IFREG | 0644;
		out.body.attr.attr_valid = UINT64_MAX;
		out.body.attr.attr.size = size1;
		out.body.attr.attr.uid = uid;
	})));
	expect_read(ino, 0, size0, size0, CONTENTS0);
	expect_read(ino, 0, size1, size1, CONTENTS1);

	/* Fill the data cache */
	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(size0, read(fd, buf, size0)) << strerror(errno);
	EXPECT_EQ(0, memcmp(buf, CONTENTS0, size0));

	/* Evict the data cache */
	iia.mock = m_mock;
	iia.ino = ino;
	iia.off = 0;
	iia.len = 0;
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_inode, &iia))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* cache attributes were purged; this will trigger a new GETATTR */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(uid, sb.st_uid);
	EXPECT_EQ(size1, sb.st_size);

	/* This read should not be serviced by cache */
	ASSERT_EQ(0, lseek(fd, 0, SEEK_SET)) << strerror(errno);
	ASSERT_EQ(size1, read(fd, buf, size1)) << strerror(errno);
	EXPECT_EQ(0, memcmp(buf, CONTENTS1, size1));

	leak(fd);
}

/*
 * Attempting to invalidate an entry or inode after unmounting should fail, but
 * nothing bad should happen.
 * https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=290519
 */
TEST_P(Notify, notify_after_unmount)
{
	const static char *name = "foo";
	struct inval_entry_args iea;

	expect_destroy(0);

	m_mock->unmount();

	iea.mock = m_mock;
	iea.parent = FUSE_ROOT_ID;
	iea.name = name;
	iea.namelen = strlen(name);
	iea.mock->notify_inval_entry(iea.parent, iea.name, iea.namelen, ENODEV);
}

/* FUSE_NOTIFY_STORE with a file that's not in the entry cache */
TEST_P(Notify, store_nonexistent)
{
	struct store_args sa;
	ino_t ino = 42;
	void *thr0_value;
	pthread_t th0;

	sa.mock = m_mock;
	sa.nodeid = ino;
	sa.offset = 0;
	sa.size = 0;
	sa.data = "";
	ASSERT_EQ(0, pthread_create(&th0, NULL, store, &sa)) << strerror(errno);
	pthread_join(th0, &thr0_value);
	/* Linux reports an unknown node even for a zero-length STORE. */
	EXPECT_EQ(ENOENT, (intptr_t)thr0_value);
}

/* Store data into for a file that does not yet have anything cached */
TEST_P(Notify, store_with_blank_cache)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	const char CONTENTS1[] = "ijklmnopqrstuvwxyz";
	struct store_args sa;
	ino_t ino = 42;
	void *thr0_value;
	Sequence seq;
	pthread_t th0;
	ssize_t size1 = sizeof(CONTENTS1);
	char buf[80];
	int fd;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino, size1, seq);
	expect_open(ino, 0, 1);

	/* Fill the data cache */
	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);

	/* Evict the data cache */
	sa.mock = m_mock;
	sa.nodeid = ino;
	sa.offset = 0;
	sa.size = size1;
	sa.data = (const void*)CONTENTS1;
	ASSERT_EQ(0, pthread_create(&th0, NULL, store, &sa)) << strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* This read should be serviced by cache */
	ASSERT_EQ(size1, read(fd, buf, size1)) << strerror(errno);
	EXPECT_EQ(0, memcmp(buf, CONTENTS1, size1));

	leak(fd);
}


/* STORE updates clean pages without scheduling a WRITE back to the daemon. */
TEST_P(Notify, store_clean_cache)
{
	Sequence seq;
	const char initial[] = "abcdefgh";
	const char expected[] = "abXYZfgh";
	char buf[sizeof(initial)];
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, sizeof(initial), seq);
	expect_open(ino, 0, 1);
	expect_read(ino, 0, sizeof(initial), sizeof(initial), initial);
	int fd = open("mountpoint/foo", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ((ssize_t)sizeof(buf), pread(fd, buf, sizeof(buf), 0));
	ASSERT_EQ(0, m_mock->notify_store(ino, 2, "XYZ", 3));
	ASSERT_EQ((ssize_t)sizeof(buf), pread(fd, buf, sizeof(buf), 0));
	EXPECT_EQ(0, memcmp(buf, expected, sizeof(buf)));
	maybe_expect_fsync(ino);
	ASSERT_EQ(0, fsync(fd));
	leak(fd);
}

/* A partial invalid page cannot be advertised as completely initialized. */
TEST_P(Notify, store_partial_blank_page)
{
	Sequence seq;
	std::string contents(getpagesize(), 's');
	std::string buf(contents.size(), '?');
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, contents.size(), seq);
	expect_open(ino, 0, 1);
	expect_read(ino, 0, contents.size(), contents.size(), contents.data());
	int fd = open("mountpoint/foo", O_RDONLY);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, m_mock->notify_store(ino, 17, "XYZ", 3));
	ASSERT_EQ((ssize_t)buf.size(), pread(fd, &buf[0], buf.size(), 0));
	EXPECT_EQ(contents, buf);
	leak(fd);
}

/* New complete pages and a partial EOF page must be readable without RPCs. */
TEST_P(Notify, store_extends_and_maps)
{
	Sequence seq;
	std::string contents(2 * getpagesize() + 37, 's');
	std::string buf(contents.size(), '?');
	struct stat sb;
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, 0, seq);
	expect_open(ino, 0, 1);
	int fd = open("mountpoint/foo", O_RDONLY);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, m_mock->notify_store(ino, 0, contents.data(), contents.size()));
	ASSERT_EQ(0, fstat(fd, &sb));
	EXPECT_EQ((off_t)contents.size(), sb.st_size);
	ASSERT_EQ((ssize_t)buf.size(), pread(fd, &buf[0], buf.size(), 0));
	EXPECT_EQ(contents, buf);
	void *mapping = mmap(NULL, contents.size(), PROT_READ, MAP_SHARED, fd, 0);
	ASSERT_NE(MAP_FAILED, mapping);
	EXPECT_EQ(0, memcmp(mapping, contents.data(), contents.size()));
	/* The remainder of the EOF page must not disclose old physical data. */
	const char *bytes = static_cast<const char *>(mapping);
	for (size_t i = contents.size(); i < 3 * (size_t)getpagesize(); i++)
		ASSERT_EQ(0, bytes[i]);
	ASSERT_EQ(0, munmap(mapping, contents.size()));
	leak(fd);
}

TEST_P(Notify, store_offset_overflow)
{
	ASSERT_EQ(-1, m_mock->notify_store(42, -1, "", 0));
	EXPECT_EQ(EINVAL, errno);
	ASSERT_EQ(-1, m_mock->notify_store(42, INT64_MAX, "x", 1));
	EXPECT_EQ(EINVAL, errno);
}


/* The inode remains usable when only its pathname cache has expired. */
TEST_P(Notify, store_expired_entry)
{
	const char contents[] = "cached";
	char buf[sizeof(contents)];
	ino_t ino = 42;

	EXPECT_LOOKUP(FUSE_ROOT_ID, "foo")
	.WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, entry);
		out.body.entry.nodeid = ino;
		out.body.entry.attr.ino = ino;
		out.body.entry.attr.mode = S_IFREG | 0644;
		out.body.entry.attr.nlink = 1;
		out.body.entry.attr.size = sizeof(contents);
		out.body.entry.attr_valid = UINT64_MAX;
		out.body.entry.entry_valid = 0;
	})));
	expect_open(ino, 0, 1);
	int fd = open("mountpoint/foo", O_RDONLY);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, m_mock->notify_store(ino, 0, contents, sizeof(contents)));
	ASSERT_EQ((ssize_t)sizeof(buf), read(fd, buf, sizeof(buf)));
	EXPECT_EQ(0, memcmp(buf, contents, sizeof(buf)));
	leak(fd);
}

TEST_P(Notify, store_malformed)
{
	std::unique_ptr<mockfs_buf_out> out(new mockfs_buf_out);
	out->header.unique = 0;
	out->header.error = FUSE_NOTIFY_STORE;
	out->expected_errno = EINVAL;
	out->header.len = sizeof(out->header) + sizeof(out->body.store) - 1;
	m_mock->write_response(*out);
	out->header.len = sizeof(out->header) + sizeof(out->body.store);
	out->body.store.nodeid = 42;
	out->body.store.offset = 0;
	out->body.store.size = 1; /* Payload missing. */
	m_mock->write_response(*out);
	out->body.store.size = 0;
	out->header.len++; /* Unexpected trailing byte. */
	m_mock->write_response(*out);
	/* An invalid STORE must not disconnect the daemon. */
	ASSERT_EQ(-1, m_mock->notify_store(42, 0, "", 0));
	EXPECT_EQ(ENOENT, errno);
}

/* STORE must preserve both untouched dirty bytes and their writeback state. */
TEST_P(NotifyWriteback, store_dirty_cache)
{
	Sequence seq;
	const char initial[] = "abcdefgh";
	const char expected[] = "abXYZfgh";
	char buf[sizeof(initial)];
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, 0, seq);
	expect_open(ino, 0, 1);
	int fd = open("mountpoint/foo", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ((ssize_t)sizeof(initial), write(fd, initial, sizeof(initial)));
	ASSERT_EQ(0, m_mock->notify_store(ino, 2, "XYZ", 3));
	ASSERT_EQ((ssize_t)sizeof(buf), pread(fd, buf, sizeof(buf), 0));
	EXPECT_EQ(0, memcmp(buf, expected, sizeof(buf)));
	expect_write(ino, 0, sizeof(expected), expected);
	maybe_expect_fsync(ino);
	ASSERT_EQ(0, fsync(fd));
	leak(fd);
}


/* Extending the file must neither flush nor invalidate an existing dirty page. */
TEST_P(NotifyWriteback, store_extends_dirty_cache)
{
	Sequence seq;
	std::string initial(getpagesize(), 'd');
	std::string supplied(getpagesize(), 's');
	std::string buf(initial.size(), '?');
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, 0, seq);
	expect_open(ino, 0, 1);
	int fd = open("mountpoint/foo", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ((ssize_t)initial.size(), write(fd, initial.data(), initial.size()));
	ASSERT_EQ(0, m_mock->notify_store(ino, getpagesize(), supplied.data(),
	    supplied.size()));
	ASSERT_EQ((ssize_t)buf.size(), pread(fd, &buf[0], buf.size(), 0));
	EXPECT_EQ(initial, buf);
	std::string readback(supplied.size(), '?');
	ASSERT_EQ((ssize_t)readback.size(), pread(fd, &readback[0], readback.size(),
	    getpagesize()));
	EXPECT_EQ(supplied, readback);
	expect_write(ino, 0, initial.size(), initial.data());
	maybe_expect_fsync(ino);
	ASSERT_EQ(0, fsync(fd));
	leak(fd);
}


/* Reading an incompletely valid block may flush only the preexisting dirt. */
TEST_P(NotifyWriteback, store_extends_partial_dirty_cache)
{
	Sequence seq;
	const char initial[] = "dirty";
	std::string supplied(getpagesize(), 's');
	std::string server(2 * getpagesize(), '\0');
	memcpy(&server[0], initial, sizeof(initial));
	memcpy(&server[getpagesize()], supplied.data(), supplied.size());
	std::string buf(server.size(), '?');
	ino_t ino = 42;

	expect_lookup(FUSE_ROOT_ID, "foo", ino, 0, seq);
	expect_open(ino, 0, 1);
	int fd = open("mountpoint/foo", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ((ssize_t)sizeof(initial), write(fd, initial, sizeof(initial)));
	ASSERT_EQ(0, m_mock->notify_store(ino, getpagesize(), supplied.data(),
	    supplied.size()));
	/* STORE itself must not issue either RPC. The following read may. */
	expect_write(ino, 0, sizeof(initial), initial);
	expect_read(ino, 0, server.size(), server.size(), server.data());
	ASSERT_EQ((ssize_t)buf.size(), pread(fd, &buf[0], buf.size(), 0));
	EXPECT_EQ(server, buf);
	maybe_expect_fsync(ino);
	ASSERT_EQ(0, fsync(fd));
	leak(fd);
}

TEST_P(NotifyWriteback, inval_inode_with_dirty_cache)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	const char CONTENTS[] = "abcdefgh";
	struct inval_inode_args iia;
	ino_t ino = 42;
	void *thr0_value;
	Sequence seq;
	pthread_t th0;
	ssize_t bufsize = sizeof(CONTENTS);
	int fd;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino, 0, seq);
	expect_open(ino, 0, 1);

	/* Fill the data cache */
	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ(bufsize, write(fd, CONTENTS, bufsize)) << strerror(errno);

	expect_write(ino, 0, bufsize, CONTENTS);
	/* 
	 * The FUSE protocol does not require an fsync here, but FreeBSD's
	 * bufobj_invalbuf sends it anyway
	 */
	maybe_expect_fsync(ino);

	/* Evict the data cache */
	iia.mock = m_mock;
	iia.ino = ino;
	iia.off = 0;
	iia.len = 0;
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_inode, &iia))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	leak(fd);
}

TEST_P(NotifyWriteback, inval_inode_attrs_only)
{
	const static char FULLPATH[] = "mountpoint/foo";
	const static char RELPATH[] = "foo";
	const char CONTENTS[] = "abcdefgh";
	struct inval_inode_args iia;
	struct stat sb;
	uid_t uid = 12345;
	ino_t ino = 42;
	void *thr0_value;
	Sequence seq;
	pthread_t th0;
	ssize_t bufsize = sizeof(CONTENTS);
	int fd;

	expect_lookup(FUSE_ROOT_ID, RELPATH, ino, 0, seq);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_WRITE);
		}, Eq(true)),
		_)
	).Times(0);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETATTR &&
				in.header.nodeid == ino);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto i __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, attr);
		out.body.attr.attr.mode = S_IFREG | 0644;
		out.body.attr.attr_valid = UINT64_MAX;
		out.body.attr.attr.size = bufsize;
		out.body.attr.attr.uid = uid;
	})));

	/* Fill the data cache */
	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(bufsize, write(fd, CONTENTS, bufsize)) << strerror(errno);

	/* Evict the attributes, but not data cache */
	iia.mock = m_mock;
	iia.ino = ino;
	iia.off = -1;
	iia.len = 0;
	ASSERT_EQ(0, pthread_create(&th0, NULL, inval_inode, &iia))
		<< strerror(errno);
	pthread_join(th0, &thr0_value);
	EXPECT_EQ(0, (intptr_t)thr0_value);

	/* cache attributes were been purged; this will trigger a new GETATTR */
	ASSERT_EQ(0, stat(FULLPATH, &sb)) << strerror(errno);
	EXPECT_EQ(uid, sb.st_uid);
	EXPECT_EQ(bufsize, sb.st_size);

	leak(fd);
}

/*
 * Attempting asynchronous invalidation of an Entry before mounting the file
 * system should fail, but nothing bad should happen.
 *
 * Note that invalidating an inode before mount goes through the same path, and
 * is not separately tested.
 *
 * https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=290519
 */
TEST(PreMount, inval_entry_before_mount)
{
	const static char name[] = "foo";
	size_t namelen = strlen(name);
	struct mockfs_buf_out *out;
	int r;
	int fuse_fd;

	fuse_fd = open("/dev/fuse", O_CLOEXEC | O_RDWR);
	ASSERT_GE(fuse_fd, 0) << strerror(errno);

	out = new mockfs_buf_out;
	out->header.unique = 0;	/* 0 means asynchronous notification */
	out->header.error = FUSE_NOTIFY_INVAL_ENTRY;
	out->body.inval_entry.parent = FUSE_ROOT_ID;
	out->body.inval_entry.namelen = namelen;
	strlcpy((char*)&out->body.bytes + sizeof(out->body.inval_entry),
		name, sizeof(out->body.bytes) - sizeof(out->body.inval_entry));
	out->header.len = sizeof(out->header) + sizeof(out->body.inval_entry) +
		namelen;
	r = write(fuse_fd, out, out->header.len);
	EXPECT_EQ(-1, r);
	EXPECT_EQ(ENODEV, errno);
	delete out;
}

/*
 * Try with and without async reads, because it affects the type of vnode lock
 * acquired in fuse_internal_invalidate_entry.
 */
INSTANTIATE_TEST_SUITE_P(N, Notify, Values(0, FUSE_ASYNC_READ));
INSTANTIATE_TEST_SUITE_P(N, NotifyWriteback, Values(0, FUSE_ASYNC_READ));

class LinuxNotify: public FuseTest {
void SetUp() override {
	m_linux_errnos = true;
	FuseTest::SetUp();
}
};

/* Positive asynchronous notification codes must bypass errno translation. */
TEST_F(LinuxNotify, notification_opcode)
{
	EXPECT_EQ(0, m_mock->notify_inval_inode(999, -1, 0));
}
