/* SPDX-License-Identifier: BSD-2-Clause */
/* Per-open Linux-daemon handles; run exclusively in disposable guests. */
extern "C" {
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/linker.h>
#include <fcntl.h>
#include <dirent.h>
#include <aio.h>
#include <unistd.h>
}
#include "mockfs.hh"
#include "utils.hh"
using namespace testing;

class OpenFile: public FuseTest {
public:
Sequence open_sequence;
unsigned expected_releases = 0;
sem_t release_seen;
void TearDown() override {
	struct timespec deadline;
	ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &deadline));
	deadline.tv_sec += 5;
	for (unsigned n = 0; n < expected_releases; n++)
		EXPECT_EQ(0, sem_timedwait(&release_seen, &deadline));
	FuseTest::TearDown();
	EXPECT_EQ(0, sem_destroy(&release_seen));
}
void SetUp() override {
	ASSERT_EQ(0, sem_init(&release_seen, 0, 0));
	m_linux_errnos = true;
	FuseTest::SetUp();
}
void lookup(int times = 1, size_t size = 4096) {
	FuseTest::expect_lookup("file", 42, S_IFREG | 0666, size, times);
}
void opened(uint64_t fh, uint32_t flags, uint32_t reply = FOPEN_DIRECT_IO) {
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == FUSE_OPEN && in.header.nodeid == 42 &&
		    in.body.open.flags == (flags | 00100000);
	}, Eq(true)), _)).InSequence(open_sequence).WillOnce(Invoke(ReturnImmediate([=](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, open);
		out.body.open.fh = fh;
		out.body.open.open_flags = reply;
	})));
}
void flushed(uint64_t fh, int times = 1) {
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == FUSE_FLUSH && in.body.flush.fh == fh;
	}, Eq(true)), _)).Times(times).WillRepeatedly(Invoke(ReturnErrno(0)));
}
void released(uint64_t fh, uint32_t flags) {
	expected_releases++;
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == FUSE_RELEASE &&
		    in.body.release.fh == fh && in.body.release.flags == (flags | 00100000);
	}, Eq(true)), _)).WillOnce(Invoke([this](auto in, auto& out) {
		ReturnErrno(0)(in, out);
		out.back()->reply_sent = &release_seen;
	}));
}
void written(uint64_t fh, uint32_t flags, off_t offset) {
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == FUSE_WRITE && in.body.write.fh == fh &&
		    in.body.write.flags == (flags | 00100000) && in.body.write.offset == (uint64_t)offset &&
		    in.body.write.size == 1;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, write);
		out.body.write.size = 1;
	})));
}
};

TEST_F(OpenFile, independent_handles_and_append)
{
	lookup(2);
	opened(11, O_RDWR | 00002000);
	opened(12, O_RDWR);
	written(11, O_RDWR | 00002000, 4096);
	written(12, O_RDWR, 0);
	flushed(11); released(11, O_RDWR | 00002000);
	flushed(12); released(12, O_RDWR);
	int a = open("mountpoint/file", O_RDWR | O_APPEND);
	ASSERT_LE(0, a) << strerror(errno);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b) << strerror(errno);
	ASSERT_EQ(1, write(a, "a", 1)) << strerror(errno);
	ASSERT_EQ(1, pwrite(b, "b", 1, 0)) << strerror(errno);
	ASSERT_EQ(0, close(a));
	ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, dup_flushes_each_descriptor)
{
	lookup();
	opened(11, O_RDONLY);
	flushed(11, 2);
	int a = open("mountpoint/file", O_RDONLY);
	ASSERT_LE(0, a);
	int b = dup(a);
	ASSERT_LE(0, b);
	ASSERT_EQ(0, close(a));
	released(11, O_RDONLY);
	ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, fsync_uses_issuing_handle)
{
	lookup(2);
	opened(11, O_RDWR); opened(12, O_RDWR);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_FSYNC && in.body.fsync.fh == 11;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(0)));
	flushed(11); released(11, O_RDWR);
	flushed(12); released(12, O_RDWR);
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	ASSERT_EQ(0, fsync(a)) << strerror(errno);
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, nonseekable_is_per_open)
{
	lookup(2);
	opened(11, O_RDONLY, FOPEN_DIRECT_IO | FOPEN_NONSEEKABLE);
	opened(12, O_RDONLY);
	flushed(11); released(11, O_RDONLY);
	flushed(12); released(12, O_RDONLY);
	int a = open("mountpoint/file", O_RDONLY);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDONLY);
	ASSERT_LE(0, b);
	ASSERT_EQ(-1, lseek(a, 0, SEEK_SET)); ASSERT_EQ(ESPIPE, errno);
	char c;
	ASSERT_EQ(-1, pread(a, &c, 1, 0)); ASSERT_EQ(ESPIPE, errno);
	ASSERT_EQ(0, lseek(b, 0, SEEK_SET));
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, direct_io_mapping_modes)
{
	lookup(); opened(11, O_RDWR); flushed(11);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ(MAP_FAILED, mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0));
	ASSERT_EQ(ENODEV, errno);
	void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	ASSERT_NE(MAP_FAILED, map) << strerror(errno);
	ASSERT_EQ(0, close(fd));
	released(11, O_RDWR);
	ASSERT_EQ(0, munmap(map, 4096));
}

TEST_F(OpenFile, forced_unmount_then_close)
{
	lookup(); opened(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	/* Tear down the server before forced reclaim; no RELEASE can be sent. */
	m_mock->kill_daemon();
	m_mock->join_daemon();
	ASSERT_EQ(0, unmount("mountpoint", MNT_FORCE)) << strerror(errno);
	char c;
	ASSERT_EQ(-1, read(fd, &c, 1));
	/* The descriptor still uses core-owned fileops after reclaim. */
	(void)close(fd);
}

class OpenFileLocks: public OpenFile {
public:
void SetUp() override {
	m_init_flags = FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS;
	OpenFile::SetUp();
}
};

TEST_F(OpenFileLocks, posix_lock_uses_issuing_handle)
{
	lookup(2); opened(11, O_RDWR); opened(12, O_RDWR);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == 11 &&
		    in.body.setlk.lk.type == 1;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(0)));
	for (uint64_t fh: {11, 12}) {
		EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
			return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == fh &&
			    in.body.setlk.lk.type == 2;
		}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(0)));
		flushed(fh); released(fh, O_RDWR);
	}
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	struct flock lock = {};
	lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
	ASSERT_EQ(0, fcntl(a, F_SETLK, &lock)) << strerror(errno);
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

/* Permit building the current-kernel probe with older installed headers. */
#ifndef F_OFD_SETLK
#define F_OFD_SETLK 26
#endif

TEST_F(OpenFileLocks, ofd_owners_and_final_unlock)
{
	uint64_t owners[2] = {};
	lookup(2); opened(11, O_RDWR); opened(12, O_RDWR);
	/* An earlier POSIX-lock test may have set the process P_ADVLOCK flag. */
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.lk.type == 2 &&
		    in.body.setlk.owner == (uint64_t)getpid();
	}, Eq(true)), _)).Times(AnyNumber()).WillRepeatedly(Invoke(ReturnErrno(0)));
	for (unsigned i = 0; i < 2; i++) {
		const uint64_t fh = 11 + i;
		EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
			return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == fh &&
			    in.body.setlk.lk.type == 1 && in.body.setlk.lk_flags == 0;
		}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([&, i](auto in, auto& out) {
			owners[i] = in.body.setlk.owner;
			out.header.len = sizeof(out.header);
		})));
		EXPECT_CALL(*m_mock, process(ResultOf([&, i, fh](auto in) {
			return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == fh &&
			    in.body.setlk.lk.type == 2 && in.body.setlk.owner == owners[i];
		}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(0)));
		flushed(fh); released(fh, O_RDWR);
	}
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	struct flock lock = {};
	lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 1;
	ASSERT_EQ(0, fcntl(a, F_OFD_SETLK, &lock)) << strerror(errno);
	lock.l_start = 1;
	ASSERT_EQ(0, fcntl(b, F_OFD_SETLK, &lock)) << strerror(errno);
	ASSERT_NE(owners[0], owners[1]);
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFileLocks, getlk_reports_description_owner)
{
	lookup(); opened(11, O_RDWR);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_GETLK && in.body.getlk.fh == 11;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk.type = 1;
		out.body.getlk.lk.start = 0;
		out.body.getlk.lk.end = 0;
		out.body.getlk.lk.pid = UINT32_MAX;
	})));
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.lk.type == 2;
	}, Eq(true)), _)).Times(AnyNumber()).WillRepeatedly(Invoke(ReturnErrno(0)));
	flushed(11); released(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	struct flock lock = {};
	lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET; lock.l_len = 1;
	ASSERT_EQ(0, fcntl(fd, F_GETLK, &lock)) << strerror(errno);
	ASSERT_EQ(-1, lock.l_pid);
	ASSERT_EQ(F_WRLCK, lock.l_type);
	ASSERT_EQ(0, close(fd));
}

TEST_F(OpenFileLocks, flock_unlock_precedes_release)
{
	uint64_t owner = 0;
	Sequence lifecycle;
	expected_releases++;
	lookup(); opened(11, O_RDWR); flushed(11);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.lk_flags == 0 &&
		    in.body.setlk.lk.type == 2;
	}, Eq(true)), _)).Times(AnyNumber()).WillRepeatedly(Invoke(ReturnErrno(0)));
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == 11 &&
		    in.body.setlk.lk.type == 1 && in.body.setlk.lk_flags == 1;
	}, Eq(true)), _)).InSequence(lifecycle)
	.WillOnce(Invoke(ReturnImmediate([&](auto in, auto& out) {
		owner = in.body.setlk.owner;
		out.header.len = sizeof(out.header);
	})));
	EXPECT_CALL(*m_mock, process(ResultOf([&](auto in) {
		return in.header.opcode == FUSE_SETLK && in.body.setlk.fh == 11 &&
		    in.body.setlk.lk.type == 2 && in.body.setlk.lk_flags == 1 &&
		    in.body.setlk.owner == owner;
	}, Eq(true)), _)).InSequence(lifecycle).WillOnce(Invoke(ReturnErrno(0)));
	EXPECT_CALL(*m_mock, process(ResultOf([&](auto in) {
		return in.header.opcode == FUSE_RELEASE && in.body.release.fh == 11 &&
		    (in.body.release.release_flags & FUSE_RELEASE_FLOCK_UNLOCK) != 0 &&
		    in.body.release.lock_owner == owner;
	}, Eq(true)), _)).InSequence(lifecycle).WillOnce(Invoke([this](auto in, auto& out) {
		ReturnErrno(0)(in, out);
		out.back()->reply_sent = &release_seen;
	}));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
	ASSERT_EQ(0, close(fd));
}

TEST_F(OpenFile, changed_status_flags_follow_description)
{
	lookup(2); opened(11, O_RDWR); opened(12, O_RDWR);
	written(11, O_RDWR | 00002000 | 00004000, 4096);
	written(12, O_RDWR, 0);
	flushed(11); released(11, O_RDWR | 00002000 | 00004000);
	flushed(12); released(12, O_RDWR);
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	ASSERT_EQ(0, fcntl(a, F_SETFL, O_APPEND | O_NONBLOCK));
	ASSERT_EQ(1, write(a, "a", 1));
	ASSERT_EQ(1, write(b, "b", 1));
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, directories_select_issuing_handle)
{
	FuseTest::expect_lookup("dir", 42, S_IFDIR | 0755, 0, 2);
	expected_releases += 2;
	for (uint64_t fh: {11, 12}) {
		EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
			return in.header.opcode == FUSE_OPENDIR &&
			    in.header.nodeid == 42;
		}, Eq(true)), _)).InSequence(open_sequence)
		.WillOnce(Invoke(ReturnImmediate([=](auto, auto& out) {
			SET_OUT_HEADER_LEN(out, open);
			out.body.open.fh = fh;
		})));
		EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
			return in.header.opcode == FUSE_READDIR &&
			    in.body.readdir.fh == fh;
		}, Eq(true)), _)).WillOnce(Invoke(ReturnErrno(0)));
		EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
			return in.header.opcode == FUSE_RELEASEDIR &&
			    in.body.release.fh == fh;
		}, Eq(true)), _)).WillOnce(Invoke([this](auto in, auto& out) {
			ReturnErrno(0)(in, out);
			out.back()->reply_sent = &release_seen;
		}));
	}
	int a = open("mountpoint/dir", O_RDONLY | O_DIRECTORY);
	ASSERT_LE(0, a);
	int b = open("mountpoint/dir", O_RDONLY | O_DIRECTORY);
	ASSERT_LE(0, b);
	char bytes[4096]; off_t base;
	ASSERT_EQ(0, getdirentries(a, bytes, sizeof(bytes), &base));
	ASSERT_EQ(0, getdirentries(b, bytes, sizeof(bytes), &base));
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, each_open_is_authorized)
{
	lookup(2); opened(11, O_RDWR);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_OPEN && in.header.nodeid == 42;
	}, Eq(true)), _)).InSequence(open_sequence)
	.WillOnce(Invoke(ReturnErrno(EACCES)));
	written(11, O_RDWR, 0); flushed(11); released(11, O_RDWR);
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	ASSERT_EQ(-1, open("mountpoint/file", O_RDWR));
	ASSERT_EQ(EACCES, errno);
	ASSERT_EQ(1, write(a, "a", 1));
	ASSERT_EQ(0, close(a));
}

TEST_F(OpenFile, unloaded_module_with_live_description)
{
	lookup(); opened(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	m_mock->kill_daemon();
	m_mock->join_daemon();
	ASSERT_EQ(0, unmount("mountpoint", MNT_FORCE));
	int mod = kldfind("fusefs");
	ASSERT_LE(0, mod);
	ASSERT_EQ(0, kldunload(mod)) << strerror(errno);
	char c;
	EXPECT_EQ(-1, read(fd, &c, 1));
	(void)close(fd);
	/* Restore the module for following fixtures in this disposable guest. */
	ASSERT_LE(0, kldload("fusefs")) << strerror(errno);
}

TEST_F(OpenFile, final_release_does_not_wait_for_reply)
{
	lookup(); opened(11, O_RDWR); flushed(11);
	expected_releases++;
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_RELEASE && in.body.release.fh == 11;
	}, Eq(true)), _)).WillOnce(Invoke([this](auto, auto&) {
		/* Intentionally retain the request without replying. */
		sem_post(&release_seen);
	}));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ(0, close(fd));
}

TEST_F(OpenFile, aio_uses_issuing_description)
{
	lookup(2); opened(11, O_RDWR); opened(12, O_RDWR);
	written(11, O_RDWR, 0);
	flushed(11); released(11, O_RDWR);
	flushed(12); released(12, O_RDWR);
	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	char byte = 'a';
	struct aiocb cb = {};
	cb.aio_fildes = a; cb.aio_buf = &byte; cb.aio_nbytes = 1;
	ASSERT_EQ(0, aio_write(&cb)) << strerror(errno);
	for (unsigned n = 0; n < 5000 && aio_error(&cb) == EINPROGRESS; n++)
		usleep(1000);
	ASSERT_EQ(0, aio_error(&cb));
	ASSERT_EQ(1, aio_return(&cb));
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

TEST_F(OpenFile, range_copy_selects_both_descriptions)
{
	lookup(2); opened(11, O_RDWR); opened(12, O_RDWR);
	flushed(11); released(11, O_RDWR);
	flushed(12); released(12, O_RDWR);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_COPY_FILE_RANGE &&
		    in.body.copy_file_range.fh_in == 11 &&
		    in.body.copy_file_range.fh_out == 12 &&
		    in.body.copy_file_range.off_in == 0 &&
		    in.body.copy_file_range.off_out == 128 &&
		    in.body.copy_file_range.len == 1;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, write);
		out.body.write.size = 1;
	})));
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETATTR && in.header.nodeid == 42 &&
		    (in.body.setattr.valid & ~(FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)) == 0;
	}, Eq(true)), _)).Times(1).WillRepeatedly(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, attr);
		out.body.attr.attr.mode = S_IFREG | 0666;
		out.body.attr.attr.size = 4096;
		out.body.attr.attr_valid = UINT64_MAX;
	})));

	int a = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, a);
	int b = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, b);
	off_t in = 0, out = 128;
	ASSERT_EQ(1, copy_file_range(a, &in, b, &out, 1, 0)) << strerror(errno);
	ASSERT_EQ(1, in); ASSERT_EQ(129, out);
	ASSERT_EQ(0, close(a)); ASSERT_EQ(0, close(b));
}

class OpenFileStream: public OpenFile {
public:
void timestamps() {
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_SETATTR && in.header.nodeid == 42 &&
		    (in.body.setattr.valid & ~(FATTR_ATIME | FATTR_MTIME | FATTR_CTIME)) == 0;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, attr);
		out.body.attr.attr.mode = S_IFREG | 0666;
		out.body.attr.attr.size = 4096;
		out.body.attr.attr_valid = UINT64_MAX;
	})));
}
void read_at(off_t offset) {
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == FUSE_READ && in.body.read.fh == 11 &&
		    in.body.read.offset == (uint64_t)offset && in.body.read.size == 1;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		out.header.len = sizeof(out.header) + 1;
		out.body.bytes[0] = 'r';
	}))).RetiresOnSaturation();
}
void duplex(bool write_first);
void force_pending(bool writing);
};

TEST_F(OpenFileStream, offsets_restart_for_each_call)
{
	lookup(); opened(11, O_RDWR, FOPEN_DIRECT_IO | FOPEN_STREAM);
	read_at(0); read_at(0);
	{
		InSequence writes;
		written(11, O_RDWR, 0); written(11, O_RDWR, 0);
	}
	timestamps(); flushed(11, 2); released(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	int alias = dup(fd);
	ASSERT_LE(0, alias);
	char c;
	ASSERT_EQ(1, read(fd, &c, 1)); ASSERT_EQ('r', c);
	ASSERT_EQ(1, read(alias, &c, 1)); ASSERT_EQ('r', c);
	ASSERT_EQ(1, write(fd, "a", 1));
	ASSERT_EQ(1, write(alias, "b", 1));
	ASSERT_EQ(-1, lseek(fd, 0, SEEK_SET)); ASSERT_EQ(ESPIPE, errno);
	ASSERT_EQ(-1, pread(fd, &c, 1, 0)); ASSERT_EQ(ESPIPE, errno);
	ASSERT_EQ(-1, pwrite(fd, &c, 1, 0)); ASSERT_EQ(ESPIPE, errno);
	ASSERT_EQ(0, close(alias)); ASSERT_EQ(0, close(fd));
}

TEST_F(OpenFileStream, nonseekable_retains_sequential_offsets)
{
	lookup(); opened(11, O_RDONLY, FOPEN_DIRECT_IO | FOPEN_NONSEEKABLE);
	Sequence reads;
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_READ && in.body.read.offset == 0;
	}, Eq(true)), _)).InSequence(reads).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		out.header.len = sizeof(out.header) + 1; out.body.bytes[0] = 'a';
	})));
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_READ && in.body.read.offset == 1;
	}, Eq(true)), _)).InSequence(reads).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		out.header.len = sizeof(out.header) + 1; out.body.bytes[0] = 'b';
	})));
	timestamps(); flushed(11); released(11, O_RDONLY);
	int fd = open("mountpoint/file", O_RDONLY);
	ASSERT_LE(0, fd);
	char c;
	ASSERT_EQ(1, read(fd, &c, 1)); ASSERT_EQ('a', c);
	ASSERT_EQ(1, read(fd, &c, 1)); ASSERT_EQ('b', c);
	ASSERT_EQ(0, close(fd));
}

struct stream_io_call {
	int fd;
	bool writing;
	ssize_t result;
	sem_t *done;
};
static void *stream_io_thread(void *arg)
{
	auto call = static_cast<stream_io_call *>(arg);
	char byte = 'w';
	call->result = call->writing ? write(call->fd, &byte, 1) : read(call->fd, &byte, 1);
	sem_post(call->done);
	return nullptr;
}

void OpenFileStream::duplex(bool write_first)
{
	sem_t waiting, done;
	ASSERT_EQ(0, sem_init(&waiting, 0, 0));
	ASSERT_EQ(0, sem_init(&done, 0, 0));
	lookup(); opened(11, O_RDWR, FOPEN_DIRECT_IO | FOPEN_STREAM);
	uint64_t held = 0;
	uint32_t first = write_first ? FUSE_WRITE : FUSE_READ;
	uint32_t second = write_first ? FUSE_READ : FUSE_WRITE;
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == first;
	}, Eq(true)), _)).WillOnce(Invoke([&](auto in, auto&) {
		held = in.header.unique;
		sem_post(&waiting);
	}));
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == second;
	}, Eq(true)), _)).WillOnce(Invoke([&](auto in, auto& out) {
		for (unsigned n = 0; n < 2; n++) {
			std::unique_ptr<mockfs_buf_out> reply(new mockfs_buf_out);
			reply->header.unique = n == 0 ? held : in.header.unique;
			uint32_t opcode = n == 0 ? first : second;
			if (opcode == FUSE_WRITE) {
				SET_OUT_HEADER_LEN(*reply, write);
				reply->body.write.size = 1;
			} else {
				reply->header.len = sizeof(reply->header) + 1;
				reply->body.bytes[0] = 'r';
			}
			out.push_back(std::move(reply));
		}
	}));
	timestamps(); flushed(11); released(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	pthread_t a, b;
	stream_io_call ca{fd, write_first, -1, &done};
	stream_io_call cb{fd, !write_first, -1, &done};
	ASSERT_EQ(0, pthread_create(&a, nullptr, stream_io_thread, &ca));
	struct timespec deadline;
	ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &deadline));
	deadline.tv_sec += 5;
	int first_seen = sem_timedwait(&waiting, &deadline);
	EXPECT_EQ(0, first_seen);
	int started = pthread_create(&b, nullptr, stream_io_thread, &cb);
	EXPECT_EQ(0, started);
	int finished_a = sem_timedwait(&done, &deadline);
	int finished_b = started == 0 ? sem_timedwait(&done, &deadline) : -1;
	if (first_seen != 0 || finished_a != 0 || finished_b != 0)
		m_mock->kill_daemon();
	EXPECT_EQ(0, pthread_join(a, nullptr));
	if (started == 0) EXPECT_EQ(0, pthread_join(b, nullptr));
	EXPECT_EQ(0, finished_a); EXPECT_EQ(0, finished_b);
	EXPECT_EQ(1, ca.result); EXPECT_EQ(1, cb.result);
	EXPECT_EQ(0, close(fd));
	EXPECT_EQ(0, sem_destroy(&waiting)); EXPECT_EQ(0, sem_destroy(&done));
}

TEST_F(OpenFileStream, write_completes_while_read_pending) { duplex(false); }
TEST_F(OpenFileStream, read_completes_while_write_pending) { duplex(true); }

TEST_F(OpenFileStream, short_write_does_not_advance_shared_offset)
{
	lookup(); opened(11, O_RDWR, FOPEN_DIRECT_IO | FOPEN_STREAM);
	EXPECT_CALL(*m_mock, process(ResultOf([](auto in) {
		return in.header.opcode == FUSE_WRITE && in.body.write.offset == 0 &&
		    in.body.write.size == 2;
	}, Eq(true)), _)).WillOnce(Invoke(ReturnImmediate([](auto, auto& out) {
		SET_OUT_HEADER_LEN(out, write); out.body.write.size = 1;
	})));
	written(11, O_RDWR, 0);
	flushed(11); released(11, O_RDWR);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	ASSERT_EQ(1, write(fd, "ab", 2));
	ASSERT_EQ(1, write(fd, "c", 1));
	ASSERT_EQ(0, close(fd));
}

void OpenFileStream::force_pending(bool writing)
{
	sem_t waiting, done;
	ASSERT_EQ(0, sem_init(&waiting, 0, 0));
	ASSERT_EQ(0, sem_init(&done, 0, 0));
	lookup(); opened(11, O_RDWR, FOPEN_DIRECT_IO | FOPEN_STREAM);
	EXPECT_CALL(*m_mock, process(ResultOf([=](auto in) {
		return in.header.opcode == (writing ? FUSE_WRITE : FUSE_READ);
	}, Eq(true)), _)).WillOnce(Invoke([&](auto, auto&) { sem_post(&waiting); }));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	stream_io_call call{fd, writing, -1, &done};
	pthread_t worker;
	ASSERT_EQ(0, pthread_create(&worker, nullptr, stream_io_thread, &call));
	struct timespec deadline;
	ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &deadline));
	deadline.tv_sec += 5;
	int seen = sem_timedwait(&waiting, &deadline);
	EXPECT_EQ(0, seen);
	if (seen != 0) m_mock->kill_daemon();
	m_mock->m_expect_unmount = true;
	struct timespec before, after;
	ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &before));
	EXPECT_EQ(0, unmount("mountpoint", MNT_FORCE)) << strerror(errno);
	ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &after));
	EXPECT_LT(after.tv_sec - before.tv_sec, 5);
	EXPECT_EQ(0, pthread_join(worker, nullptr));
	EXPECT_EQ(-1, call.result);
	(void)close(fd);
	EXPECT_EQ(0, sem_destroy(&waiting)); EXPECT_EQ(0, sem_destroy(&done));
}

TEST_F(OpenFileStream, forced_unmount_wakes_pending_read) { force_pending(false); }
TEST_F(OpenFileStream, forced_unmount_wakes_pending_write) { force_pending(true); }

TEST_F(OpenFileStream, buffered_stream_restarts_offset)
{
	lookup(); opened(11, O_RDONLY, FOPEN_STREAM | FOPEN_KEEP_CACHE);
	char contents[4096]; memset(contents, 'b', sizeof(contents));
	expect_read(42, 0, 4096, 4096, contents, 00100000, 11);
	timestamps(); flushed(11); released(11, O_RDONLY);
	int fd = open("mountpoint/file", O_RDONLY);
	ASSERT_LE(0, fd);
	char c;
	ASSERT_EQ(1, read(fd, &c, 1)); ASSERT_EQ('b', c);
	ASSERT_EQ(1, read(fd, &c, 1)); ASSERT_EQ('b', c);
	ASSERT_EQ(-1, lseek(fd, 0, SEEK_SET)); ASSERT_EQ(ESPIPE, errno);
	ASSERT_EQ(0, close(fd));
}

TEST_F(OpenFileStream, unloaded_module_with_stream_description)
{
	lookup(); opened(11, O_RDWR, FOPEN_STREAM | FOPEN_DIRECT_IO);
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	m_mock->kill_daemon(); m_mock->join_daemon();
	ASSERT_EQ(0, unmount("mountpoint", MNT_FORCE));
	int mod = kldfind("fusefs");
	ASSERT_LE(0, mod);
	ASSERT_EQ(0, kldunload(mod)) << strerror(errno);
	char c;
	EXPECT_EQ(-1, read(fd, &c, 1));
	EXPECT_EQ(-1, write(fd, "a", 1));
	(void)close(fd);
	ASSERT_LE(0, kldload("fusefs")) << strerror(errno);
}
