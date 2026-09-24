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
#include <sys/file.h>
#include <fcntl.h>
#include <semaphore.h>
}

#include <thread>

#include "mockfs.hh"
#include "utils.hh"

/* This flag value should probably be defined in fuse_kernel.h */
#define OFFSET_MAX 0x7fffffffffffffffLL

using namespace testing;

/* For testing filesystems without posix locking support */
class Fallback: public FuseTest {
public:

void expect_lookup(const char *relpath, uint64_t ino, uint64_t size = 0)
{
	FuseTest::expect_lookup(relpath, ino, S_IFREG | 0644, size, 1);
}

};

/* For testing filesystems with posix locking support */
class Locks: public Fallback {
	virtual void SetUp() {
		m_init_flags = FUSE_POSIX_LOCKS;
		Fallback::SetUp();
	}
};

class Fcntl: public Locks {
public:
void expect_setlk(uint64_t ino, pid_t pid, uint64_t start, uint64_t end,
	uint32_t type, int err)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_SETLK &&
				in.header.nodeid == ino &&
				in.body.setlk.fh == FH &&
				in.body.setlk.owner == (uint32_t)pid &&
				in.body.setlk.lk.start == start &&
				in.body.setlk.lk.end == end &&
				in.body.setlk.lk.type == type &&
				in.body.setlk.lk.pid == (uint64_t)pid);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(err)));
}
void expect_setlkw(uint64_t ino, pid_t pid, uint64_t start, uint64_t end,
	uint32_t type, int err)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_SETLKW &&
				in.header.nodeid == ino &&
				in.body.setlkw.fh == FH &&
				in.body.setlkw.owner == (uint32_t)pid &&
				in.body.setlkw.lk.start == start &&
				in.body.setlkw.lk.end == end &&
				in.body.setlkw.lk.type == type &&
				in.body.setlkw.lk.pid == (uint64_t)pid);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnErrno(err)));
}
};

class Flock: public Locks {};

/* Negotiate flock independently of POSIX record locks. */
class FlockRemote: public Fallback {
public:
void SetUp() override {
	m_init_flags = FUSE_FLOCK_LOCKS;
	Fallback::SetUp();
}
void expect_setlk(uint64_t ino, uint32_t type, int err, bool wait = false)
{
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == (wait ? FUSE_SETLKW : FUSE_SETLK) &&
				in.header.nodeid == ino &&
				in.body.setlk.fh == FH &&
				in.body.setlk.lk_flags == FUSE_LK_FLOCK &&
				in.body.setlk.lk.start == 0 &&
				in.body.setlk.lk.end == OFFSET_MAX &&
				in.body.setlk.lk.type == type);
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnErrno(err)));
}
};

class FlockFallback: public Fallback {};
class GetlkFallback: public Fallback {};
class Getlk: public Fcntl {};
class SetlkFallback: public Fallback {};
class Setlk: public Fcntl {};
class SetlkwFallback: public Fallback {};
class Setlkw: public Fcntl {};

/*
 * If the fuse filesystem does not support flock locks, then the kernel should
 * fall back to local locks.
 */
TEST_F(FlockFallback, local)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(0, flock(fd, LOCK_EX)) << strerror(errno);
	leak(fd);
}

/*
 * Even if the fuse file system supports POSIX locks, we must implement flock
 * locks locally until protocol 7.17.  Protocol 7.9 added partial buggy support
 * but we won't implement that.
 */
TEST_F(Flock, local)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(0, flock(fd, LOCK_EX)) << strerror(errno);
	leak(fd);
}

/* Set a new flock lock with FUSE_SETLK */
TEST_F(FlockRemote, set)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, F_WRLCK, 0, true);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(0, flock(fd, LOCK_EX)) << strerror(errno);
	leak(fd);
}

/* Fail to set a flock lock in non-blocking mode */
TEST_F(FlockRemote, eagain)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, F_WRLCK, EAGAIN);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_NE(0, flock(fd, LOCK_EX | LOCK_NB));
	ASSERT_EQ(EAGAIN, errno);
	leak(fd);
}

/*
 * If the fuse filesystem does not support posix file locks, then the kernel
 * should fall back to local locks.
 */
TEST_F(GetlkFallback, local)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_GETLK, &fl)) << strerror(errno);
	leak(fd);
}

/* 
 * If the filesystem has no locks that fit the description, the filesystem
 * should return F_UNLCK
 */
TEST_F(Getlk, no_locks)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETLK &&
				in.header.nodeid == ino &&
				in.body.getlk.fh == FH &&
				/*
				 * Though it seems useless, libfuse expects the
				 * owner and pid fields to be set during
				 * FUSE_GETLK.
				 */
				in.body.getlk.owner == (uint32_t)pid &&
				in.body.getlk.lk.pid == (uint64_t)pid &&
				in.body.getlk.lk.start == 10 &&
				in.body.getlk.lk.end == 1009 &&
				in.body.getlk.lk.type == F_RDLCK);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk = in.body.getlk.lk;
		out.body.getlk.lk.type = F_UNLCK;
	})));

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 42;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 42;
	ASSERT_NE(-1, fcntl(fd, F_GETLK, &fl)) << strerror(errno);

	/*
	 * If no lock is found that would prevent this lock from being created,
	 * the structure is left unchanged by this system call except for the
	 * lock type which is set to F_UNLCK.
	 */
	ASSERT_EQ(F_UNLCK, fl.l_type);
	ASSERT_EQ(fl.l_pid, 42);
	ASSERT_EQ(fl.l_start, 10);
	ASSERT_EQ(fl.l_len, 1000);
	ASSERT_EQ(fl.l_whence, SEEK_SET);
	ASSERT_EQ(fl.l_sysid, 42);

	leak(fd);
}

/* A different pid does have a lock */
TEST_F(Getlk, lock_exists)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();
	pid_t pid2 = 1235;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETLK &&
				in.header.nodeid == ino &&
				in.body.getlk.fh == FH &&
				/*
				 * Though it seems useless, libfuse expects the
				 * owner and pid fields to be set during
				 * FUSE_GETLK.
				 */
				in.body.getlk.owner == (uint32_t)pid &&
				in.body.getlk.lk.pid == (uint64_t)pid &&
				in.body.getlk.lk.start == 10 &&
				in.body.getlk.lk.end == 1009 &&
				in.body.getlk.lk.type == F_RDLCK);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk.start = 100;
		out.body.getlk.lk.end = 199;
		out.body.getlk.lk.type = F_WRLCK;
		out.body.getlk.lk.pid = (uint32_t)pid2;;
	})));

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_GETLK, &fl)) << strerror(errno);
	EXPECT_EQ(100, fl.l_start);
	EXPECT_EQ(100, fl.l_len);
	EXPECT_EQ(pid2, fl.l_pid);
	EXPECT_EQ(F_WRLCK, fl.l_type);
	EXPECT_EQ(SEEK_SET, fl.l_whence);
	EXPECT_EQ(0, fl.l_sysid);
	leak(fd);
}

/*
 * F_GETLK with SEEK_CUR
 */
TEST_F(Getlk, seek_cur)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino, 1024);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETLK &&
				in.header.nodeid == ino &&
				in.body.getlk.fh == FH &&
				/*
				 * Though it seems useless, libfuse expects the
				 * owner and pid fields to be set during
				 * FUSE_GETLK.
				 */
				in.body.getlk.owner == (uint32_t)pid &&
				in.body.getlk.lk.pid == (uint64_t)pid &&
				in.body.getlk.lk.start == 500 &&
				in.body.getlk.lk.end == 509 &&
				in.body.getlk.lk.type == F_RDLCK);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk.start = 400;
		out.body.getlk.lk.end = 499;
		out.body.getlk.lk.type = F_WRLCK;
		out.body.getlk.lk.pid = (uint32_t)pid + 1;
	})));

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_NE(-1, lseek(fd, 500, SEEK_SET));

	fl.l_start = 0;
	fl.l_len = 10;
	fl.l_pid = 42;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_CUR;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_GETLK, &fl)) << strerror(errno);

	/*
	 * After a successful F_GETLK request, the value of l_whence is
	 * SEEK_SET.
	 */
	EXPECT_EQ(F_WRLCK, fl.l_type);
	EXPECT_EQ(fl.l_pid, pid + 1);
	EXPECT_EQ(fl.l_start, 400);
	EXPECT_EQ(fl.l_len, 100);
	EXPECT_EQ(fl.l_whence, SEEK_SET);
	ASSERT_EQ(fl.l_sysid, 0);

	leak(fd);
}

/*
 * F_GETLK with SEEK_END
 */
TEST_F(Getlk, seek_end)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino, 1024);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([=](auto in) {
			return (in.header.opcode == FUSE_GETLK &&
				in.header.nodeid == ino &&
				in.body.getlk.fh == FH &&
				/*
				 * Though it seems useless, libfuse expects the
				 * owner and pid fields to be set during
				 * FUSE_GETLK.
				 */
				in.body.getlk.owner == (uint32_t)pid &&
				in.body.getlk.lk.pid == (uint64_t)pid &&
				in.body.getlk.lk.start == 512 &&
				in.body.getlk.lk.end == 1023 &&
				in.body.getlk.lk.type == F_RDLCK);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk.start = 400;
		out.body.getlk.lk.end = 499;
		out.body.getlk.lk.type = F_WRLCK;
		out.body.getlk.lk.pid = (uint32_t)pid + 1;
	})));

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_NE(-1, lseek(fd, 500, SEEK_SET));

	fl.l_start = -512;
	fl.l_len = 512;
	fl.l_pid = 42;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_END;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_GETLK, &fl)) << strerror(errno);

	/*
	 * After a successful F_GETLK request, the value of l_whence is
	 * SEEK_SET.
	 */
	EXPECT_EQ(F_WRLCK, fl.l_type);
	EXPECT_EQ(fl.l_pid, pid + 1);
	EXPECT_EQ(fl.l_start, 400);
	EXPECT_EQ(fl.l_len, 100);
	EXPECT_EQ(fl.l_whence, SEEK_SET);
	ASSERT_EQ(fl.l_sysid, 0);

	leak(fd);
}

/*
 * If the fuse filesystem does not support posix file locks, then the kernel
 * should fall back to local locks.
 */
TEST_F(SetlkFallback, local)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = getpid();
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);
	leak(fd);
}

/* Clear a lock with FUSE_SETLK */
TEST_F(Setlk, clear)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 10, 1009, F_UNLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);
	leak(fd);
}

/* Set a new lock with FUSE_SETLK */
TEST_F(Setlk, set)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 10, 1009, F_RDLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);
	leak(fd);
}

/* l_len = 0 is a flag value that means to lock until EOF */
TEST_F(Setlk, set_eof)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 10, OFFSET_MAX, F_RDLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 0;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);
	leak(fd);
}

/* Set a new lock with FUSE_SETLK, using SEEK_CUR for l_whence */
TEST_F(Setlk, set_seek_cur)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino, 1024);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 500, 509, F_RDLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_NE(-1, lseek(fd, 500, SEEK_SET));

	fl.l_start = 0;
	fl.l_len = 10;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_CUR;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);

	leak(fd);
}

/* Set a new lock with FUSE_SETLK, using SEEK_END for l_whence */
TEST_F(Setlk, set_seek_end)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino, 1024);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 1000, 1009, F_RDLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);

	fl.l_start = -24;
	fl.l_len = 10;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_END;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLK, &fl)) << strerror(errno);

	leak(fd);
}

/* Fail to set a new lock with FUSE_SETLK due to a conflict */
TEST_F(Setlk, eagain)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlk(ino, pid, 10, 1009, F_RDLCK, EAGAIN);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_EQ(-1, fcntl(fd, F_SETLK, &fl));
	ASSERT_EQ(EAGAIN, errno);
	leak(fd);
}

/*
 * If the fuse filesystem does not support posix file locks, then the kernel
 * should fall back to local locks.
 */
TEST_F(SetlkwFallback, local)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLKW, &fl)) << strerror(errno);
	leak(fd);
}

/*
 * Set a new lock with FUSE_SETLK.  If the lock is not available, then the
 * command should block.  But to the kernel, that's the same as just being
 * slow, so we don't need a separate test method
 */
TEST_F(Setlkw, set)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;
	struct flock fl;
	int fd;
	pid_t pid = getpid();

	expect_lookup(RELPATH, ino);
	expect_open(ino, 0, 1);
	expect_setlkw(ino, pid, 10, 1009, F_RDLCK, 0);

	fd = open(FULLPATH, O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	fl.l_start = 10;
	fl.l_len = 1000;
	fl.l_pid = 0;
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_sysid = 0;
	ASSERT_NE(-1, fcntl(fd, F_SETLKW, &fl)) << strerror(errno);
	leak(fd);
}

/* Reject malformed daemon replies before copying them into struct flock. */
class GetlkInvalid: public Getlk, public WithParamInterface<int> {};

TEST_P(GetlkInvalid, reply)
{
	const uint64_t ino = 42;
	const int variant = GetParam();
	expect_lookup("file", ino);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_GETLK;
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([=](auto in, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk = in.body.getlk.lk;
		auto& lk = out.body.getlk.lk;
		lk.type = F_WRLCK;
		lk.start = 10;
		lk.end = 19;
		switch (variant) {
		case 0: lk.type = 0xffffffff; break;
		case 1: lk.start = UINT64_MAX; break;
		case 2: lk.end = UINT64_MAX; break;
		case 3: lk.end = 9; break;
		case 4: lk.pid = 0x80000000U; break;
		}
	})));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	struct flock fl = {};
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	ASSERT_EQ(-1, fcntl(fd, F_GETLK, &fl));
	EXPECT_EQ(EIO, errno);
	leak(fd);
}

INSTANTIATE_TEST_SUITE_P(Malformed, GetlkInvalid, Range(0, 5));

TEST_F(Getlk, negative_length)
{
	const uint64_t ino = 42;
	expect_lookup("file", ino);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_GETLK &&
			    in.body.getlk.lk.start == 10 &&
			    in.body.getlk.lk.end == 19;
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([](auto in, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk = in.body.getlk.lk;
		out.body.getlk.lk.type = F_UNLCK;
	})));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	struct flock fl = {};
	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 20;
	fl.l_len = -10;
	ASSERT_EQ(0, fcntl(fd, F_GETLK, &fl)) << strerror(errno);
	EXPECT_EQ(F_UNLCK, fl.l_type);
	leak(fd);
}

/* dup shares a lock owner; an independent open has its own owner. */
TEST_F(FlockRemote, owners_and_final_close)
{
	const uint64_t ino = 42;
	uint64_t owner1 = 0, owner2 = 0;
	unsigned calls = 0;
	FuseTest::expect_lookup("file", ino, S_IFREG | 0644, 0, 2);
	expect_open(ino, 0, 1);
	expect_flush(ino, 2, ReturnErrno(0));
	expect_release(ino, FH);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_SETLK &&
			    in.body.setlk.lk_flags == FUSE_LK_FLOCK;
		}, Eq(true)), _))
	.Times(4)
	.WillRepeatedly(Invoke(ReturnImmediate([&](auto in, auto& out) {
		const auto& lk = in.body.setlk;
		switch (calls++) {
		case 0:
			owner1 = lk.owner;
			EXPECT_EQ((uint32_t)F_RDLCK, lk.lk.type);
			break;
		case 1:
			owner2 = lk.owner;
			EXPECT_NE(owner1, owner2);
			EXPECT_EQ((uint32_t)F_RDLCK, lk.lk.type);
			break;
		case 2:
			EXPECT_EQ(owner1, lk.owner);
			EXPECT_EQ((uint32_t)F_UNLCK, lk.lk.type);
			break;
		case 3:
			EXPECT_EQ(owner2, lk.owner);
			EXPECT_EQ((uint32_t)F_UNLCK, lk.lk.type);
			break;
		}
		out.header.len = sizeof(out.header);
		out.header.error = 0;
	})));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	int alias = dup(fd);
	ASSERT_LE(0, alias);
	int separate = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, separate);
	ASSERT_EQ(0, flock(fd, LOCK_SH | LOCK_NB));
	ASSERT_EQ(0, flock(separate, LOCK_SH | LOCK_NB));
	ASSERT_EQ(0, close(fd));
	ASSERT_EQ(0, close(alias));
	ASSERT_EQ(0, close(separate));
}

class LinuxFlock: public FlockRemote {
void SetUp() override {
	m_linux_errnos = true;
	FlockRemote::SetUp();
}
};

TEST_F(LinuxFlock, wire_types)
{
	const uint64_t ino = 42;
	expect_lookup("file", ino);
	expect_open(ino, 0, 1);
	/* Linux wire values: F_RDLCK=0, F_WRLCK=1, F_UNLCK=2. */
	{
		InSequence sequence;
		expect_setlk(ino, 0, 0);
		expect_setlk(ino, 1, 0);
		expect_setlk(ino, 2, 0);
	}
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	ASSERT_EQ(0, flock(fd, LOCK_SH | LOCK_NB));
	ASSERT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
	ASSERT_EQ(0, flock(fd, LOCK_UN));
	leak(fd);
}

class LinuxGetlk: public Getlk, public WithParamInterface<int> {
void SetUp() override {
	m_linux_errnos = true;
	m_init_flags = FUSE_POSIX_LOCKS;
	Fallback::SetUp();
}
};

TEST_P(LinuxGetlk, reply_type)
{
	const uint64_t ino = 42;
	const uint32_t type = GetParam();
	expect_lookup("file", ino);
	expect_open(ino, 0, 1);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_GETLK &&
			    in.body.getlk.lk.type == 1;
		}, Eq(true)), _))
	.WillOnce(Invoke(ReturnImmediate([=](auto in, auto& out) {
		SET_OUT_HEADER_LEN(out, getlk);
		out.body.getlk.lk = in.body.getlk.lk;
		out.body.getlk.lk.type = type;
	})));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd) << strerror(errno);
	struct flock fl = {};
	fl.l_whence = SEEK_SET;
	fl.l_type = F_WRLCK;
	ASSERT_EQ(0, fcntl(fd, F_GETLK, &fl)) << strerror(errno);
	EXPECT_EQ(type == 0 ? F_RDLCK : type == 1 ? F_WRLCK : F_UNLCK,
	    fl.l_type);
	leak(fd);
}

INSTANTIATE_TEST_SUITE_P(Wire, LinuxGetlk, Range(0, 3));

/* A blocked SETLKW must allow a different owner's final close to unlock. */
TEST_F(FlockRemote, blocked_waiter_final_close)
{
	const uint64_t ino = 42;
	uint64_t pending = 0;
	sem_t waiting;
	ASSERT_EQ(0, sem_init(&waiting, 0, 0));
	FuseTest::expect_lookup("file", ino, S_IFREG | 0644, 0, 2);
	expect_open(ino, 0, 1);
	expect_flush(ino, 2, ReturnErrno(0));
	expect_release(ino, FH);
	expect_setlk(ino, F_WRLCK, 0);
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_SETLKW &&
			    in.body.setlkw.lk_flags == FUSE_LK_FLOCK;
		}, Eq(true)), _))
	.WillOnce(Invoke([&](const mockfs_buf_in& in,
	    std::vector<std::unique_ptr<mockfs_buf_out>>& out __unused) {
		pending = in.header.unique;
		sem_post(&waiting);
	}));
	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return in.header.opcode == FUSE_SETLK &&
			    in.body.setlk.lk.type == F_UNLCK &&
			    in.body.setlk.lk_flags == FUSE_LK_FLOCK;
		}, Eq(true)), _))
	.Times(2)
	.WillRepeatedly(Invoke([&](const mockfs_buf_in& in,
	    std::vector<std::unique_ptr<mockfs_buf_out>>& out) {
		ReturnErrno(0)(in, out);
		if (pending != 0) {
			std::unique_ptr<mockfs_buf_out> reply(new mockfs_buf_out);
			reply->header.unique = pending;
			reply->header.len = sizeof(reply->header);
			out.push_back(std::move(reply));
			pending = 0;
		}
	}));
	int fd = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, fd);
	int other = open("mountpoint/file", O_RDWR);
	ASSERT_LE(0, other);
	ASSERT_EQ(0, flock(fd, LOCK_EX | LOCK_NB));
	int result = -1;
	std::thread waiter([&] { result = flock(other, LOCK_EX); });
	while (sem_wait(&waiting) != 0 && errno == EINTR)
		;
	EXPECT_EQ(0, close(fd));
	waiter.join();
	EXPECT_EQ(0, result);
	EXPECT_EQ(0, close(other));
	EXPECT_EQ(0, sem_destroy(&waiting));
}
