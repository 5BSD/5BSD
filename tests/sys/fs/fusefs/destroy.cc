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
#include <sys/param.h>
#include <sys/mount.h>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <semaphore.h>
}

#include "mockfs.hh"
#include "utils.hh"

using namespace testing;

/* Tests for orderly unmounts */
class Destroy: public FuseTest {};

/* Tests for unexpected deaths of the server */
class Death: public FuseTest{};

/* Tests for the auto_unmount mount option*/
class AutoUnmount: public FuseTest {
virtual void SetUp() {
	m_auto_unmount = true;
	FuseTest::SetUp();
}

protected:
/* Unmounting fusefs might be asynchronous with close, so use a retry loop */
void assert_unmounted() {
	struct statfs statbuf;

	for (int retry = 100; retry > 0; retry--) {
		if (statfs("mountpoint", &statbuf) != 0) {
			/* Lookup may have crossed the mount being torn down. */
			ASSERT_EQ(ENOENT, errno) << strerror(errno);
			nap();
			continue;
		}
		if (strcmp("fusefs", statbuf.f_fstypename) != 0 &&
		    strcmp("/dev/fuse", statbuf.f_mntfromname) != 0)
			return;
		nap();
	}
	FAIL() << "fusefs is still mounted";
}

};

static void* read_th(void* arg) {
	int fd = *(int *)arg;
	char byte;

	EXPECT_EQ(-1, pread(fd, &byte, 1, 0));
	EXPECT_EQ(ENOTCONN, errno);
	return 0;
}

/*
 * With the auto_unmount mount option, the kernel will automatically unmount
 * the file system when the server dies.
 */
TEST_F(AutoUnmount, auto_unmount)
{
	/* Kill the daemon */
	m_mock->kill_daemon();

	/* Use statfs to check that the file system is no longer mounted */
	assert_unmounted();
}

/*
 * When -o auto_unmount is used, the kernel should _not_ unmount the file
 * system when any /dev/fuse file descriptor is closed, but only for the last
 * one.
 */
TEST_F(AutoUnmount, dup)
{
	struct statfs statbuf;
	int fuse2;

	EXPECT_CALL(*m_mock, process(
		ResultOf([](auto in) {
			return (in.header.opcode == FUSE_STATFS);
		}, Eq(true)),
		_)
	).WillOnce(Invoke(ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, statfs);
	})));

	fuse2 = dup_dev_fuse();

	/*
	 * Close one of the /dev/fuse file descriptors.  Close the duplicate
	 * first so the daemon thread doesn't freak out when it gets a bunch of
	 * EBADF errors.
	 */
	close(fuse2);

	/* Use statfs to check that the file system is still mounted */
	ASSERT_EQ(0, statfs("mountpoint", &statbuf)) << strerror(errno);
	EXPECT_EQ(0, strcmp("fusefs", statbuf.f_fstypename));
	EXPECT_EQ(0, strcmp("/dev/fuse", statbuf.f_mntfromname));

	/*
	 * Close the original file descriptor too. Now the file system should be
	 * unmounted at last.
	 */
	m_mock->kill_daemon();
	assert_unmounted();
}

/*
 * The server dies with unsent operations still on the message queue.
 * Check for any memory leaks like this:
 * 1) kldunload fusefs, if necessary
 * 2) kldload fusefs
 * 3) ./destroy --gtest_filter=Death.unsent_operations
 * 4) kldunload fusefs
 * 5) check /var/log/messages for anything like this:
Freed UMA keg (fuse_ticket) was not empty (31 items).  Lost 2 pages of memory.
Warning: memory type fuse_msgbuf leaked memory on destroy (68 allocations, 428800 bytes leaked).
 */
TEST_F(Death, unsent_operations)
{
	const char FULLPATH0[] = "mountpoint/some_file.txt";
	const char FULLPATH1[] = "mountpoint/other_file.txt";
	const char RELPATH0[] = "some_file.txt";
	const char RELPATH1[] = "other_file.txt";
	pthread_t th0, th1;
	ino_t ino0 = 42, ino1 = 43;
	sem_t sem;
	mode_t mode = S_IFREG | 0644;
	struct pollfd pending;
	int poll_result;
	int fd0, fd1;

	sem_init(&sem, 0, 0);

	EXPECT_LOOKUP(FUSE_ROOT_ID, RELPATH0)
	.WillRepeatedly(Invoke(
		ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, entry);
		out.body.entry.attr.mode = mode;
		out.body.entry.nodeid = ino0;
		out.body.entry.attr.nlink = 1;
		out.body.entry.attr.size = 4096;
		out.body.entry.entry_valid = UINT64_MAX;
		out.body.entry.attr_valid = UINT64_MAX;
	})));
	EXPECT_LOOKUP(FUSE_ROOT_ID, RELPATH1)
	.WillRepeatedly(Invoke(
		ReturnImmediate([=](auto in __unused, auto& out) {
		SET_OUT_HEADER_LEN(out, entry);
		out.body.entry.attr.mode = mode;
		out.body.entry.nodeid = ino1;
		out.body.entry.attr.nlink = 1;
		out.body.entry.attr.size = 4096;
		out.body.entry.entry_valid = UINT64_MAX;
		out.body.entry.attr_valid = UINT64_MAX;
	})));

	/*
	 * Resolve names and labels before blocking the daemon.  Path-based
	 * OPEN can stall in a MAC label query instead of queuing the operation
	 * being tested.  Direct reads on already-open files avoid that race.
	 */
	expect_open(ino0, FOPEN_DIRECT_IO, 1);
	expect_open(ino1, FOPEN_DIRECT_IO, 1);
	fd0 = open(FULLPATH0, O_RDONLY);
	ASSERT_GE(fd0, 0) << strerror(errno);
	fd1 = open(FULLPATH1, O_RDONLY);
	ASSERT_GE(fd1, 0) << strerror(errno);
	pending.fd = m_mock->dup_dev_fuse();
	ASSERT_GE(pending.fd, 0);
	pending.events = POLLIN;
	pending.revents = 0;

	EXPECT_CALL(*m_mock, process(
		ResultOf([&](auto in) {
			return (in.header.opcode == FUSE_READ);
		}, Eq(true)),
		_)
	).WillOnce(Invoke([&](auto in __unused, auto &out __unused) {
		sem_post(&sem);
		pause();
	}));

	/*
	 * One thread's operation will be sent to the daemon and block, and the
	 * other's will be stuck in the message queue.
	 */
	ASSERT_EQ(0, pthread_create(&th0, NULL, read_th, &fd0)) << strerror(errno);
	ASSERT_EQ(0, pthread_create(&th1, NULL, read_th, &fd1)) << strerror(errno);

	/* Wait for the first thread to block */
	sem_wait(&sem);
	/* The first READ was consumed; readable data is the queued second one. */
	poll_result = poll(&pending, 1, 5000);
	close(pending.fd);

	m_mock->kill_daemon();

	pthread_join(th0, NULL);
	pthread_join(th1, NULL);
	close(fd0);
	close(fd1);

	sem_destroy(&sem);
	EXPECT_EQ(1, poll_result);
	EXPECT_NE(0, pending.revents & POLLIN);
}

/*
 * On unmount the kernel should send a FUSE_DESTROY operation.  It should also
 * send FUSE_FORGET operations for all inodes with lookup_count > 0.
 */
TEST_F(Destroy, ok)
{
	const char FULLPATH[] = "mountpoint/some_file.txt";
	const char RELPATH[] = "some_file.txt";
	uint64_t ino = 42;

	expect_lookup(RELPATH, ino, S_IFREG | 0644, 0, 2);
	expect_forget(ino, 2);
	expect_destroy(0);

	/*
	 * access(2) the file to force a lookup.  Access it twice to double its
	 * lookup count.
	 */
	ASSERT_EQ(0, access(FULLPATH, F_OK)) << strerror(errno);
	ASSERT_EQ(0, access(FULLPATH, F_OK)) << strerror(errno);

	/*
	 * Unmount, triggering a FUSE_DESTROY and also causing a VOP_RECLAIM
	 * for every vnode on this mp, triggering FUSE_FORGET for each of them.
	 */
	m_mock->unmount();
}

/*
 * Release a successful LOOKUP reply while another thread forces the mount
 * down.  Repeating this in an isolated VM exercises creation/reclaim races;
 * it does not force every scheduling outcome inside insmntque().
 */
TEST_F(Destroy, forced_unmount_pending_lookup)
{
	sem_t pending, unmount_started;
	pthread_t lookup_thread, unmount_thread;
	uint64_t unique = 0;
	void *lookup_result, *unmount_result;
	struct statfs fs;

	ASSERT_EQ(0, sem_init(&pending, 0, 0));
	ASSERT_EQ(0, sem_init(&unmount_started, 0, 0));
	EXPECT_LOOKUP(FUSE_ROOT_ID, "racing")
	.WillOnce(Invoke([&](auto in, auto &out __unused) {
		unique = in.header.unique;
		sem_post(&pending);
	}));
	/* Forced purge ends the session; it need not send FORGET or DESTROY. */
	m_mock->m_expect_unmount = true;
	ASSERT_EQ(0, pthread_create(&lookup_thread, nullptr,
	    [](void *) -> void * {
		int error = access("mountpoint/racing", F_OK) == 0 ? 0 : errno;
		return ((void *)(intptr_t)error);
	    }, nullptr));
	while (sem_wait(&pending) != 0 && errno == EINTR)
		;
	ASSERT_EQ(0, pthread_create(&unmount_thread, nullptr,
	    [](void *arg) -> void * {
		sem_post(static_cast<sem_t *>(arg));
		int error = ::unmount("mountpoint", MNT_FORCE) == 0 ? 0 : errno;
		return ((void *)(intptr_t)error);
	    }, &unmount_started));
	while (sem_wait(&unmount_started) != 0 && errno == EINTR)
		;
	std::unique_ptr<mockfs_buf_out> reply(new mockfs_buf_out{});
	reply->header.unique = unique;
	SET_OUT_HEADER_LEN(*reply, entry);
	reply->body.entry.nodeid = 42;
	reply->body.entry.attr.ino = 42;
	reply->body.entry.attr.mode = S_IFREG | 0644;
	reply->body.entry.attr.nlink = 1;
	reply->body.entry.attr_valid = UINT64_MAX;
	m_mock->write_response(*reply);
	ASSERT_EQ(0, pthread_join(lookup_thread, &lookup_result));
	ASSERT_EQ(0, pthread_join(unmount_thread, &unmount_result));
	/* Mount teardown may reject insertion of the freshly returned inode. */
	EXPECT_TRUE((intptr_t)lookup_result == 0 ||
	    (intptr_t)lookup_result == EBUSY ||
	    (intptr_t)lookup_result == ENOTCONN) << (intptr_t)lookup_result;
	EXPECT_EQ(0, (intptr_t)unmount_result);
	ASSERT_EQ(0, statfs("mountpoint", &fs)) << strerror(errno);
	EXPECT_STRNE("fusefs", fs.f_fstypename);
	EXPECT_EQ(0, sem_destroy(&pending));
	EXPECT_EQ(0, sem_destroy(&unmount_started));
}
