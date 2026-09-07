/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <logcmp.h>

#include "storage.h"
#include "store.h"

struct fixture {
	char path[PATH_MAX];
	int dirfd;
	int control_fd;
	pid_t manager;
};

struct writer {
	struct logcmp_storage_session session;
	uint64_t first;
	unsigned count;
	int error;
};

struct flood_writer {
	struct logcmp_storage_session session;
	atomic_bool stop;
	atomic_uint_fast64_t count;
	int error;
};

static void
attach_session(struct fixture *fixture, const char *label,
    struct logcmp_storage_session *session)
{
	ATF_REQUIRE_EQ(0, logcmp_storage_attach(fixture->control_fd, label,
	    session));
	ATF_REQUIRE_EQ(0, logcmp_storage_session_activate(session));
}

static size_t
make_record(uint8_t *buffer, uint64_t sequence)
{
	static const char subsystem[] = "tests.storage";
	static const char category[] = "ipc";
	static const char message[] = "record";
	struct logcmp_record *record;
	uint8_t *cursor;

	record = (void *)buffer;
	memset(record, 0, sizeof(*record));
	record->sequence = sequence;
	record->timestamp_ns = sequence;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = sizeof(subsystem) - 1;
	record->category_length = sizeof(category) - 1;
	record->message_length = sizeof(message) - 1;
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, sizeof(subsystem) - 1);
	cursor += sizeof(subsystem) - 1;
	memcpy(cursor, category, sizeof(category) - 1);
	cursor += sizeof(category) - 1;
	memcpy(cursor, message, sizeof(message) - 1);
	cursor += sizeof(message) - 1;
	return (cursor - buffer);
}

static size_t
make_named_record(uint8_t *buffer, uint64_t sequence, uint64_t timestamp_ns,
    const char *subsystem, const char *category)
{
	static const char message[] = "record";
	struct logcmp_record *record;
	uint8_t *cursor;
	size_t subsystem_length, category_length;

	subsystem_length = strlen(subsystem);
	category_length = strlen(category);
	record = (void *)buffer;
	memset(record, 0, sizeof(*record));
	record->sequence = sequence;
	record->timestamp_ns = timestamp_ns;
	record->severity = LOGCMP_SEVERITY_INFO;
	record->kind = LOGCMP_KIND_LOG;
	record->message_privacy = LOGCMP_PRIVACY_PUBLIC;
	record->subsystem_length = (uint16_t)subsystem_length;
	record->category_length = (uint16_t)category_length;
	record->message_length = sizeof(message) - 1;
	cursor = (void *)(record + 1);
	memcpy(cursor, subsystem, subsystem_length);
	cursor += subsystem_length;
	memcpy(cursor, category, category_length);
	cursor += category_length;
	memcpy(cursor, message, sizeof(message) - 1);
	cursor += sizeof(message) - 1;
	return (cursor - buffer);
}

static void
fixture_create(struct fixture *fixture)
{

	memset(fixture, 0, sizeof(*fixture));
	strlcpy(fixture->path, "storage.XXXXXX", sizeof(fixture->path));
	ATF_REQUIRE(mkdtemp(fixture->path) != NULL);
	fixture->dirfd = open(fixture->path,
	    O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fixture->dirfd >= 0);
	ATF_REQUIRE_EQ(0, logcmp_storage_test_start(fixture->dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, 0, 0,
	    &fixture->control_fd, &fixture->manager));
}

static void
remove_files(int dirfd)
{
	DIR *directory;
	struct dirent *entry;
	int fd;

	fd = openat(dirfd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	ATF_REQUIRE(fd >= 0);
	directory = fdopendir(fd);
	ATF_REQUIRE(directory != NULL);
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;
		ATF_REQUIRE_EQ(0, unlinkat(dirfd, entry->d_name, 0));
	}
	closedir(directory);
}

/*
 * Stop the storage manager and start a fresh one on the same directory,
 * modelling a logd restart.  The manager exits once its control channel is
 * closed and no sessions remain, so the caller must close every session first.
 */
static void
fixture_restart(struct fixture *fixture)
{
	int status;

	close(fixture->control_fd);
	fixture->control_fd = -1;
	ATF_REQUIRE_EQ(fixture->manager, waitpid(fixture->manager, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_REQUIRE_EQ(0, WEXITSTATUS(status));
	ATF_REQUIRE_EQ(0, logcmp_storage_test_start(fixture->dirfd,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, 0, 0,
	    &fixture->control_fd, &fixture->manager));
}

static void
fixture_destroy(struct fixture *fixture)
{
	int status;

	if (fixture->control_fd >= 0)
		close(fixture->control_fd);
	ATF_REQUIRE_EQ(fixture->manager, waitpid(fixture->manager, &status, 0));
	ATF_CHECK(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	remove_files(fixture->dirfd);
	close(fixture->dirfd);
	ATF_REQUIRE_EQ(0, rmdir(fixture->path));
}

static void *
write_records(void *argument)
{
	struct writer *writer;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;
	unsigned i;

	writer = argument;
	for (i = 0; i < writer->count; i++) {
		length = make_record(record, writer->first + i);
		if (logcmp_storage_append(&writer->session, (const void *)record,
		    length) == -1) {
			writer->error = errno;
			return (NULL);
		}
	}
	if (logcmp_storage_flush(&writer->session,
	    LOGCMP_STORAGE_TIMEOUT_MS) == -1)
		writer->error = errno;
	return (NULL);
}

static void *
flood_records(void *argument)
{
	struct flood_writer *writer;
	uint8_t record[LOGCMP_MAX_RECORD];
	uint64_t sequence;
	size_t length;

	writer = argument;
	sequence = 1;
	while (!atomic_load_explicit(&writer->stop, memory_order_relaxed)) {
		length = make_record(record, sequence);
		if (logcmp_storage_append(&writer->session,
		    (const void *)record, length) == 0) {
			sequence++;
			atomic_store_explicit(&writer->count, sequence - 1,
			    memory_order_relaxed);
			continue;
		}
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS) {
			sched_yield();
			continue;
		}
		writer->error = errno;
		break;
	}
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(independent_sessions_and_reopen);
ATF_TC_BODY(independent_sessions_and_reopen, tc)
{
	struct fixture fixture;
	uint8_t record[LOGCMP_MAX_RECORD];
	struct logcmp_storage_session first, second, reopened;
	size_t length;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.first", &first);
	attach_session(&fixture, "org.test.second", &second);
	length = make_record(record, 1);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&first,
	    (const void *)record, length));
	((struct logcmp_record *)(void *)record)->sequence = 2;
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&second,
	    (const void *)record, length));
	ATF_REQUIRE_EQ_MSG(0, logcmp_storage_flush(&first,
	    LOGCMP_STORAGE_TIMEOUT_MS), "flush: %s", strerror(errno));
	logcmp_storage_session_close(&first);
	attach_session(&fixture, "org.test.first", &reopened);
	((struct logcmp_record *)(void *)record)->sequence = 3;
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&reopened,
	    (const void *)record, length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&reopened,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	logcmp_storage_session_close(&reopened);
	logcmp_storage_session_close(&second);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(concurrent_sessions);
ATF_TC_BODY(concurrent_sessions, tc)
{
	struct fixture fixture;
	struct writer writers[4];
	pthread_t threads[4];
	unsigned i;

	fixture_create(&fixture);
	memset(writers, 0, sizeof(writers));
	for (i = 0; i < nitems(writers); i++) {
		char label[32];

		snprintf(label, sizeof(label), "org.test.writer.%u", i);
		attach_session(&fixture, label, &writers[i].session);
		writers[i].first = (uint64_t)i * 1000 + 1;
		writers[i].count = 100;
		ATF_REQUIRE_EQ(0, pthread_create(&threads[i], NULL,
		    write_records, &writers[i]));
	}
	for (i = 0; i < nitems(writers); i++) {
		ATF_REQUIRE_EQ(0, pthread_join(threads[i], NULL));
		ATF_CHECK_EQ_MSG(0, writers[i].error, "writer %u: %s", i,
		    strerror(writers[i].error));
		logcmp_storage_session_close(&writers[i].session);
	}
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(hot_session_does_not_starve_peer);
ATF_TC_BODY(hot_session_does_not_starve_peer, tc)
{
	struct fixture fixture;
	struct flood_writer flood;
	struct logcmp_storage_session peer;
	pthread_t thread;
	uint8_t record[LOGCMP_MAX_RECORD];
	bool peer_failed;
	size_t length;
	unsigned i;

	fixture_create(&fixture);
	memset(&flood, 0, sizeof(flood));
	atomic_init(&flood.stop, false);
	atomic_init(&flood.count, 0);
	attach_session(&fixture, "org.test.flood", &flood.session);
	attach_session(&fixture, "org.test.peer", &peer);
	ATF_REQUIRE_EQ(0, pthread_create(&thread, NULL, flood_records, &flood));
	for (i = 0; i < 1000 && atomic_load_explicit(&flood.count,
	    memory_order_relaxed) < 1000; i++)
		usleep(1000);
	ATF_CHECK(atomic_load_explicit(&flood.count,
	    memory_order_relaxed) >= 1000);

	peer_failed = false;
	for (i = 1; i <= 16; i++) {
		length = make_record(record, i);
		if (logcmp_storage_append(&peer, (const void *)record, length) == -1 ||
		    logcmp_storage_flush(&peer, 1000) == -1) {
			peer_failed = true;
			break;
		}
	}
	atomic_store_explicit(&flood.stop, true, memory_order_relaxed);
	ATF_REQUIRE_EQ(0, pthread_join(thread, NULL));
	ATF_CHECK_EQ_MSG(0, flood.error, "flood writer: %s",
	    strerror(flood.error));
	ATF_CHECK_MSG(!peer_failed, "peer failed while flood was active: %s",
	    strerror(errno));
	logcmp_storage_session_close(&flood.session);
	logcmp_storage_session_close(&peer);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(malformed_session_is_isolated);
ATF_TC_BODY(malformed_session_is_isolated, tc)
{
	struct fixture fixture;
	uint8_t record[LOGCMP_MAX_RECORD];
	struct logcmp_storage_session bad, good;
	size_t length;
	char junk[7] = "broken";

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.bad", &bad);
	attach_session(&fixture, "org.test.good", &good);
	ATF_REQUIRE_EQ(sizeof(junk), send(bad.control_fd, junk, sizeof(junk),
	    MSG_NOSIGNAL));
	length = make_record(record, 1);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&good,
	    (const void *)record, length));
	ATF_REQUIRE_EQ_MSG(0, logcmp_storage_flush(&good,
	    LOGCMP_STORAGE_TIMEOUT_MS), "good flush: %s", strerror(errno));
	ATF_CHECK(logcmp_storage_flush(&bad, 100) == -1);
	logcmp_storage_session_close(&bad);
	logcmp_storage_session_close(&good);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(unexpected_descriptor_is_closed);
ATF_TC_BODY(unexpected_descriptor_is_closed, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session bad, good;
	struct msghdr message;
	struct iovec iov;
	union {
		struct cmsghdr header;
		uint8_t bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct cmsghdr *cmsg;
	struct pollfd descriptor;
	int bearer[2];
	char junk[7] = "broken";

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.badfd", &bad);
	attach_session(&fixture, "org.test.goodfd", &good);
	ATF_REQUIRE_EQ(0, socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
	    bearer));
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	iov = (struct iovec){ .iov_base = junk, .iov_len = sizeof(junk) };
	message.msg_iov = &iov;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	cmsg = CMSG_FIRSTHDR(&message);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &bearer[1], sizeof(int));
	ATF_REQUIRE_EQ(sizeof(junk), sendmsg(bad.control_fd, &message,
	    MSG_NOSIGNAL));
	close(bearer[1]);
	descriptor = (struct pollfd){ .fd = bearer[0], .events = POLLIN };
	ATF_REQUIRE_EQ(1, poll(&descriptor, 1, 1000));
	ATF_CHECK((descriptor.revents & POLLHUP) != 0);
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&good,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	close(bearer[0]);
	logcmp_storage_session_close(&bad);
	logcmp_storage_session_close(&good);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(manager_death_is_reported);
ATF_TC_BODY(manager_death_is_reported, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;
	int status;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.death", &session);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGKILL));
	ATF_REQUIRE_EQ(fixture.manager, waitpid(fixture.manager, &status, 0));
	fixture.manager = -1;
	ATF_CHECK(logcmp_storage_flush(&session, 100) == -1);
	logcmp_storage_session_close(&session);
	close(fixture.control_fd);
	fixture.control_fd = -1;
	remove_files(fixture.dirfd);
	close(fixture.dirfd);
	ATF_REQUIRE_EQ(0, rmdir(fixture.path));
}

ATF_TC_WITHOUT_HEAD(flush_has_a_total_deadline);
ATF_TC_BODY(flush_has_a_total_deadline, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.deadline", &session);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGSTOP));
	ATF_CHECK_ERRNO(ETIMEDOUT, logcmp_storage_flush(&session, 25) == -1);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGCONT));
	logcmp_storage_session_close(&session);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(bounded_ring_backpressure);
ATF_TC_BODY(bounded_ring_backpressure, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;
	uint8_t record[LOGCMP_MAX_RECORD];
	struct timespec begin, end;
	size_t length;
	unsigned accepted;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.backpressure", &session);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGSTOP));
	length = make_record(record, 1);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &begin));
	for (accepted = 0;; accepted++) {
		((struct logcmp_record *)(void *)record)->sequence = accepted + 1;
		if (logcmp_storage_append(&session, (const void *)record,
		    length) == -1)
			break;
	}
	ATF_CHECK_EQ(EAGAIN, errno);
	ATF_CHECK(accepted > 1000);
	ATF_REQUIRE_EQ(0, clock_gettime(CLOCK_MONOTONIC, &end));
	ATF_CHECK(end.tv_sec - begin.tv_sec < 2);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGCONT));
	ATF_REQUIRE_EQ_MSG(0, logcmp_storage_flush(&session,
	    LOGCMP_STORAGE_TIMEOUT_MS), "flush after pressure: %s",
	    strerror(errno));
	logcmp_storage_session_close(&session);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(activation_and_close_lifecycle);
ATF_TC_BODY(activation_and_close_lifecycle, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;
	uint8_t record[LOGCMP_MAX_RECORD];
	size_t length;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_storage_attach(fixture.control_fd,
	    "org.test.lifecycle", &session));
	length = make_record(record, 1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_append(&session,
	    (const void *)record, length) == -1);
	ATF_REQUIRE_EQ(0, logcmp_storage_session_activate(&session));
	ATF_CHECK_ERRNO(EINVAL,
	    logcmp_storage_session_activate(&session) == -1);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&session,
	    (const void *)record, length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&session,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	logcmp_storage_session_close(&session);
	logcmp_storage_session_close(&session);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_append(&session,
	    (const void *)record, length) == -1);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(pool_descriptors_survive_exactly_one_fork);
ATF_TC_BODY(pool_descriptors_survive_exactly_one_fork, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;
	int descriptors[SHMRING_NFDS + 1], status;
	pid_t child, grandchild;
	size_t i;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_storage_attach_pool(fixture.control_fd,
	    &session));
	ATF_REQUIRE_EQ(0, logcmp_storage_session_prepare_fork(&session));
	descriptors[0] = session.control_fd;
	descriptors[1] = session.producer_fds.config_fd;
	descriptors[2] = session.producer_fds.data_fd;
	descriptors[3] = session.producer_fds.head_fd;
	descriptors[4] = session.producer_fds.tail_fd;
	child = fork();
	ATF_REQUIRE(child >= 0);
	if (child == 0) {
		for (i = 0; i < nitems(descriptors); i++)
			if (fcntl(descriptors[i], F_GETFD) == -1)
				_exit(10 + (int)i);
		grandchild = fork();
		if (grandchild == -1)
			_exit(20);
		if (grandchild == 0) {
			for (i = 0; i < nitems(descriptors); i++)
				if (fcntl(descriptors[i], F_GETFD) != -1 || errno != EBADF)
					_exit(30 + (int)i);
			_exit(0);
		}
		if (waitpid(grandchild, &status, 0) != grandchild ||
		    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
			_exit(40);
		_exit(0);
	}
	ATF_REQUIRE_EQ(child, waitpid(child, &status, 0));
	ATF_REQUIRE(WIFEXITED(status));
	ATF_CHECK_EQ(0, WEXITSTATUS(status));
	logcmp_storage_session_close(&session);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_is_identity_scoped_and_ordered);
ATF_TC_BODY(query_is_identity_scoped_and_ordered, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session alpha, beta;
	struct logcmp_store_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.alpha", &alpha);
	attach_session(&fixture, "org.test.beta", &beta);
	length = make_record(record, 101);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&alpha,
	    (const void *)record, length));
	((struct logcmp_record *)(void *)record)->sequence = 202;
	((struct logcmp_record *)(void *)record)->severity = LOGCMP_SEVERITY_FATAL;
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&beta,
	    (const void *)record, length));

	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_storage_query_next(&alpha, 0, &cursor,
	    output, sizeof(output), &output_length, LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(101,
	    ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(0, logcmp_storage_query_next(&alpha, 0, &cursor,
	    output, sizeof(output), &output_length, LOGCMP_STORAGE_TIMEOUT_MS));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(1, logcmp_storage_query_next(&beta,
	    LOGCMP_SEVERITY_ERROR, &cursor, output, sizeof(output),
	    &output_length, LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(202,
	    ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(length, output_length);
	logcmp_storage_session_close(&alpha);
	logcmp_storage_session_close(&beta);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(multiplexed_pool_preserves_identity);
ATF_TC_BODY(multiplexed_pool_preserves_identity, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session pool, ordinary;
	struct logcmp_store_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;

	fixture_create(&fixture);
	ATF_REQUIRE_EQ(0, logcmp_storage_attach_pool(fixture.control_fd, &pool));
	ATF_REQUIRE_EQ(0, logcmp_storage_session_activate(&pool));
	attach_session(&fixture, "org.test.ordinary", &ordinary);
	length = make_record(record, 11);
	ATF_REQUIRE_EQ(0, logcmp_storage_append_for(&pool, "org.test.alpha",
	    (const void *)record, length));
	((struct logcmp_record *)(void *)record)->sequence = 22;
	ATF_REQUIRE_EQ(0, logcmp_storage_append_for(&pool, "org.test.beta",
	    (const void *)record, length));
	ATF_CHECK_ERRNO(EACCES,
	    logcmp_storage_append_for(&ordinary, "org.test.alpha",
	    (const void *)record, length) == -1);
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&pool,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next_for(&pool, "org.test.alpha", 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(11, ((struct logcmp_record *)(void *)output)->sequence);
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next_for(&pool, "org.test.beta", 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(22, ((struct logcmp_record *)(void *)output)->sequence);
	logcmp_storage_session_close(&ordinary);
	logcmp_storage_session_close(&pool);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_has_a_total_deadline);
ATF_TC_BODY(query_has_a_total_deadline, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session session;
	struct logcmp_store_cursor cursor;
	uint8_t output[LOGCMP_MAX_RECORD];
	size_t output_length;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.query-deadline", &session);
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGSTOP));
	ATF_CHECK_ERRNO(ETIMEDOUT, logcmp_storage_query_next(&session, 0,
	    &cursor, output, sizeof(output), &output_length, 25) == -1);
	ATF_REQUIRE_EQ(0, kill(fixture.manager, SIGCONT));
	logcmp_storage_session_close(&session);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_slices_are_hidden_from_clients);
ATF_TC_BODY(query_slices_are_hidden_from_clients, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session other, target;
	struct logcmp_store_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;
	unsigned i;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.other", &other);
	attach_session(&fixture, "org.test.target", &target);
	for (i = 0; i < LOGCMP_STORE_QUERY_RECORD_BUDGET; i++) {
		length = make_record(record, i + 1);
		ATF_REQUIRE_EQ(0, logcmp_storage_append(&other,
		    (const void *)record, length));
	}
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&other,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	length = make_record(record, 999);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&target,
	    (const void *)record, length));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next(&target, 0, &cursor, output,
	    sizeof(output), &output_length, LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(999,
	    ((struct logcmp_record *)(void *)output)->sequence);
	logcmp_storage_session_close(&other);
	logcmp_storage_session_close(&target);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(query_filter_is_applied_server_side);
ATF_TC_BODY(query_filter_is_applied_server_side, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session alpha, beta;
	struct logcmp_store_cursor cursor;
	struct logcmp_query_filter filter;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	size_t length, output_length;

	fixture_create(&fixture);
	attach_session(&fixture, "org.q.alpha", &alpha);
	attach_session(&fixture, "org.q.beta", &beta);
	/* alpha: two distinct subsystems/timestamps. */
	length = make_named_record(record, 1, 1000, "auth.daemon", "login");
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&alpha, (const void *)record,
	    length));
	length = make_named_record(record, 2, 5000, "net.stack", "connect");
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&alpha, (const void *)record,
	    length));
	/* beta owns a colliding subsystem, to prove scoping is not widened. */
	length = make_named_record(record, 3, 1000, "auth.daemon", "login");
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&beta, (const void *)record,
	    length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&alpha,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&beta,
	    LOGCMP_STORAGE_TIMEOUT_MS));

	/* Subsystem substring "auth" over alpha matches only sequence 1. */
	memset(&filter, 0, sizeof(filter));
	filter.subsystem = "auth";
	filter.subsystem_length = 4;
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next_filtered_for(&alpha, "org.q.alpha", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(1, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF,
	    logcmp_storage_query_next_filtered_for(&alpha, "org.q.alpha", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));

	/* Time window narrows alpha to sequence 2. */
	memset(&filter, 0, sizeof(filter));
	filter.from_ns = 4000;
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next_filtered_for(&alpha, "org.q.alpha", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(2, ((struct logcmp_record *)(void *)output)->sequence);

	/*
	 * The same "auth.daemon" exact filter under beta returns only beta's
	 * own record (sequence 3) -- the filter never reaches alpha's data.
	 */
	memset(&filter, 0, sizeof(filter));
	filter.subsystem = "auth.daemon";
	filter.subsystem_length = 11;
	filter.match_flags = LOGCMP_QUERY_MATCH_SUBSYSTEM_EXACT;
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD,
	    logcmp_storage_query_next_filtered_for(&beta, "org.q.beta", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(3, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF,
	    logcmp_storage_query_next_filtered_for(&beta, "org.q.beta", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));

	/* A cross-label filtered query is refused outright. */
	ATF_CHECK_ERRNO(EACCES,
	    logcmp_storage_query_next_filtered_for(&beta, "org.q.alpha", 0,
	    &filter, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS) == -1);

	logcmp_storage_session_close(&alpha);
	logcmp_storage_session_close(&beta);
	fixture_destroy(&fixture);
}

/*
 * Capability-cleanup reclaim over the manager's control channel: reclaiming one
 * label makes its records unqueryable and its count zero, leaves every other
 * label intact, is idempotent, and treats an unknown label as a no-op success.
 */
ATF_TC_WITHOUT_HEAD(reclaim_prunes_only_the_retired_label);
ATF_TC_BODY(reclaim_prunes_only_the_retired_label, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session alpha, beta;
	struct logcmp_store_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	uint64_t count;
	size_t length, output_length;

	fixture_create(&fixture);
	attach_session(&fixture, "org.test.alpha", &alpha);
	attach_session(&fixture, "org.test.beta", &beta);
	length = make_record(record, 101);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&alpha, (const void *)record,
	    length));
	((struct logcmp_record *)(void *)record)->sequence = 202;
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&beta, (const void *)record,
	    length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&alpha, LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&beta, LOGCMP_STORAGE_TIMEOUT_MS));

	/* An unknown label is a clean no-op; a malformed one is rejected. */
	ATF_REQUIRE_EQ(0, logcmp_storage_reclaim(fixture.control_fd,
	    "org.test.never"));
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_reclaim(fixture.control_fd,
	    "") == -1);

	/* Retire alpha, twice, to prove idempotency. */
	ATF_REQUIRE_EQ(0, logcmp_storage_reclaim(fixture.control_fd,
	    "org.test.alpha"));
	ATF_REQUIRE_EQ(0, logcmp_storage_reclaim(fixture.control_fd,
	    "org.test.alpha"));

	/* alpha's records and count are gone. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF, logcmp_storage_query_next(&alpha, 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_count(&alpha, "org.test.alpha",
	    strlen("org.test.alpha"), &count));
	ATF_CHECK_EQ(0, count);

	/* beta is untouched. */
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD, logcmp_storage_query_next(&beta,
	    0, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(202, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_REQUIRE_EQ(0, logcmp_storage_count(&beta, "org.test.beta",
	    strlen("org.test.beta"), &count));
	ATF_CHECK_EQ(1, count);

	/* beta can still append after the peer's reclaim. */
	((struct logcmp_record *)(void *)record)->sequence = 303;
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&beta, (const void *)record,
	    length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&beta, LOGCMP_STORAGE_TIMEOUT_MS));

	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_reclaim(-1, "org.test.alpha") == -1);
	logcmp_storage_session_close(&alpha);
	logcmp_storage_session_close(&beta);
	fixture_destroy(&fixture);
}

/*
 * End-to-end cross-tenant + restart invariant over the real control channel and
 * manager process: after label "L" is reclaimed and the manager is restarted on
 * the same directory, a NEW owner reusing "L" reads only its own records and can
 * never see the retired owner's.  This is the security-relevant path the durable
 * reclaim floor protects.
 */
ATF_TC_WITHOUT_HEAD(reused_label_across_restart_is_isolated);
ATF_TC_BODY(reused_label_across_restart_is_isolated, tc)
{
	struct fixture fixture;
	struct logcmp_storage_session owner;
	struct logcmp_store_cursor cursor;
	uint8_t record[LOGCMP_MAX_RECORD], output[LOGCMP_MAX_RECORD];
	uint64_t count;
	size_t length, output_length;
	unsigned i;

	fixture_create(&fixture);

	/* Owner A writes three records under org.shared, then it is retired. */
	attach_session(&fixture, "org.shared", &owner);
	for (i = 0; i < 3; i++) {
		length = make_record(record, 100 + i);
		ATF_REQUIRE_EQ(0, logcmp_storage_append(&owner,
		    (const void *)record, length));
	}
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&owner, LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_reclaim(fixture.control_fd,
	    "org.shared"));
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF, logcmp_storage_query_next(&owner, 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	logcmp_storage_session_close(&owner);

	/* Restart the manager on the same directory. */
	fixture_restart(&fixture);

	/* Owner B reuses the name: A's records stay invisible across the restart. */
	attach_session(&fixture, "org.shared", &owner);
	memset(&cursor, 0, sizeof(cursor));
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF, logcmp_storage_query_next(&owner, 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_count(&owner, "org.shared",
	    strlen("org.shared"), &count));
	ATF_CHECK_EQ(0, count);

	/* B's own records are visible and are the only ones returned. */
	length = make_record(record, 900);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&owner, (const void *)record,
	    length));
	length = make_record(record, 901);
	ATF_REQUIRE_EQ(0, logcmp_storage_append(&owner, (const void *)record,
	    length));
	ATF_REQUIRE_EQ(0, logcmp_storage_flush(&owner, LOGCMP_STORAGE_TIMEOUT_MS));
	memset(&cursor, 0, sizeof(cursor));
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD, logcmp_storage_query_next(&owner,
	    0, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(900, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_REQUIRE_EQ(LOGCMP_STORE_QUERY_RECORD, logcmp_storage_query_next(&owner,
	    0, &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_CHECK_EQ(901, ((struct logcmp_record *)(void *)output)->sequence);
	ATF_CHECK_EQ(LOGCMP_STORE_QUERY_EOF, logcmp_storage_query_next(&owner, 0,
	    &cursor, output, sizeof(output), &output_length,
	    LOGCMP_STORAGE_TIMEOUT_MS));
	ATF_REQUIRE_EQ(0, logcmp_storage_count(&owner, "org.shared",
	    strlen("org.shared"), &count));
	ATF_CHECK_EQ(2, count);

	logcmp_storage_session_close(&owner);
	fixture_destroy(&fixture);
}

ATF_TC_WITHOUT_HEAD(arguments);
ATF_TC_BODY(arguments, tc)
{
	uint8_t record[LOGCMP_MAX_RECORD];
	int fd;
	struct logcmp_storage_session session;
	size_t length;

	length = make_record(record, 1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_test_start(-1,
	    LOGCMP_STORE_SEGMENT_MIN, LOGCMP_STORE_SEGMENTS_DEFAULT, 0, 0, &fd,
	    NULL) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_attach(-1, "x", &session) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_append(NULL,
	    (const void *)record, length) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_flush(NULL, 1) == -1);
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_query_next(NULL, 0, NULL,
	    record, sizeof(record), &length, 1) == -1);
	memset(&session, 0, sizeof(session));
	session.control_fd = -1;
	ATF_CHECK_ERRNO(EINVAL, logcmp_storage_flush(&session, 0) == -1);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, independent_sessions_and_reopen);
	ATF_TP_ADD_TC(tp, concurrent_sessions);
	ATF_TP_ADD_TC(tp, hot_session_does_not_starve_peer);
	ATF_TP_ADD_TC(tp, malformed_session_is_isolated);
	ATF_TP_ADD_TC(tp, unexpected_descriptor_is_closed);
	ATF_TP_ADD_TC(tp, manager_death_is_reported);
	ATF_TP_ADD_TC(tp, flush_has_a_total_deadline);
	ATF_TP_ADD_TC(tp, bounded_ring_backpressure);
	ATF_TP_ADD_TC(tp, activation_and_close_lifecycle);
	ATF_TP_ADD_TC(tp, pool_descriptors_survive_exactly_one_fork);
	ATF_TP_ADD_TC(tp, query_is_identity_scoped_and_ordered);
	ATF_TP_ADD_TC(tp, multiplexed_pool_preserves_identity);
	ATF_TP_ADD_TC(tp, query_has_a_total_deadline);
	ATF_TP_ADD_TC(tp, query_slices_are_hidden_from_clients);
	ATF_TP_ADD_TC(tp, query_filter_is_applied_server_side);
	ATF_TP_ADD_TC(tp, reclaim_prunes_only_the_retired_label);
	ATF_TP_ADD_TC(tp, reused_label_across_restart_is_isolated);
	ATF_TP_ADD_TC(tp, arguments);
	return (atf_no_error());
}
