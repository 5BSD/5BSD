/* SPDX-License-Identifier: BSD-2-Clause */
/* Functional regression checks, not evidence that DTrace probes fire live. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <archive.h>
#include <archive_entry.h>

/* Private libfetch calls are intentionally tested at their probe boundary. */
struct fetchconn;
extern struct fetchconn *fetch_reopen(int);
extern ssize_t fetch_read(struct fetchconn *, void *, size_t);
extern ssize_t fetch_write(struct fetchconn *, const void *, size_t);
extern int fetch_close(struct fetchconn *);
extern int fetchTimeout;

static pthread_rwlock_t lock = PTHREAD_RWLOCK_INITIALIZER;
static sem_t ready, release_wait;

static void *
reader(void *arg)
{
	(void)arg;
	assert(pthread_rwlock_rdlock(&lock) == 0);
	assert(sem_post(&ready) == 0);
	assert(sem_wait(&release_wait) == 0);
	assert(pthread_rwlock_unlock(&lock) == 0);
	return (NULL);
}

static void
waits(void)
{
	pthread_t thread;
	struct timespec deadline;

	assert(sem_init(&ready, 0, 0) == 0);
	assert(sem_init(&release_wait, 0, 0) == 0);
	assert(pthread_create(&thread, NULL, reader, NULL) == 0);
	assert(sem_wait(&ready) == 0);
	assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	deadline.tv_nsec += 20000000;
	if (deadline.tv_nsec >= 1000000000) {
		deadline.tv_sec++;
		deadline.tv_nsec -= 1000000000;
	}
	assert(pthread_rwlock_timedwrlock(&lock, &deadline) == ETIMEDOUT);
	assert(sem_post(&release_wait) == 0);
	assert(pthread_join(thread, NULL) == 0);
	assert(pthread_rwlock_wrlock(&lock) == 0);
	assert(pthread_rwlock_unlock(&lock) == 0);
	assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
	assert(sem_timedwait(&ready, &deadline) == -1 && errno == ETIMEDOUT);
	assert(sem_trywait(&ready) == -1 && errno == EAGAIN);
	assert(sem_destroy(&ready) == 0);
	assert(sem_destroy(&release_wait) == 0);
	assert(pthread_rwlock_destroy(&lock) == 0);
}

static void
archives(void)
{
	char data[16384];
	size_t used;
	struct archive *a;
	struct archive_entry *entry;

	a = archive_write_new();
	assert(a != NULL);
	assert(archive_write_set_format_pax_restricted(a) == ARCHIVE_OK);
	assert(archive_write_open_memory(a, data, sizeof(data), &used) == ARCHIVE_OK);
	entry = archive_entry_new();
	assert(entry != NULL);
	archive_entry_set_pathname(entry, "payload");
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_perm(entry, 0600);
	archive_entry_set_size(entry, 4);
	assert(archive_write_header(a, entry) == ARCHIVE_OK);
	assert(archive_write_data(a, "data", 4) == 4);
	archive_entry_free(entry);
	assert(archive_write_close(a) == ARCHIVE_OK);
	assert(archive_write_free(a) == ARCHIVE_OK);
	a = archive_read_new();
	assert(a != NULL);
	assert(archive_read_support_format_tar(a) == ARCHIVE_OK);
	assert(archive_read_open_memory(a, data, used) == ARCHIVE_OK);
	assert(archive_read_next_header(a, &entry) == ARCHIVE_OK);
	assert(archive_read_data_skip(a) == ARCHIVE_OK);
	assert(archive_read_next_header(a, &entry) == ARCHIVE_EOF);
	assert(archive_read_free(a) == ARCHIVE_OK);
}

static void
fetches(void)
{
	int fd[2];
	struct fetchconn *conn;
	char data[8];

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
	conn = fetch_reopen(fd[0]);
	assert(conn != NULL);
	assert(write(fd[1], "data", 4) == 4);
	assert(fetch_read(conn, data, sizeof(data)) == 4);
	assert(memcmp(data, "data", 4) == 0);
	assert(fetch_write(conn, "reply", 5) == 5);
	assert(read(fd[1], data, sizeof(data)) == 5);
	assert(memcmp(data, "reply", 5) == 0);
	assert(shutdown(fd[1], SHUT_WR) == 0);
	assert(fetch_read(conn, data, sizeof(data)) == 0);
	assert(close(fd[1]) == 0);
	assert(fetch_write(conn, "x", 1) == -1 && errno == EPIPE);
	assert(fetch_close(conn) == 0);
}

int
main(int argc, char **argv)
{
	assert(argc == 2);
	alarm(10);
	assert(signal(SIGPIPE, SIG_IGN) != SIG_ERR);
	if (strcmp(argv[1], "waits") == 0)
		waits();
	else if (strcmp(argv[1], "archives") == 0)
		archives();
	else if (strcmp(argv[1], "fetches") == 0)
		fetches();
	else
		return (2);
	puts("PASS");
	return (0);
}
