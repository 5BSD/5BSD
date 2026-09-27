/* SPDX-License-Identifier: BSD-2-Clause
 * Run in a disposable VM: stream retries and private-kqueue process lifetime.
 * Build against the pinned liburing used by this qualification harness.
 */
#define _GNU_SOURCE
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <liburing.h>

#define CHECK(x) do { if (!(x)) { \
 fprintf(stderr, "line %d: %s (errno=%d)\n", __LINE__, #x, errno); \
 exit(1); } } while (0)

static void
submit(struct io_uring *ring, int count)
{
 int ret = io_uring_submit(ring);
 CHECK(ret >= 0);
 /* SQPOLL may consume entries while liburing calculates the ready count. */
 CHECK((ring->flags & IORING_SETUP_SQPOLL) != 0 || ret == count);
}

static void
completion(struct io_uring *ring, uint64_t id, int result)
{
 struct io_uring_cqe *cqe;
 CHECK(io_uring_wait_cqe(ring, &cqe) == 0);
 if (cqe->user_data != id || cqe->res != result) {
  fprintf(stderr, "CQE id=%llu res=%d, wanted id=%llu res=%d\n",
      (unsigned long long)cqe->user_data, cqe->res,
      (unsigned long long)id, result);
  exit(1);
 }
 io_uring_cqe_seen(ring, cqe);
}

static void
pair(int kind, int fd[2])
{
 if (kind == 0)
  CHECK(pipe(fd) == 0);
 else if (kind == 1)
  CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
 else {
  fd[0] = eventfd(0, 0);
  CHECK(fd[0] >= 0);
  fd[1] = dup(fd[0]);
  CHECK(fd[1] >= 0);
 }
}

static void
stream(int kind, int fixed, unsigned flags)
{
 struct io_uring ring;
 struct io_uring_sqe *sqe;
 struct io_uring_cqe *cqe;
 uint64_t value = 7, data = 0;
 int fd[2], replacement[2], original_flags;
 unsigned sqflags = fixed ? IOSQE_FIXED_FILE : 0;
 int async = (flags & IOSQE_ASYNC) != 0;
 unsigned setup = flags & IORING_SETUP_SQPOLL;

 pair(kind, fd);
 pair(kind, replacement);
 CHECK(io_uring_queue_init(8, &ring, setup) == 0);
 if (fixed)
  CHECK(io_uring_register_files(&ring, fd, 2) == 0);
 original_flags = fcntl(fd[0], F_GETFL);
 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_read(sqe, fixed ? 0 : fd[0], &data, sizeof(data), 0);
 sqe->flags = sqflags | (async ? IOSQE_ASYNC : 0);
 sqe->user_data = 1;
 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_nop(sqe);
 sqe->user_data = 99;
 submit(&ring, 2);
 /* A later completion proves SQPOLL has consumed the read before update. */
 completion(&ring, 99, 0);
 /* The submitter must remain runnable with a blocking, empty descriptor. */
 CHECK(io_uring_peek_cqe(&ring, &cqe) == -EAGAIN);
 CHECK(fcntl(fd[0], F_GETFL) == original_flags);
 if (fixed && !async)
  CHECK(io_uring_register_files_update(&ring, 0, replacement, 1) == 1);
 CHECK(write(fd[1], &value, sizeof(value)) == sizeof(value));
 completion(&ring, 1, sizeof(data));
 CHECK(data == value);
 if (fixed && !async)
  CHECK(io_uring_register_files_update(&ring, 0, fd, 1) == 1);

 /* Pipes/eventfds ignore positive offsets; sockets reject them. */
 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_write(sqe, fixed ? 1 : fd[1], &value, sizeof(value), 4096);
 sqe->flags = sqflags | (async ? IOSQE_ASYNC : 0);
 sqe->user_data = 2;
 submit(&ring, 1);
 if (kind == 1) {
  completion(&ring, 2, -ESPIPE);
  sqe = io_uring_get_sqe(&ring);
  io_uring_prep_write(sqe, fixed ? 1 : fd[1], &value, sizeof(value), 0);
  sqe->flags = sqflags | (async ? IOSQE_ASYNC : 0);
  sqe->user_data = 2;
  submit(&ring, 1);
 }
 completion(&ring, 2, sizeof(value));
 CHECK(read(fd[0], &data, sizeof(data)) == sizeof(data));
 CHECK(data == value);

 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_read(sqe, fixed ? 0 : fd[0], &data, sizeof(data), 0);
 sqe->flags = sqflags | (async ? IOSQE_ASYNC : 0);
 sqe->user_data = 3;
 submit(&ring, 1);
 usleep(10000);
 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_cancel64(sqe, 3, 0);
 sqe->user_data = 4;
 submit(&ring, 1);
 unsigned seen = 0;
 for (int i = 0; i < 2; i++) {
  CHECK(io_uring_wait_cqe(&ring, &cqe) == 0);
  CHECK((cqe->user_data == 3 && cqe->res == -ECANCELED) ||
      (cqe->user_data == 4 && (cqe->res == 0 ||
       (async && cqe->res == -EALREADY))));
  seen |= 1U << cqe->user_data;
  io_uring_cqe_seen(&ring, cqe);
 }
 CHECK(seen == ((1U << 3) | (1U << 4)));
 CHECK(fcntl(fd[0], F_GETFL) == original_flags);
 io_uring_queue_exit(&ring);
 close(fd[0]); close(fd[1]);
 close(replacement[0]); close(replacement[1]);
 printf("STREAM_PASS kind=%d fixed=%d setup=%u async=%d\n",
     kind, fixed, setup, async);
}

static void
backpressure(int kind)
{
 struct io_uring ring;
 struct io_uring_sqe *sqe;
 struct io_uring_cqe *cqe;
 char buf[4096] = {0};
 uint64_t value = 1, full = UINT64_MAX - 1;
 int fd[2], flags;
 ssize_t n;

 pair(kind, fd);
 flags = fcntl(fd[1], F_GETFL);
 if (kind == 2) {
  CHECK(write(fd[1], &full, sizeof(full)) == sizeof(full));
 } else {
  CHECK(fcntl(fd[1], F_SETFL, flags | O_NONBLOCK) == 0);
  do {
   n = write(fd[1], buf, sizeof(buf));
  } while (n > 0);
  CHECK(n == -1 && errno == EAGAIN);
  CHECK(fcntl(fd[1], F_SETFL, flags) == 0);
 }
 CHECK(io_uring_queue_init(8, &ring, 0) == 0);
 sqe = io_uring_get_sqe(&ring);
 io_uring_prep_write(sqe, fd[1], &value, sizeof(value), 0);
 sqe->user_data = 1;
 submit(&ring, 1);
 CHECK(io_uring_peek_cqe(&ring, &cqe) == -EAGAIN);
 CHECK(fcntl(fd[1], F_GETFL) == flags);
 /* Drain all previously queued bytes without depending on buffer sizes. */
 int readflags = fcntl(fd[0], F_GETFL);
 CHECK(fcntl(fd[0], F_SETFL, readflags | O_NONBLOCK) == 0);
 do {
  n = read(fd[0], buf, kind == 2 ? sizeof(full) : sizeof(buf));
 } while (n > 0);
 CHECK(n == -1 && errno == EAGAIN);
 CHECK(fcntl(fd[0], F_SETFL, readflags) == 0);
 completion(&ring, 1, sizeof(value));
 io_uring_queue_exit(&ring);
 close(fd[0]); close(fd[1]);
 printf("BACKPRESSURE_PASS kind=%d\n", kind);
}

static void
creator_exit(void)
{
 for (int i = 0; i < 32; i++) {
  struct io_uring ring;
  struct io_uring_sqe *sqe;
  uint64_t data;
  int fd[2], status;
  pid_t pid;

  CHECK(pipe(fd) == 0);
  CHECK(io_uring_queue_init(8, &ring, 0) == 0);
  pid = fork();
  CHECK(pid >= 0);
  if (pid == 0) {
   sqe = io_uring_get_sqe(&ring);
   io_uring_prep_read(sqe, fd[0], &data, sizeof(data), 0);
   sqe->user_data = 1;
   submit(&ring, 1);
   /* Parent retains the ring; the private kqueue's creator exits first. */
   _exit(0);
  }
  CHECK(waitpid(pid, &status, 0) == pid);
  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
  /* Last close must cancel the parked read and close the child's kqueue. */
  io_uring_queue_exit(&ring);
  close(fd[0]); close(fd[1]);
 }
 puts("CREATOR_EXIT_PASS iterations=32");
}

int
main(void)
{
 alarm(90);
 for (int kind = 0; kind < 3; kind++)
  for (int fixed = 0; fixed < 2; fixed++) {
   stream(kind, fixed, 0);
   stream(kind, fixed, IOSQE_ASYNC);
   stream(kind, fixed, IORING_SETUP_SQPOLL);
  }
 for (int kind = 0; kind < 3; kind++)
  backpressure(kind);
 creator_exit();
 puts("STREAM_COMPAT_PASS");
 return (0);
}
