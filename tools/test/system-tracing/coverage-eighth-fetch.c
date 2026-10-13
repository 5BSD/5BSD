/* SPDX-License-Identifier: BSD-2-Clause */
/* Local socketpair only: readiness, timeout, interruption and peer closure. */
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include "fetch.h"
#include "common.h"
static void interrupted(int sig) { (void)sig; }
int
main(void)
{
 int fd[2], status;
 pid_t child;
 char value;
 struct sigaction sa = { .sa_handler = interrupted };
 struct itimerval timer = { .it_value = { .tv_usec = 20000 } };
 conn_t *conn;
 assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
 conn = fetch_reopen(fd[0]); assert(conn != NULL);
 fetchTimeout = 1;
 assert(fetch_read(conn, &value, 1) == -1 && errno == ETIMEDOUT);
 assert(sigaction(SIGALRM, &sa, NULL) == 0);
 fetchRestartCalls = 0;
 assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
 assert(fetch_read(conn, &value, 1) == -1 && errno == EINTR);
 child = fork(); assert(child != -1);
 if (child == 0) {
  usleep(20000);
  _exit(write(fd[1], "x", 1) == 1 ? 0 : 1);
 }
 assert(fetch_read(conn, &value, 1) == 1 && value == 'x');
 assert(waitpid(child, &status, 0) == child && status == 0);
 assert(fetch_write(conn, "y", 1) == 1);
 assert(read(fd[1], &value, 1) == 1 && value == 'y');
 assert(close(fd[1]) == 0);
 assert(fetch_read(conn, &value, 1) == 0);
 assert(fetch_close(conn) == 0);
 return (0);
}
