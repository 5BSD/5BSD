/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
const char *test_flopen_lock_child(void);
pid_t __wrap_fork(void);
int __wrap_kill(pid_t, int);
static unsigned int kill_calls;
pid_t __wrap_fork(void) { errno = EAGAIN; return (-1); }
int __wrap_kill(pid_t pid, int sig) { (void)pid; (void)sig; ++kill_calls; return (0); }
int main(void) {
 const char *error = test_flopen_lock_child();
 puts("1..2");
 puts(kill_calls == 0 ? "ok 1 - failed fork sends no signal" : "not ok 1 - failed fork tried to signal");
 puts(error != NULL && strcmp(error, strerror(EAGAIN)) == 0 ? "ok 2 - original fork failure survives" : "not ok 2 - original fork failure lost");
 return (0);
}
