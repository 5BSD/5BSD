/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <rpoll.h>

static int ready, timer_calls, cancelled_calls;
static int registration;

static void
readable(int fd, int mask, void *arg)
{
    char c;
    if (arg != &ready || !(mask & RPOLL_IN) || read(fd, &c, 1) != 1 || c != 'x')
        exit(1);
    ready++;
    poll_unregister(registration);
}

static void
tick(int id, void *arg)
{
    if (arg != &timer_calls) exit(2);
    if (++timer_calls == 3) poll_stop_timer(id);
}

static void
cancelled(int id, void *arg)
{
    (void)id;
    if (arg != &cancelled_calls) exit(3);
    cancelled_calls++;
}

int
main(void)
{
    int fds[2];
    alarm(10);
    if (pipe(fds) != 0) return 4;
    registration = poll_register(fds[0], readable, &ready, RPOLL_IN);
    if (registration < 0 || write(fds[1], "x", 1) != 1) return 5;
    poll_dispatch(1);
    if (ready != 1) return 6;
    /* A still-readable descriptor must no longer trigger after unregister. */
    if (write(fds[1], "x", 1) != 1) return 7;
    poll_dispatch(0);
    if (ready != 1) return 8;
    close(fds[0]); close(fds[1]);
    int doomed = poll_start_timer(0, 0, cancelled, &cancelled_calls);
    if (doomed < 0) return 9;
    poll_stop_timer(doomed);
    int repeating = poll_start_timer(1, 1, tick, &timer_calls);
    if (repeating < 0) return 10;
    while (timer_calls < 3) poll_dispatch(1);
    poll_dispatch(0);
    if (timer_calls != 3 || cancelled_calls != 0) return 11;
    int once = poll_start_utimer(0, 0, cancelled, &cancelled_calls);
    if (once < 0) return 12;
    while (cancelled_calls == 0) poll_dispatch(1);
    poll_dispatch(0);
    return cancelled_calls != 1;
}
