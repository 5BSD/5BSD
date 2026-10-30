/* SPDX-License-Identifier: BSD-2-Clause */
#include <err.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static int delivered;
static void callback(union sigval value) {
    pthread_mutex_lock(&mutex);
    delivered = value.sival_int;
    pthread_cond_signal(&ready);
    pthread_mutex_unlock(&mutex);
}
int main(void) {
    timer_t timer;
    struct sigevent event = { .sigev_notify = SIGEV_THREAD,
        .sigev_notify_function = callback, .sigev_value.sival_int = 42 };
    struct itimerspec arm = { .it_value.tv_nsec = 1000000 }, remaining;
    struct timespec deadline;
    int status = 0;
    if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) err(1, "clock_gettime");
    deadline.tv_sec += 5;
    if (timer_create(CLOCK_MONOTONIC, &event, &timer) != 0) err(1, "timer_create");
    if (timer_gettime(timer, &remaining) != 0) err(1, "timer_gettime");
    if (remaining.it_value.tv_sec || remaining.it_value.tv_nsec) errx(1, "new timer armed");
    pthread_mutex_lock(&mutex);
    if (timer_settime(timer, 0, &arm, NULL) != 0) err(1, "timer_settime");
    while (delivered == 0 && status == 0)
        status = pthread_cond_timedwait(&ready, &mutex, &deadline);
    if (status != 0 || delivered != 42) errx(1, "callback: status=%d value=%d", status, delivered);
    pthread_mutex_unlock(&mutex);
    if (timer_delete(timer) != 0) err(1, "timer_delete");
    return 0;
}
