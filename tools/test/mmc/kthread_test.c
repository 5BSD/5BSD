/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __unused
#define __unused __attribute__((unused))
#endif
#define KTHREAD_SHOULD_STOP_MASK 1
#define SWI_NET 0
#define PI_SWI(n) (n)
#define SRQ_BORING 0
typedef int linux_task_fn_t(void *);
struct completion {
	pthread_mutex_t lock;
	pthread_cond_t cv;
	bool done;
};
struct task_struct {
	_Atomic unsigned kthread_flags;
	_Atomic int usage;
	linux_task_fn_t *task_fn;
	void *task_data;
	int task_ret;
	struct completion exited;
};
struct thread { struct task_struct *td_lkpi_task; };
static _Thread_local struct task_struct *current;
static _Atomic unsigned freed, runs, interrupts;
#define atomic_read(p) atomic_load(p)
#define atomic_or(v, p) ((void)atomic_fetch_or((p), (v)))
static void get_task_struct(struct task_struct *t) { assert(atomic_fetch_add(&t->usage, 1) > 0); }
static void put_task_struct(struct task_struct *t) {
	if (atomic_fetch_sub(&t->usage, 1) == 1) {
		assert(pthread_cond_destroy(&t->exited.cv) == 0);
		assert(pthread_mutex_destroy(&t->exited.lock) == 0);
		atomic_fetch_add(&freed, 1);
		free(t);
	}
}
static void complete(struct completion *c) {
	assert(pthread_mutex_lock(&c->lock) == 0);
	c->done = true;
	assert(pthread_cond_broadcast(&c->cv) == 0);
	assert(pthread_mutex_unlock(&c->lock) == 0);
}
static void wait_for_completion(struct completion *c) {
	assert(pthread_mutex_lock(&c->lock) == 0);
	while (!c->done) assert(pthread_cond_wait(&c->cv, &c->lock) == 0);
	assert(pthread_mutex_unlock(&c->lock) == 0);
}
static void linux_task_wake_interruptible(struct task_struct *t) {
	assert(atomic_load(&t->kthread_flags) & KTHREAD_SHOULD_STOP_MASK);
	atomic_fetch_add(&interrupts, 1);
}
static void kthread_unpark(struct task_struct *t) { (void)t; }
static void wake_up_process(struct task_struct *t) { (void)t; }
static void linux_set_current(struct thread *td) { assert(td->td_lkpi_task != NULL); }
static void thread_lock(struct thread *td) { (void)td; }
static void sched_prio(struct thread *td, int p) { (void)td; (void)p; }
static void sched_add(struct thread *td, int flags) { (void)td; (void)flags; }
static void kthread_exit(void) {
	struct task_struct *t = current;
	current = NULL;
	put_task_struct(t); /* Native thread destructor's reference. */
}
#include "power_functions.h"

static int returns(void *arg) { atomic_fetch_add(&runs, 1); return (*(int *)arg); }
static struct task_struct *create(linux_task_fn_t *fn, void *arg) {
	struct task_struct *t = calloc(1, sizeof(*t));
	assert(t != NULL);
	atomic_init(&t->usage, 1);
	assert(pthread_mutex_init(&t->exited.lock, NULL) == 0);
	assert(pthread_cond_init(&t->exited.cv, NULL) == 0);
	struct thread td = { .td_lkpi_task = t };
	assert(linux_kthread_setup_and_run(&td, fn, arg) == t);
	return (t);
}
static void *runner(void *arg) { current = arg; linux_kthread_fn(NULL); return (NULL); }
static struct completion entered, finish;
static int waits(void *arg) {
	complete(&entered);
	wait_for_completion(&finish);
	return (returns(arg));
}
static void *stopper(void *arg) {
	assert(linux_kthread_stop(arg) == 37);
	return (NULL);
}
int main(void) {
	struct task_struct *t;
	pthread_t worker, joiner;
	int value = 37;
	/* Natural exits without a retained handle must not leak. */
	t = create(returns, &value);
	current = t; linux_kthread_fn(NULL);
	assert(atomic_load(&freed) == 1);
	/* The driver's retained reference survives an exit before stop starts. */
	t = create(returns, &value); get_task_struct(t);
	current = t; linux_kthread_fn(NULL);
	assert(atomic_load(&freed) == 1 && atomic_load(&t->usage) == 1);
	assert(linux_kthread_stop(t) == value);
	assert(atomic_load(&t->usage) == 1);
	put_task_struct(t); assert(atomic_load(&freed) == 2);
	/* A stopped thread that never called its function reports EINTR. */
	t = create(returns, &value); get_task_struct(t);
	atomic_or(KTHREAD_SHOULD_STOP_MASK, &t->kthread_flags);
	current = t; linux_kthread_fn(NULL);
	assert(linux_kthread_stop(t) == -EINTR && atomic_load(&runs) == 2);
	put_task_struct(t);
	/* Completion and join on separate threads preserve both references. */
	assert(pthread_mutex_init(&entered.lock, NULL) == 0);
	assert(pthread_cond_init(&entered.cv, NULL) == 0);
	assert(pthread_mutex_init(&finish.lock, NULL) == 0);
	assert(pthread_cond_init(&finish.cv, NULL) == 0);
	t = create(waits, &value); get_task_struct(t);
	assert(pthread_create(&worker, NULL, runner, t) == 0);
	wait_for_completion(&entered);
	assert(pthread_create(&joiner, NULL, stopper, t) == 0);
	complete(&finish);
	assert(pthread_join(worker, NULL) == 0);
	assert(pthread_join(joiner, NULL) == 0);
	assert(atomic_load(&t->usage) == 1);
	put_task_struct(t);
	assert(atomic_load(&freed) == 4 && atomic_load(&interrupts) == 3);
	puts("PASS: kthread exit before/during join, natural-exit ownership, stop before entry");
	return (0);
}
