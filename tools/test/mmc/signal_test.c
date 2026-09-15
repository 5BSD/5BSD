/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

typedef unsigned int u_int;
#define _SIG_WORDS 4
#define _SIG_MAXSIG 128
#define ERESTARTSYS 512
#define SLEEPQ_SLEEP 1
#define SLEEPQ_INTERRUPTIBLE 2
#define SCHEDULER_STOPPED() false
#define DROP_GIANT() ((void)0)
#define PICKUP_GIANT() ((void)0)
#define PROC_LOCK(p) ((void)(p))
#define PROC_UNLOCK(p) ((void)(p))
#define nitems(a) (sizeof(a) / sizeof((a)[0]))
struct thread { void *td_proc; };
struct task_struct {
	struct thread *task_thread;
	void *task_fn;
	_Atomic u_int kthread_sigallowed[_SIG_WORDS];
	_Atomic u_int kthread_sigpending[_SIG_WORDS];
	_Atomic uintptr_t interruptible_wchan;
	int interrupt_value;
	_Atomic bool should_stop;
};
struct completion { unsigned int done; };
static struct task_struct task;
static _Thread_local struct task_struct *current;
static pthread_mutex_t queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t joined_cv = PTHREAD_COND_INITIALIZER;
static bool joined;
static int native_signals;
static _Atomic int result;
#define atomic_load_acq_int(p) atomic_load_explicit((p), memory_order_acquire)
#define atomic_load_acq_ptr(p) atomic_load_explicit((p), memory_order_acquire)
#define atomic_store_rel_ptr(p, v) atomic_store_explicit((p), (v), memory_order_release)
#define atomic_set_int(p, v) atomic_fetch_or_explicit((p), (v), memory_order_release)
#define atomic_thread_fence_seq_cst() atomic_thread_fence(memory_order_seq_cst)
static void sleepq_lock(void *w) { (void)w; assert(pthread_mutex_lock(&queue_lock) == 0); }
static void sleepq_release(void *w) { (void)w; assert(pthread_mutex_unlock(&queue_lock) == 0); }
static void sleepq_add(void *w, void *lock, const char *name, int flags, int queue) {
	(void)w; (void)lock; (void)name; (void)flags; (void)queue;
	joined = true;
	assert(pthread_cond_broadcast(&joined_cv) == 0);
}
static void sleepq_broadcast(void *w, int flags, int priority, int queue) {
	(void)w; (void)flags; (void)priority; (void)queue;
	assert(pthread_cond_broadcast(&queue_cv) == 0);
}
static int sleepq_wait_sig(void *w, int queue) {
	(void)queue;
	assert(pthread_cond_wait(&queue_cv, &queue_lock) == 0);
	sleepq_release(w);
	return (0);
}
static void sleepq_wait(void *w, int queue) { (void)sleepq_wait_sig(w, queue); }
static void tdsignal(struct thread *td, int sig) { (void)td; (void)sig; native_signals++; }
static void linux_schedule_save_interrupt_value(struct task_struct *t, int error) {
	t->interrupt_value = error;
}
static void linux_task_finish_interruptible(struct task_struct *);
static bool linux_kthread_should_stop_task(struct task_struct *t) { return atomic_load(&t->should_stop); }
#include "power_functions.h"

static struct completion completion;
static void *waiter(void *arg) {
	current = &task;
	atomic_store(&result, linux_wait_for_common(&completion, (uintptr_t)arg));
	return (NULL);
}
static void reset(void) {
	memset(&task, 0, sizeof(task));
	task.task_fn = &task;
	current = &task;
	completion.done = 0;
	joined = false;
	atomic_store(&result, INT_MAX);
}
int main(void) {
	pthread_t thread;
	/* A signal published before entering a wait cannot be lost. */
	reset(); assert(linux_allow_signal(15) == 0);
	linux_send_sig(15, &task);
	assert(linux_wait_for_common(&completion, 1) == -ERESTARTSYS);
	assert(!joined && atomic_load(&task.interruptible_wchan) == 0);
	/* Nor can one arrive after the waiter has joined the completion queue. */
	reset(); assert(linux_allow_signal(15) == 0);
	assert(pthread_create(&thread, NULL, waiter, (void *)1) == 0);
	sleepq_lock(&completion);
	while (!joined) assert(pthread_cond_wait(&joined_cv, &queue_lock) == 0);
	sleepq_release(&completion);
	linux_send_sig(15, &task);
	assert(pthread_join(thread, NULL) == 0);
	assert(atomic_load(&result) == -ERESTARTSYS);
	assert(atomic_load(&task.interruptible_wchan) == 0);
	/* Stop must interrupt a completion even if SIGTERM is not allowed yet. */
	reset();
	atomic_store(&task.should_stop, true);
	linux_task_wake_interruptible(&task);
	assert(linux_wait_for_common(&completion, 1) == -ERESTARTSYS);
	reset();
	assert(pthread_create(&thread, NULL, waiter, (void *)1) == 0);
	sleepq_lock(&completion);
	while (!joined) assert(pthread_cond_wait(&joined_cv, &queue_lock) == 0);
	sleepq_release(&completion);
	atomic_store(&task.should_stop, true);
	linux_task_wake_interruptible(&task);
	assert(pthread_join(thread, NULL) == 0);
	assert(atomic_load(&result) == -ERESTARTSYS);
	/* Uninterruptible completion waits still require completion. */
	reset(); assert(linux_allow_signal(15) == 0);
	assert(pthread_create(&thread, NULL, waiter, NULL) == 0);
	sleepq_lock(&completion);
	while (!joined) assert(pthread_cond_wait(&joined_cv, &queue_lock) == 0);
	sleepq_release(&completion);
	linux_send_sig(15, &task);
	assert(atomic_load(&result) == INT_MAX);
	sleepq_lock(&completion); completion.done = 1;
	sleepq_broadcast(&completion, 0, 0, 0); sleepq_release(&completion);
	assert(pthread_join(thread, NULL) == 0 && atomic_load(&result) == 0);
	assert(native_signals == 0);
	reset(); assert(linux_allow_signal(0) == -EINVAL);
	assert(linux_allow_signal(129) == -EINVAL);
	assert(linux_allow_signal(128) == 0);
	linux_send_sig(128, &task);
	assert(linux_kthread_signal_pending(&task));
	puts("PASS: kernel-thread signals before/during waits, uninterruptible waits, signal bounds, no proc0 signals");
	return (0);
}
