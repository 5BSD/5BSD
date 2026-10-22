/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Boundary between kernel-ABI translation units (compiled with -D_KERNEL
 * against the source tree's headers, exactly as the production sources are)
 * and the userland host runtime (compiled against /usr/include).  Only
 * scalar and opaque-pointer types cross this interface so that no structure
 * layout is shared between the two header worlds.
 *
 * Nothing here is production code.  Coverage reports exclude these files.
 */
#ifndef KHX_HOST_H
#define KHX_HOST_H

typedef __SIZE_TYPE__ khx_size_t;

/* ---- fatal / assertion handling --------------------------------------- */
void khx_host_panic(const char *msg) __attribute__((__noreturn__));
void khx_host_vlog(const char *fmt, __builtin_va_list ap);
int khx_host_verbose(void);
int khx_host_env_flag(const char *name);	/* environment variable set */
int khx_host_env_is(const char *name, const char *value);
void khx_host_log(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 2)));
/* Expected-panic support: run fn(arg); return 1 if it panicked (the panic
 * unwinds with longjmp; the caller must discard any state fn left locked),
 * 0 if it returned.  Nested use is supported. */
int khx_host_try(void (*fn)(void *), void *arg);
const char *khx_host_last_panic(void);
/* Unwind to the innermost khx_host_try frame without recording a panic. */
void khx_host_unwind(void) __attribute__((__noreturn__));
long khx_host_panics(void);

/* ---- memory ------------------------------------------------------------ */
/* can_fail: allocation may honour fault injection (M_NOWAIT).  Returns NULL
 * only for an injected failure or genuine host exhaustion (which aborts when
 * can_fail is zero). */
void *khx_host_alloc(khx_size_t size, int zero, int can_fail, const char *tag);
void khx_host_free(void *ptr, const char *tag);
khx_size_t khx_host_alloc_size(void *ptr);
long khx_host_live_allocs(void);
long khx_host_live_tag(const char *tag);	/* live allocations with tag */
long khx_host_alloc_count(void);
void khx_host_dump_tag(const char *tag);
/* Fail the nth (1-based) subsequent fallible allocation, or -1 to disable.
 * When tag is non-NULL only allocations with that tag are counted. */
void khx_host_fail_alloc(long nth, const char *tag);
int khx_host_alloc_failed(void);	/* injected failures so far */

/* ---- locks ------------------------------------------------------------- */
/* Host lock records are keyed by the kernel object's address.  owner is the
 * kernel struct thread pointer, so cooperative tests on one pthread can still
 * detect recursion and cross-"thread" deadlock. */
#define KHX_LOCK_EXCL 1
#define KHX_LOCK_SHARED 2
void khx_host_lock_init(const void *key, const char *name, int recursable,
    int sleepable);
void khx_host_lock_destroy(const void *key);
int khx_host_lock_exists(const void *key);
void khx_host_lock_acquire(const void *key, const void *td, int mode,
    int trylock, int *acquired, const char *file, int line);
/* Returns the remaining recursion depth for exclusive owners. */
int khx_host_lock_release(const void *key, const void *td, int mode);
int khx_host_lock_held(const void *key, const void *td, int mode);
int khx_host_lock_sharers(const void *key);
const char *khx_host_lock_name(const void *key);
/* Drop every hold of td (any mode) for a sleep and return a cookie. */
int khx_host_lock_sleep_drop(const void *key, const void *td, int *mode,
    int *depth);
void khx_host_lock_sleep_reacquire(const void *key, const void *td, int mode,
    int depth);
/* After an expected panic: drop every hold of td; returns keys released. */
int khx_host_lock_force_release_all(const void *td, const void **keys,
    int max);
/* Number of locks td currently holds (used to assert balanced paths). */
int khx_host_locks_held_by(const void *td);

/* ---- sleep/wakeup ------------------------------------------------------ */
/* A test-installed scheduler hook replaces blocking.  It is called with all
 * sleep locks of the sleeper released and returns the value the sleep
 * primitive should return (0, EWOULDBLOCK, EINTR, ERESTART).  When no hook
 * is installed the sleep blocks on a real condition variable keyed by wchan
 * (timo is in ticks, 0 means forever; hz is 1000 in the harness). */
typedef int (*khx_sleep_hook_t)(void *arg, const void *wchan,
    const char *wmesg, int timo, int catch_signals);
void khx_host_set_sleep_hook(khx_sleep_hook_t hook, void *arg);
int khx_host_sleep(const void *wchan, const char *wmesg, int timo,
    int catch_signals);
void khx_host_wakeup(const void *wchan, int all);
long khx_host_wakeups(const void *wchan);
int khx_host_has_sleep_hook(void);
int khx_host_sleepers(void);	/* threads blocked in real (unhooked) sleeps */

void *khx_host_sem_new(int value);
void khx_host_sem_post(void *sem);
void khx_host_sem_wait(void *sem);

/* ---- per-thread CPU state --------------------------------------------- */
void khx_host_set_gsbase(void *base);
void *khx_host_get_gsbase(void);
unsigned long khx_host_pthread_self(void);
void khx_host_stack_bounds(void **lo, khx_size_t *size);
/* Start a real host thread running fn(arg); returns opaque handle. */
void *khx_host_thread_start(void (*fn)(void *), void *arg);
void khx_host_thread_join(void *handle);
void khx_host_thread_exit(void) __attribute__((__noreturn__));
void khx_host_yield(void);
unsigned long khx_host_monotonic_ns(void);
void khx_host_random(void *buf, khx_size_t len);

/* ---- user memory faults ------------------------------------------------ */
/* copyin/copyout consult these; addresses are host addresses. */
void khx_host_user_fault_range(const void *start, khx_size_t len);
void khx_host_user_fault_clear(void);
int khx_host_user_faults(const void *addr, khx_size_t len);
void khx_host_fail_copy(long nth);	/* fail nth copyin/copyout, -1 off */
int khx_host_copy_should_fail(void);

/* Read DIR/name where DIR is the value of environment variable dirvar.
 * The buffer is a harness allocation (tag "khx-file"). */
void *khx_host_read_file(const char *dirvar, const char *name,
    khx_size_t *len);

/* ---- test bookkeeping -------------------------------------------------- */
void khx_host_check(int ok, const char *expr, const char *file, int line);
long khx_host_checks(void);
long khx_host_failures(void);
int khx_host_finish(const char *suite);
void khx_host_case(const char *name);

#define KHX_CHECK(e) khx_host_check(!!(e), #e, __FILE__, __LINE__)
#define KHX_EQ(a, b) do {						\
	long long khx_a_ = (long long)(a), khx_b_ = (long long)(b);	\
	if (khx_a_ != khx_b_)						\
		khx_host_log("  %s=%lld %s=%lld\n", #a, khx_a_, #b, khx_b_); \
	khx_host_check(khx_a_ == khx_b_, #a " == " #b, __FILE__, __LINE__); \
} while (0)

#endif
