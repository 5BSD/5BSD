/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Userland host runtime for kernel-source coverage harnesses.  Compiled
 * against the host's /usr/include; never sees kernel structure layouts.
 * Not production code; excluded from reported coverage.
 */
#include <machine/sysarch.h>

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "khx_host.h"

static pthread_mutex_t khx_big = PTHREAD_MUTEX_INITIALIZER;

/* ---- output and fatal ------------------------------------------------- */
void
khx_host_vlog(const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
}

int
khx_host_env_flag(const char *name)
{
	return (getenv(name) != NULL);
}

int
khx_host_env_is(const char *name, const char *value)
{
	const char *v = getenv(name);

	return (v != NULL && strcmp(v, value) == 0);
}

int
khx_host_verbose(void)
{
	return (getenv("KHX_VERBOSE") != NULL);
}

void
khx_host_log(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

struct khx_try_frame {
	sigjmp_buf env;
	struct khx_try_frame *prev;
};
static __thread struct khx_try_frame *khx_try_top;
static char khx_panic_msg[512];
static long khx_panic_count;

void
khx_host_panic(const char *msg)
{
	snprintf(khx_panic_msg, sizeof(khx_panic_msg), "%s", msg);
	__atomic_add_fetch(&khx_panic_count, 1, __ATOMIC_SEQ_CST);
	if (khx_try_top != NULL)
		siglongjmp(khx_try_top->env, 1);
	fprintf(stderr, "KHX PANIC: %s\n", msg);
	abort();
}

void
khx_host_unwind(void)
{
	if (khx_try_top == NULL) {
		fprintf(stderr, "KHX: unwind without frame\n");
		abort();
	}
	siglongjmp(khx_try_top->env, 2);
}

int
khx_host_try(void (*fn)(void *), void *arg)
{
	struct khx_try_frame frame;

	frame.prev = khx_try_top;
	if (sigsetjmp(frame.env, 0) != 0) {
		khx_try_top = frame.prev;
		return (1);
	}
	khx_try_top = &frame;
	fn(arg);
	khx_try_top = frame.prev;
	return (0);
}

const char *
khx_host_last_panic(void)
{
	return (khx_panic_msg);
}

long
khx_host_panics(void)
{
	return (__atomic_load_n(&khx_panic_count, __ATOMIC_SEQ_CST));
}

/* ---- memory ------------------------------------------------------------ */
struct khx_hdr {
	size_t size;
	const char *tag;
	struct khx_hdr *prev, *next;
	uint64_t magic;
	uint64_t pad;
};
static struct khx_hdr khx_all = { 0, NULL, &khx_all, &khx_all, 0, 0 };
#define KHX_MAGIC 0x6b68782d616c6c63ULL
#define KHX_ALIGN 128
static long khx_live, khx_allocs, khx_fail_nth = -1, khx_failed;
static const char *khx_fail_tag;

void
khx_host_fail_alloc(long nth, const char *tag)
{
	pthread_mutex_lock(&khx_big);
	khx_fail_nth = nth;
	khx_fail_tag = tag;
	pthread_mutex_unlock(&khx_big);
}

int
khx_host_alloc_failed(void)
{
	return ((int)khx_failed);
}

void *
khx_host_alloc(khx_size_t size, int zero, int can_fail, const char *tag)
{
	struct khx_hdr *h;
	int fail = 0;

	pthread_mutex_lock(&khx_big);
	if (can_fail && khx_fail_nth > 0 &&
	    (khx_fail_tag == NULL || (tag != NULL &&
	    strcmp(tag, khx_fail_tag) == 0))) {
		if (--khx_fail_nth == 0) {
			fail = 1;
			khx_failed++;
			khx_fail_nth = -1;
		}
	}
	if (!fail) {
		khx_live++;
		khx_allocs++;
	}
	pthread_mutex_unlock(&khx_big);
	if (fail)
		return (NULL);
	/* Kernel malloc(9) returns cache-line aligned memory for these sizes;
	 * keep 128-byte alignment so aligned kernel structures stay valid. */
	{
		void *raw = NULL;

		if (posix_memalign(&raw, KHX_ALIGN, KHX_ALIGN +
		    (size == 0 ? 1 : size)) != 0)
			raw = NULL;
		h = raw == NULL ? NULL :
		    (struct khx_hdr *)((char *)raw + KHX_ALIGN - sizeof(*h));
	}
	if (h == NULL) {
		if (can_fail)
			return (NULL);
		khx_host_panic("host allocation exhausted for M_WAITOK");
	}
	h->size = size;
	h->tag = tag;
	h->magic = KHX_MAGIC;
	pthread_mutex_lock(&khx_big);
	h->next = khx_all.next;
	h->prev = &khx_all;
	khx_all.next->prev = h;
	khx_all.next = h;
	pthread_mutex_unlock(&khx_big);
	if (zero)
		memset(h + 1, 0, size);
	else
		memset(h + 1, 0xa5, size);	/* expose reads of uninitialized memory */
	return (h + 1);
}

khx_size_t
khx_host_alloc_size(void *ptr)
{
	struct khx_hdr *h = (struct khx_hdr *)ptr - 1;

	if (h->magic != KHX_MAGIC)
		khx_host_panic("alloc_size of foreign pointer");
	return (h->size);
}

void
khx_host_free(void *ptr, const char *tag)
{
	struct khx_hdr *h;

	(void)tag;
	if (ptr == NULL)
		return;
	h = (struct khx_hdr *)ptr - 1;
	if (h->magic != KHX_MAGIC)
		khx_host_panic("free of foreign or already-freed pointer");
	h->magic = 0;
	memset(ptr, 0x5a, h->size);	/* expose use after free */
	pthread_mutex_lock(&khx_big);
	h->prev->next = h->next;
	h->next->prev = h->prev;
	khx_live--;
	pthread_mutex_unlock(&khx_big);
	free((char *)h + sizeof(*h) - KHX_ALIGN);
}

long
khx_host_live_allocs(void)
{
	return (__atomic_load_n(&khx_live, __ATOMIC_SEQ_CST));
}

long
khx_host_live_tag(const char *tag)
{
	long n = 0;

	pthread_mutex_lock(&khx_big);
	for (struct khx_hdr *h = khx_all.next; h != &khx_all; h = h->next)
		if (h->tag != NULL && strcmp(h->tag, tag) == 0)
			n++;
	pthread_mutex_unlock(&khx_big);
	return (n);
}

/* Log live allocations with a tag, grouped by size (leak diagnosis). */
void
khx_host_dump_tag(const char *tag)
{
	size_t sizes[32];
	long counts[32];
	int n = 0;

	pthread_mutex_lock(&khx_big);
	for (struct khx_hdr *h = khx_all.next; h != &khx_all; h = h->next) {
		int i;

		if (h->tag == NULL || strcmp(h->tag, tag) != 0)
			continue;
		for (i = 0; i < n && sizes[i] != h->size; i++)
			;
		if (i == n && n < 32) {
			sizes[n] = h->size;
			counts[n++] = 0;
		}
		if (i < n)
			counts[i]++;
	}
	pthread_mutex_unlock(&khx_big);
	for (int i = 0; i < n; i++)
		khx_host_log("  live %s: %ld x %zu bytes\n", tag, counts[i],
		    sizes[i]);
}

long
khx_host_alloc_count(void)
{
	return (__atomic_load_n(&khx_allocs, __ATOMIC_SEQ_CST));
}

/* ---- locks ------------------------------------------------------------- */
struct khx_holder {
	const void *td;
	int depth;
};
#define KHX_MAX_SHARERS 64
struct khx_lock {
	const void *key;
	char name[64];
	int recursable, sleepable;
	const void *xowner;
	unsigned long xpthread;
	int xdepth;
	struct khx_holder sharers[KHX_MAX_SHARERS];
	unsigned long sharer_pthread[KHX_MAX_SHARERS];
	int nsharers;
	pthread_cond_t cv;
	struct khx_lock *next;
};
#define KHX_LBUCKETS 1024
static struct khx_lock *khx_locks[KHX_LBUCKETS];

static unsigned
khx_hash(const void *key)
{
	uintptr_t v = (uintptr_t)key;

	v ^= v >> 17;
	v *= 0xed5ad4bbU;
	v ^= v >> 11;
	return ((unsigned)v & (KHX_LBUCKETS - 1));
}

static struct khx_lock *
khx_lock_find(const void *key)
{
	struct khx_lock *l;

	for (l = khx_locks[khx_hash(key)]; l != NULL; l = l->next)
		if (l->key == key)
			return (l);
	return (NULL);
}

void
khx_host_lock_init(const void *key, const char *name, int recursable,
    int sleepable)
{
	struct khx_lock *l, **pp;

	pthread_mutex_lock(&khx_big);
	for (pp = &khx_locks[khx_hash(key)]; *pp != NULL; pp = &(*pp)->next) {
		if ((*pp)->key == key) {
			l = *pp;
			if (l->xowner != NULL || l->nsharers != 0) {
				pthread_mutex_unlock(&khx_big);
				khx_host_panic("re-initializing a held lock");
			}
			*pp = l->next;
			pthread_cond_destroy(&l->cv);
			free(l);
			break;
		}
	}
	l = calloc(1, sizeof(*l));
	l->key = key;
	snprintf(l->name, sizeof(l->name), "%s", name ? name : "?");
	l->recursable = recursable;
	l->sleepable = sleepable;
	pthread_cond_init(&l->cv, NULL);
	l->next = khx_locks[khx_hash(key)];
	khx_locks[khx_hash(key)] = l;
	pthread_mutex_unlock(&khx_big);
}

void
khx_host_lock_destroy(const void *key)
{
	struct khx_lock *l, **pp;

	pthread_mutex_lock(&khx_big);
	for (pp = &khx_locks[khx_hash(key)]; *pp != NULL; pp = &(*pp)->next) {
		if ((*pp)->key == key) {
			l = *pp;
			if (l->xowner != NULL || l->nsharers != 0) {
				pthread_mutex_unlock(&khx_big);
				khx_host_panic("destroying a held lock");
			}
			*pp = l->next;
			pthread_cond_destroy(&l->cv);
			free(l);
			pthread_mutex_unlock(&khx_big);
			return;
		}
	}
	pthread_mutex_unlock(&khx_big);
	khx_host_panic("destroying an uninitialized lock");
}

int
khx_host_lock_exists(const void *key)
{
	int r;

	pthread_mutex_lock(&khx_big);
	r = khx_lock_find(key) != NULL;
	pthread_mutex_unlock(&khx_big);
	return (r);
}

static int
khx_sharer_index(struct khx_lock *l, const void *td)
{
	for (int i = 0; i < l->nsharers; i++)
		if (l->sharers[i].td == td)
			return (i);
	return (-1);
}

void
khx_host_lock_acquire(const void *key, const void *td, int mode, int trylock,
    int *acquired, const char *file, int line)
{
	struct khx_lock *l;
	unsigned long self = (unsigned long)pthread_self();
	char msg[256];

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	if (l == NULL) {
		pthread_mutex_unlock(&khx_big);
		snprintf(msg, sizeof(msg), "acquire of uninitialized lock %p at %s:%d",
		    key, file ? file : "?", line);
		khx_host_panic(msg);
	}
	for (;;) {
		if (mode == KHX_LOCK_EXCL) {
			if (l->xowner == td) {
				if (!l->recursable && !trylock) {
					pthread_mutex_unlock(&khx_big);
					snprintf(msg, sizeof(msg),
					    "recursion on non-recursive lock %s at %s:%d",
					    l->name, file ? file : "?", line);
					khx_host_panic(msg);
				}
				if (!l->recursable)
					break;	/* trylock fails */
				l->xdepth++;
				if (acquired)
					*acquired = 1;
				pthread_mutex_unlock(&khx_big);
				return;
			}
			if (khx_sharer_index(l, td) >= 0 && !trylock) {
				pthread_mutex_unlock(&khx_big);
				snprintf(msg, sizeof(msg),
				    "exclusive acquire while shared-held: %s at %s:%d",
				    l->name, file ? file : "?", line);
				khx_host_panic(msg);
			}
			if (l->xowner == NULL && l->nsharers == 0) {
				l->xowner = td;
				l->xpthread = self;
				l->xdepth = 1;
				if (acquired)
					*acquired = 1;
				pthread_mutex_unlock(&khx_big);
				return;
			}
		} else {
			if (l->xowner == td && !trylock) {
				pthread_mutex_unlock(&khx_big);
				snprintf(msg, sizeof(msg),
				    "shared acquire while exclusively held: %s",
				    l->name);
				khx_host_panic(msg);
			}
			if (l->xowner == NULL) {
				int i = khx_sharer_index(l, td);
				if (i >= 0)
					l->sharers[i].depth++;
				else {
					if (l->nsharers == KHX_MAX_SHARERS) {
						pthread_mutex_unlock(&khx_big);
						khx_host_panic("too many sharers");
					}
					l->sharers[l->nsharers].td = td;
					l->sharers[l->nsharers].depth = 1;
					l->sharer_pthread[l->nsharers] = self;
					l->nsharers++;
				}
				if (acquired)
					*acquired = 1;
				pthread_mutex_unlock(&khx_big);
				return;
			}
		}
		if (trylock)
			break;
		/* A holder on this same pthread is a different cooperative kernel
		 * thread: blocking would deadlock the harness, as it would deadlock
		 * the kernel if that holder were waiting on us. */
		if ((l->xowner != NULL && l->xpthread == self) ||
		    (l->xowner == NULL && l->nsharers > 0 &&
		    l->sharer_pthread[0] == self && l->nsharers == 1)) {
			pthread_mutex_unlock(&khx_big);
			snprintf(msg, sizeof(msg),
			    "cooperative deadlock on %s at %s:%d", l->name,
			    file ? file : "?", line);
			khx_host_panic(msg);
		}
		pthread_cond_wait(&l->cv, &khx_big);
	}
	if (acquired)
		*acquired = 0;
	pthread_mutex_unlock(&khx_big);
}

int
khx_host_lock_release(const void *key, const void *td, int mode)
{
	struct khx_lock *l;
	int depth = 0, i;
	char msg[160];

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	if (l == NULL) {
		pthread_mutex_unlock(&khx_big);
		khx_host_panic("release of uninitialized lock");
	}
	if (mode == KHX_LOCK_EXCL) {
		if (l->xowner != td) {
			pthread_mutex_unlock(&khx_big);
			snprintf(msg, sizeof(msg), "release of unowned lock %s",
			    l->name);
			khx_host_panic(msg);
		}
		depth = --l->xdepth;
		if (depth == 0) {
			l->xowner = NULL;
			l->xpthread = 0;
		}
	} else {
		i = khx_sharer_index(l, td);
		if (i < 0) {
			pthread_mutex_unlock(&khx_big);
			snprintf(msg, sizeof(msg),
			    "shared release by non-sharer %s", l->name);
			khx_host_panic(msg);
		}
		depth = --l->sharers[i].depth;
		if (depth == 0) {
			l->nsharers--;
			l->sharers[i] = l->sharers[l->nsharers];
			l->sharer_pthread[i] = l->sharer_pthread[l->nsharers];
		}
	}
	pthread_cond_broadcast(&l->cv);
	pthread_mutex_unlock(&khx_big);
	return (depth);
}

int
khx_host_lock_held(const void *key, const void *td, int mode)
{
	struct khx_lock *l;
	int r = 0;

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	if (l != NULL) {
		if (mode == KHX_LOCK_EXCL)
			r = l->xowner == td;
		else if (mode == KHX_LOCK_SHARED)
			r = khx_sharer_index(l, td) >= 0;
		else
			r = l->xowner == td || khx_sharer_index(l, td) >= 0;
	}
	pthread_mutex_unlock(&khx_big);
	return (r);
}

int
khx_host_lock_sharers(const void *key)
{
	struct khx_lock *l;
	int r = 0;

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	if (l != NULL)
		r = l->nsharers;
	pthread_mutex_unlock(&khx_big);
	return (r);
}

const char *
khx_host_lock_name(const void *key)
{
	struct khx_lock *l;

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	pthread_mutex_unlock(&khx_big);
	return (l ? l->name : "<none>");
}

int
khx_host_lock_sleep_drop(const void *key, const void *td, int *mode,
    int *depth)
{
	struct khx_lock *l;
	int i;

	pthread_mutex_lock(&khx_big);
	l = khx_lock_find(key);
	if (l == NULL) {
		pthread_mutex_unlock(&khx_big);
		khx_host_panic("sleep on uninitialized lock");
	}
	if (l->xowner == td) {
		*mode = KHX_LOCK_EXCL;
		*depth = l->xdepth;
		l->xowner = NULL;
		l->xpthread = 0;
		l->xdepth = 0;
	} else if ((i = khx_sharer_index(l, td)) >= 0) {
		*mode = KHX_LOCK_SHARED;
		*depth = l->sharers[i].depth;
		l->nsharers--;
		l->sharers[i] = l->sharers[l->nsharers];
		l->sharer_pthread[i] = l->sharer_pthread[l->nsharers];
	} else {
		pthread_mutex_unlock(&khx_big);
		khx_host_panic("sleep with interlock not held");
	}
	pthread_cond_broadcast(&l->cv);
	pthread_mutex_unlock(&khx_big);
	return (0);
}

void
khx_host_lock_sleep_reacquire(const void *key, const void *td, int mode,
    int depth)
{
	int acquired;

	khx_host_lock_acquire(key, td, mode, 0, &acquired, __FILE__, __LINE__);
	if (depth > 1) {
		struct khx_lock *l;

		pthread_mutex_lock(&khx_big);
		l = khx_lock_find(key);
		if (mode == KHX_LOCK_EXCL)
			l->xdepth = depth;
		else
			l->sharers[khx_sharer_index(l, td)].depth = depth;
		pthread_mutex_unlock(&khx_big);
	}
}

int
khx_host_lock_force_release_all(const void *td, const void **keys, int max)
{
	int n = 0, i;

	pthread_mutex_lock(&khx_big);
	for (int b = 0; b < KHX_LBUCKETS; b++) {
		for (struct khx_lock *l = khx_locks[b]; l; l = l->next) {
			int hit = 0;
			if (l->xowner == td) {
				l->xowner = NULL;
				l->xpthread = 0;
				l->xdepth = 0;
				hit = 1;
			}
			if ((i = khx_sharer_index(l, td)) >= 0) {
				l->nsharers--;
				l->sharers[i] = l->sharers[l->nsharers];
				l->sharer_pthread[i] = l->sharer_pthread[l->nsharers];
				hit = 1;
			}
			if (hit) {
				if (n < max)
					keys[n] = l->key;
				n++;
				pthread_cond_broadcast(&l->cv);
			}
		}
	}
	pthread_mutex_unlock(&khx_big);
	return (n);
}

int
khx_host_locks_held_by(const void *td)
{
	int n = 0;

	pthread_mutex_lock(&khx_big);
	for (int b = 0; b < KHX_LBUCKETS; b++)
		for (struct khx_lock *l = khx_locks[b]; l; l = l->next)
			if (l->xowner == td || khx_sharer_index(l, td) >= 0)
				n++;
	pthread_mutex_unlock(&khx_big);
	return (n);
}

/* ---- sleep/wakeup ------------------------------------------------------ */
static khx_sleep_hook_t khx_hook;
static void *khx_hook_arg;
struct khx_chan {
	const void *wchan;
	long gen, wakeups;
	pthread_cond_t cv;
	struct khx_chan *next;
};
static struct khx_chan *khx_chans[KHX_LBUCKETS];
static int khx_sleepers;

static struct khx_chan *
khx_chan_get(const void *wchan)
{
	struct khx_chan *c;

	for (c = khx_chans[khx_hash(wchan)]; c != NULL; c = c->next)
		if (c->wchan == wchan)
			return (c);
	c = calloc(1, sizeof(*c));
	c->wchan = wchan;
	pthread_cond_init(&c->cv, NULL);
	c->next = khx_chans[khx_hash(wchan)];
	khx_chans[khx_hash(wchan)] = c;
	return (c);
}

void
khx_host_set_sleep_hook(khx_sleep_hook_t hook, void *arg)
{
	khx_hook = hook;
	khx_hook_arg = arg;
}

int
khx_host_has_sleep_hook(void)
{
	return (khx_hook != NULL);
}

int
khx_host_sleep(const void *wchan, const char *wmesg, int timo,
    int catch_signals)
{
	struct khx_chan *c;
	struct timespec ts;
	long gen;
	int error = 0;

	if (khx_hook != NULL)
		return (khx_hook(khx_hook_arg, wchan, wmesg, timo, catch_signals));
	pthread_mutex_lock(&khx_big);
	c = khx_chan_get(wchan);
	gen = c->gen;
	if (timo > 0) {
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += (long)(timo % 1000) * 1000000L;
		ts.tv_sec += timo / 1000 + ts.tv_nsec / 1000000000L;
		ts.tv_nsec %= 1000000000L;
	}
	khx_sleepers++;
	while (c->gen == gen && error == 0) {
		if (timo > 0) {
			if (pthread_cond_timedwait(&c->cv, &khx_big, &ts) ==
			    ETIMEDOUT)
				error = EWOULDBLOCK;
		} else
			pthread_cond_wait(&c->cv, &khx_big);
	}
	khx_sleepers--;
	pthread_mutex_unlock(&khx_big);
	return (error);
}

int
khx_host_sleepers(void)
{
	int n;

	pthread_mutex_lock(&khx_big);
	n = khx_sleepers;
	pthread_mutex_unlock(&khx_big);
	return (n);
}

void
khx_host_wakeup(const void *wchan, int all)
{
	struct khx_chan *c;

	pthread_mutex_lock(&khx_big);
	c = khx_chan_get(wchan);
	c->gen++;
	c->wakeups++;
	if (all)
		pthread_cond_broadcast(&c->cv);
	else
		pthread_cond_broadcast(&c->cv);	/* spurious wakeups are legal */
	pthread_mutex_unlock(&khx_big);
}

long
khx_host_wakeups(const void *wchan)
{
	long n;

	pthread_mutex_lock(&khx_big);
	n = khx_chan_get(wchan)->wakeups;
	pthread_mutex_unlock(&khx_big);
	return (n);
}

/* ---- threads ----------------------------------------------------------- */
void
khx_host_set_gsbase(void *base)
{
	if (amd64_set_gsbase(base) != 0)
		khx_host_panic("amd64_set_gsbase failed");
}

void *
khx_host_get_gsbase(void)
{
	void *base = NULL;

	if (amd64_get_gsbase(&base) != 0)
		khx_host_panic("amd64_get_gsbase failed");
	return (base);
}

#include <pthread_np.h>
void
khx_host_stack_bounds(void **lo, khx_size_t *size)
{
	pthread_attr_t attr;
	size_t sz;

	pthread_attr_init(&attr);
	if (pthread_attr_get_np(pthread_self(), &attr) != 0 ||
	    pthread_attr_getstack(&attr, lo, &sz) != 0)
		khx_host_panic("cannot read thread stack bounds");
	*size = sz;
	pthread_attr_destroy(&attr);
}

unsigned long
khx_host_pthread_self(void)
{
	return ((unsigned long)pthread_self());
}

struct khx_start {
	void (*fn)(void *);
	void *arg;
};

static void *
khx_thread_main(void *p)
{
	struct khx_start s = *(struct khx_start *)p;

	free(p);
	s.fn(s.arg);
	return (NULL);
}

void *
khx_host_thread_start(void (*fn)(void *), void *arg)
{
	pthread_t *t = malloc(sizeof(*t));
	struct khx_start *s = malloc(sizeof(*s));

	s->fn = fn;
	s->arg = arg;
	if (pthread_create(t, NULL, khx_thread_main, s) != 0)
		khx_host_panic("pthread_create");
	return (t);
}

void
khx_host_thread_join(void *handle)
{
	pthread_t *t = handle;

	pthread_join(*t, NULL);
	free(t);
}

void
khx_host_thread_exit(void)
{
	pthread_exit(NULL);
}

void
khx_host_yield(void)
{
	sched_yield();
}

unsigned long
khx_host_monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((unsigned long)ts.tv_sec * 1000000000UL +
	    (unsigned long)ts.tv_nsec);
}

void
khx_host_random(void *buf, khx_size_t len)
{
	arc4random_buf(buf, len);
}

/* ---- user memory ------------------------------------------------------- */
static const char *khx_fault_start;
static size_t khx_fault_len;
static long khx_copy_fail_nth = -1;

void
khx_host_user_fault_range(const void *start, khx_size_t len)
{
	khx_fault_start = start;
	khx_fault_len = len;
}

void
khx_host_user_fault_clear(void)
{
	khx_fault_start = NULL;
	khx_fault_len = 0;
}

int
khx_host_user_faults(const void *addr, khx_size_t len)
{
	const char *a = addr;

	if (addr == NULL && len != 0)
		return (1);
	if (khx_fault_start == NULL || len == 0)
		return (0);
	return (a < khx_fault_start + khx_fault_len &&
	    khx_fault_start < a + len);
}

void
khx_host_fail_copy(long nth)
{
	khx_copy_fail_nth = nth;
}

int
khx_host_copy_should_fail(void)
{
	if (khx_copy_fail_nth > 0 && --khx_copy_fail_nth == 0) {
		khx_copy_fail_nth = -1;
		return (1);
	}
	return (0);
}

/* ---- bookkeeping ------------------------------------------------------- */
static long khx_checks, khx_failures;
static const char *khx_case_name = "";

void
khx_host_case(const char *name)
{
	khx_case_name = name;
}

void
khx_host_check(int ok, const char *expr, const char *file, int line)
{
	__atomic_add_fetch(&khx_checks, 1, __ATOMIC_SEQ_CST);
	if (!ok) {
		__atomic_add_fetch(&khx_failures, 1, __ATOMIC_SEQ_CST);
		fprintf(stderr, "FAIL [%s] %s:%d: %s\n", khx_case_name, file,
		    line, expr);
	}
}

long
khx_host_checks(void)
{
	return (khx_checks);
}

long
khx_host_failures(void)
{
	return (khx_failures);
}

int
khx_host_finish(const char *suite)
{
	printf("%s: %ld checks, %ld failures, %ld live allocations, "
	    "%ld expected panics\n", suite, khx_checks, khx_failures,
	    khx_live, khx_panic_count);
	return (khx_failures == 0 ? 0 : 1);
}

/* ---- entry point ------------------------------------------------------- */
extern int khx_test_main(void);

int
main(void)
{
	setvbuf(stdout, NULL, _IOLBF, 0);
	return (khx_test_main());
}

/* ---- host semaphores (independent of the sleep hook) ------------------- */
struct khx_sem {
	pthread_mutex_t m;
	pthread_cond_t c;
	int v;
};

void *
khx_host_sem_new(int value)
{
	struct khx_sem *s = calloc(1, sizeof(*s));

	pthread_mutex_init(&s->m, NULL);
	pthread_cond_init(&s->c, NULL);
	s->v = value;
	return (s);
}

void
khx_host_sem_post(void *p)
{
	struct khx_sem *s = p;

	pthread_mutex_lock(&s->m);
	s->v++;
	pthread_cond_broadcast(&s->c);
	pthread_mutex_unlock(&s->m);
}

void
khx_host_sem_wait(void *p)
{
	struct khx_sem *s = p;

	pthread_mutex_lock(&s->m);
	while (s->v == 0)
		pthread_cond_wait(&s->c, &s->m);
	s->v--;
	pthread_mutex_unlock(&s->m);
}

/* ---- files ------------------------------------------------------------- */
void *
khx_host_read_file(const char *dirvar, const char *name, khx_size_t *len)
{
	const char *dir = getenv(dirvar);
	char path[1024];
	FILE *f;
	long n;
	void *buf;

	if (dir == NULL)
		khx_host_panic("file directory variable not set");
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	if ((f = fopen(path, "r")) == NULL) {
		fprintf(stderr, "cannot open %s\n", path);
		khx_host_panic("missing input file");
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = khx_host_alloc((size_t)n, 0, 0, "khx-file");
	if (fread(buf, 1, (size_t)n, f) != (size_t)n)
		khx_host_panic("short read");
	fclose(f);
	*len = (size_t)n;
	return (buf);
}
