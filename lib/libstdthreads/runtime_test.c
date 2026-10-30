/* SPDX-License-Identifier: BSD-2-Clause */
#include <sys/types.h>
#include <assert.h>
#include <stdatomic.h>
#include <threads.h>

static once_flag once = ONCE_FLAG_INIT;
static mtx_t mutex;
static tss_t key;
static int counter;
static atomic_int initialized, destroyed;
static int token;

static void
initialize(void)
{
	atomic_fetch_add(&initialized, 1);
}

static void
destroy(void *value)
{
	assert(value == &token);
	atomic_fetch_add(&destroyed, 1);
}

static int
worker(void *arg)
{
	(void)arg;
	call_once(&once, initialize);
	assert(tss_get(key) == NULL);
	assert(tss_set(key, &token) == thrd_success);
	assert(tss_get(key) == &token);
	assert(thrd_equal(thrd_current(), thrd_current()));
	for (int i = 0; i < 100; i++) {
		assert(mtx_lock(&mutex) == thrd_success);
		counter++;
		assert(mtx_unlock(&mutex) == thrd_success);
	}
	return (17);
}

int
main(void)
{
	thrd_t threads[4];
	int result;

	assert(mtx_init(&mutex, mtx_plain) == thrd_success);
	assert(tss_create(&key, destroy) == thrd_success);
	for (int i = 0; i < 4; i++)
		assert(thrd_create(&threads[i], worker, NULL) == thrd_success);
	for (int i = 0; i < 4; i++) {
		assert(thrd_join(threads[i], &result) == thrd_success);
		assert(result == 17);
	}
	assert(counter == 400);
	assert(atomic_load(&initialized) == 1);
	assert(atomic_load(&destroyed) == 4);
	assert(tss_get(key) == NULL);
	tss_delete(key);
	mtx_destroy(&mutex);
	return (0);
}
