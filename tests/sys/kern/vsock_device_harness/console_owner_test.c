/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

#include <atf-c.h>

#include "bhyvegc.h"
#include "console.h"

struct bhyvegc {
	struct bhyvegc_image image;
};

static struct bhyvegc test_gc;
static unsigned int first_calls;
static unsigned int second_calls;
static unsigned int low_ptr_calls;
static unsigned int high_ptr_calls;

struct bhyvegc *
bhyvegc_init(int width, int height, void *fbaddr)
{

	test_gc.image.width = width;
	test_gc.image.height = height;
	test_gc.image.data = fbaddr;
	return (&test_gc);
}

void
bhyvegc_set_fbaddr(struct bhyvegc *gc, void *fbaddr)
{

	gc->image.data = fbaddr;
}

struct bhyvegc_image *
bhyvegc_get_image(struct bhyvegc *gc)
{

	return (gc == NULL ? NULL : &gc->image);
}

static void
first_renderer(struct bhyvegc *gc, void *arg)
{

	ATF_CHECK_EQ(gc, &test_gc);
	ATF_CHECK_EQ(arg, &first_calls);
	first_calls++;
}

static void
second_renderer(struct bhyvegc *gc, void *arg)
{

	ATF_CHECK_EQ(gc, &test_gc);
	ATF_CHECK_EQ(arg, &second_calls);
	second_calls++;
}

static void
low_pointer(uint8_t button, int x, int y, void *arg)
{

	ATF_CHECK_EQ(button, 1);
	ATF_CHECK_EQ(x, 2);
	ATF_CHECK_EQ(y, 3);
	ATF_CHECK_EQ(arg, &low_ptr_calls);
	low_ptr_calls++;
}

static void
high_pointer(uint8_t button, int x, int y, void *arg)
{

	ATF_CHECK_EQ(button, 1);
	ATF_CHECK_EQ(x, 2);
	ATF_CHECK_EQ(y, 3);
	ATF_CHECK_EQ(arg, &high_ptr_calls);
	high_ptr_calls++;
}

#include "console_owner.c"

struct blocking_renderer_state {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	bool entered;
	bool release;
};

static void
blocking_renderer(struct bhyvegc *gc, void *arg)
{
	struct blocking_renderer_state *state;

	ATF_CHECK_EQ(gc, &test_gc);
	state = arg;
	pthread_mutex_lock(&state->mutex);
	state->entered = true;
	pthread_cond_broadcast(&state->cond);
	while (!state->release)
		pthread_cond_wait(&state->cond, &state->mutex);
	pthread_mutex_unlock(&state->mutex);
}

static void *
refresh_thread(void *arg __unused)
{

	console_refresh();
	return (NULL);
}

ATF_TC_WITHOUT_HEAD(framebuffer_owner_is_exclusive);
ATF_TC_BODY(framebuffer_owner_is_exclusive, tc)
{

	console_init(640, 480, NULL);
	ATF_CHECK_EQ(console_fb_register(NULL, first_renderer, &first_calls),
	    EINVAL);
	ATF_CHECK_EQ(console_fb_register("", first_renderer, &first_calls),
	    EINVAL);
	ATF_CHECK_EQ(console_fb_register("first", NULL, &first_calls), EINVAL);
	ATF_REQUIRE_EQ(console_fb_register("first", first_renderer,
	    &first_calls), 0);
	ATF_CHECK_EQ(console_fb_register("first", first_renderer,
	    &first_calls), 0);
	ATF_CHECK_EQ(console_fb_register("second", second_renderer,
	    &second_calls), EBUSY);
	ATF_CHECK_EQ(console_fb_register("first", second_renderer,
	    &first_calls), EBUSY);
	console_refresh();
	ATF_CHECK_EQ(first_calls, 1);
	ATF_CHECK_EQ(second_calls, 0);

	ATF_CHECK_EQ(console_fb_unregister(NULL, &first_calls), EINVAL);
	ATF_CHECK_EQ(console_fb_unregister("", &first_calls), EINVAL);
	ATF_CHECK_EQ(console_fb_unregister("second", &first_calls), EPERM);
	ATF_CHECK_EQ(console_fb_unregister("first", &second_calls), EPERM);
	console_refresh();
	ATF_CHECK_EQ(first_calls, 2);
	ATF_REQUIRE_EQ(console_fb_unregister("first", &first_calls), 0);
	ATF_CHECK_EQ(console_fb_unregister("first", &first_calls), ENOENT);

	ATF_REQUIRE_EQ(console_fb_register("second", second_renderer,
	    &second_calls), 0);
	console_refresh();
	ATF_CHECK_EQ(first_calls, 2);
	ATF_CHECK_EQ(second_calls, 1);
	ATF_REQUIRE_EQ(console_fb_unregister("second", &second_calls), 0);
}

ATF_TC_WITHOUT_HEAD(pointer_unregister_restores_fallback);
ATF_TC_BODY(pointer_unregister_restores_fallback, tc)
{

	console_ptr_register(low_pointer, &low_ptr_calls, 1);
	console_ptr_event(1, 2, 3);
	ATF_CHECK_EQ(low_ptr_calls, 1);
	ATF_CHECK_EQ(high_ptr_calls, 0);

	console_ptr_register(high_pointer, &high_ptr_calls, 10);
	console_ptr_register(high_pointer, &high_ptr_calls, 10);
	console_ptr_event(1, 2, 3);
	ATF_CHECK_EQ(low_ptr_calls, 1);
	ATF_CHECK_EQ(high_ptr_calls, 1);
	ATF_CHECK_EQ(console_ptr_unregister(low_pointer, &high_ptr_calls),
	    EPERM);
	ATF_REQUIRE_EQ(console_ptr_unregister(high_pointer, &high_ptr_calls),
	    0);

	console_ptr_event(1, 2, 3);
	ATF_CHECK_EQ(low_ptr_calls, 2);
	ATF_CHECK_EQ(high_ptr_calls, 1);
	ATF_REQUIRE_EQ(console_ptr_unregister(low_pointer, &low_ptr_calls), 0);
	ATF_CHECK_EQ(console_ptr_unregister(low_pointer, &low_ptr_calls),
	    ENOENT);
	console_ptr_event(1, 2, 3);
	ATF_CHECK_EQ(low_ptr_calls, 2);
	ATF_CHECK_EQ(high_ptr_calls, 1);
}

ATF_TC_WITHOUT_HEAD(refresh_excludes_input_callbacks);
ATF_TC_BODY(refresh_excludes_input_callbacks, tc)
{
	struct blocking_renderer_state state;
	pthread_t thread;
	int error;

	memset(&state, 0, sizeof(state));
	ATF_REQUIRE_EQ(pthread_mutex_init(&state.mutex, NULL), 0);
	ATF_REQUIRE_EQ(pthread_cond_init(&state.cond, NULL), 0);
	console_init(640, 480, NULL);
	ATF_REQUIRE_EQ(console_fb_register("lock-observer",
	    blocking_renderer, &state), 0);
	ATF_REQUIRE_EQ(pthread_create(&thread, NULL, refresh_thread, NULL), 0);
	pthread_mutex_lock(&state.mutex);
	while (!state.entered)
		pthread_cond_wait(&state.cond, &state.mutex);
	pthread_mutex_unlock(&state.mutex);

	/* A different input thread cannot acquire a shared callback lease. */
	error = pthread_rwlock_tryrdlock(&console_lock);
	ATF_CHECK_EQ(error, EBUSY);
	if (error == 0)
		pthread_rwlock_unlock(&console_lock);

	pthread_mutex_lock(&state.mutex);
	state.release = true;
	pthread_cond_broadcast(&state.cond);
	pthread_mutex_unlock(&state.mutex);
	ATF_REQUIRE_EQ(pthread_join(thread, NULL), 0);
	ATF_REQUIRE_EQ(console_fb_unregister("lock-observer", &state), 0);
	pthread_cond_destroy(&state.cond);
	pthread_mutex_destroy(&state.mutex);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, framebuffer_owner_is_exclusive);
	ATF_TP_ADD_TC(tp, pointer_unregister_restores_fallback);
	ATF_TP_ADD_TC(tp, refresh_excludes_input_callbacks);
	return (atf_no_error());
}
