/* Built with the current kernel dtrace_enabling_rollback() body. */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define ASSERT(condition) assert(condition)
#define ASSERT3U(left, op, right) assert((left) op (right))
#define MUTEX_HELD(lock) (*(lock) == 1)

typedef uint32_t dtrace_epid_t;
typedef struct dtrace_ecb {
	dtrace_epid_t id;
	int disabled;
} dtrace_ecb_t;
typedef struct {
	dtrace_ecb_t **dts_ecbs;
	dtrace_epid_t dts_epid;
	int dts_necbs;
} dtrace_state_t;

static int cpu_lock = 1, dtrace_lock = 1;
static int disable_count, destroy_count;
static dtrace_state_t *active_state;
static dtrace_ecb_t *dtrace_ecb_create_cache;

static void
dtrace_ecb_disable(dtrace_ecb_t *ecb)
{
	assert(ecb != NULL && ecb->disabled == 0);
	ecb->disabled = 1;
	disable_count++;
}

static void
dtrace_ecb_destroy(dtrace_ecb_t *ecb)
{
	assert(ecb != NULL && ecb->disabled == 1);
	assert(active_state->dts_ecbs[ecb->id - 1] == ecb);
	active_state->dts_ecbs[ecb->id - 1] = NULL;
	destroy_count++;
}

#include "enable-rollback-impl.inc"

int
main(void)
{
	dtrace_ecb_t existing1 = { .id = 1 }, existing2 = { .id = 2 };
	dtrace_ecb_t new3 = { .id = 3 }, new4 = { .id = 4 };
	dtrace_ecb_t new6 = { .id = 6 };
	dtrace_ecb_t *ecbs[8] = {
		&existing1, &existing2, &new3, &new4, NULL, &new6
	};
	dtrace_state_t state = { .dts_ecbs = ecbs, .dts_epid = 7,
	    .dts_necbs = 8 };
	active_state = &state;
	dtrace_ecb_create_cache = &new6;

	dtrace_enabling_rollback(&state, 3, 7);
	assert(ecbs[0] == &existing1 && ecbs[1] == &existing2);
	assert(existing1.disabled == 0 && existing2.disabled == 0);
	assert(ecbs[2] == NULL && ecbs[3] == NULL && ecbs[4] == NULL);
	assert(ecbs[5] == NULL && disable_count == 3 && destroy_count == 3);
	assert(dtrace_ecb_create_cache == NULL);
	dtrace_enabling_rollback(&state, 3, 7);
	assert(disable_count == 3 && destroy_count == 3);
	dtrace_enabling_rollback(&state, 7, 7);
	assert(disable_count == 3 && destroy_count == 3);
	puts("enable rollback: pass");
	return (0);
}
