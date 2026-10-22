/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#define ASSERT(v) assert(v)
#define MUTEX_HELD(v) ((void)(v), 1)
#define KM_SLEEP 0
#define DTRACE_MATCH_NEXT 0
#define DTRACE_MATCH_DONE 1

typedef uint16_t dtrace_vmid_t;
typedef struct dtrace_probe dtrace_probe_t;
typedef struct dtrace_ecb dtrace_ecb_t;
typedef struct dtrace_state dtrace_state_t;
typedef struct dtrace_vstate dtrace_vstate_t;
typedef struct dtrace_enabling dtrace_enabling_t;

struct dtrace_probe {
	dtrace_vmid_t dtpr_vmid;
	unsigned int dtpr_gen;
	unsigned int dtpr_id;
};
struct dtrace_ecb {
	dtrace_probe_t *probe;
};
struct dtrace_state {
	int dummy;
};
struct dtrace_vstate {
	dtrace_state_t *dtvs_state;
};
struct dtrace_enabling {
	dtrace_vstate_t *dten_vstate;
	unsigned int dten_probegen;
	int dten_error;
	dtrace_vmid_t dten_vmid;
	dtrace_probe_t **dten_probelist;
	unsigned int dten_probelistsize;
};

static int dtrace_lock, created, enabled, destroyed, enable_result;
static unsigned int dtrace_nvprobes[8] = { [1] = 4, [2] = 4 };
static dtrace_ecb_t new_ecbs[4];
static dtrace_ecb_t *dtrace_ecb_create_cache;

static void *
kmem_zalloc(size_t size, int flags)
{
	(void)flags;
	return (calloc(1, size));
}

static dtrace_ecb_t *
dtrace_ecb_create(dtrace_state_t *state, dtrace_probe_t *probe,
    dtrace_enabling_t *enab)
{
	assert(state != NULL && enab != NULL && created < 4);
	new_ecbs[created].probe = probe;
	dtrace_ecb_create_cache = &new_ecbs[created];
	return (&new_ecbs[created++]);
}

static int
dtrace_ecb_enable(dtrace_ecb_t *ecb)
{
	assert(ecb != NULL);
	enabled++;
	return (enable_result);
}

static void
dtrace_ecb_destroy(dtrace_ecb_t *ecb)
{
	assert(ecb != NULL);
	destroyed++;
}

/* PRODUCTION_MATCH */

int
main(void)
{
	dtrace_state_t state = { 0 };
	dtrace_vstate_t vstate = { .dtvs_state = &state };
	dtrace_enabling_t enabling = { .dten_vstate = &vstate };
	dtrace_probe_t first = { .dtpr_vmid = 1, .dtpr_id = 1 };
	dtrace_probe_t foreign = { .dtpr_vmid = 2, .dtpr_id = 1 };

	assert(dtrace_ecb_create_enable(&first, &enabling) == DTRACE_MATCH_NEXT);
	assert(enabling.dten_vmid == 1 && enabling.dten_probelist[0] == &first);
	assert(created == 1 && enabled == 1 && destroyed == 0);
	assert(dtrace_ecb_create_enable(&foreign, &enabling) == DTRACE_MATCH_DONE);
	assert(enabling.dten_error == EXDEV);
	assert(created == 1 && enabled == 1 && destroyed == 0);
	free(enabling.dten_probelist);
	return (0);
}
