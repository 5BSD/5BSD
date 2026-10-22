/* Exercises the current DTRACEIOC_ENABLE case and ECB rollback body. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DTRACEIOC_ENABLE 6
#define DTRACE_ACTIVITY_INACTIVE 0
#define DTRACE_IOCTL_PRINTF(...) ((void)0)
#define B_TRUE 1
#define ASSERT(expr) assert(expr)
#define ASSERT3U(a, op, b) assert((a) op (b))
#define MUTEX_HELD(lock) (depth >= *(lock))

typedef uint32_t dtrace_epid_t;
typedef struct { int id; } dtrace_probedesc_t;
typedef struct { int value; } dof_hdr_t;
typedef struct { int value; } dtrace_vstate_t;
typedef struct {
	int retained, destroyed, dten_pending;
	uint16_t dten_origin_vmid;
	uint64_t dten_origin_epoch;
} dtrace_enabling_t;
typedef struct dtrace_ecb { dtrace_epid_t id; int disabled; } dtrace_ecb_t;
typedef struct {
	int dts_activity;
	int dts_enable_pending;
	dtrace_epid_t dts_epid;
	int dts_necbs;
	dtrace_ecb_t **dts_ecbs;
	dtrace_vstate_t dts_vstate;
} dtrace_state_t;
typedef struct { void *td_ucred; } thread_t;
typedef struct {
	void *dof;
	dtrace_probedesc_t *ps;
	int n_matched, n_desc, ps_bufsize;
	uint16_t vmid;
	uint64_t epoch;
} dtrace_enable_io_t;

static int cpu_lock = 1, dtrace_lock = 2, depth;
static uint16_t dtrace_curvmid;
static dof_hdr_t dof;
static dtrace_enabling_t enabling;
static dtrace_ecb_t old_ecb, new_ecbs[2], late_ecb, foreign_ecb;
static dtrace_ecb_t *slots[8];
static dtrace_ecb_t *dtrace_ecb_create_cache;
static int match_error, late_match_error, list_error, retain_error, match_count;
static int match_calls, late_match_count, copyout_error, interleave_foreign;
static int reenter_enable;
static int disabled, destroyed_ecbs, destroyed_dofs, retained, matchall;
static dtrace_state_t *current_state;

static void mutex_enter(int *lock) { assert(*lock == depth + 1); depth++; }
static void mutex_exit(int *lock) { assert(*lock == depth); depth--; }
static int check_epoch(uint16_t vmid, uint64_t epoch)
{ (void)vmid; (void)epoch; return (0); }
static int (*hypertrace_check_epoch)(uint16_t, uint64_t) = check_epoch;
static void dtrace_enabling_matchall(void) { matchall++; }
static dof_hdr_t *dtrace_dof_copyin(uintptr_t addr, int *rval)
{ assert(addr == (uintptr_t)&dof && rval != NULL); return (&dof); }
static void dtrace_dof_destroy(dof_hdr_t *p)
{ assert(p == &dof && depth == 0); destroyed_dofs++; }
static int dtrace_dof_slurp(dof_hdr_t *p, dtrace_vstate_t *v,
    void *cred, dtrace_enabling_t **out, int a, int b, int c)
{
	assert(p == &dof && v != NULL && cred == NULL);
	assert(a == 0 && b == 0 && c == B_TRUE && depth == 2);
	*out = &enabling;
	return (0);
}
static int dtrace_dof_options(dof_hdr_t *p, dtrace_state_t *state)
{ assert(p == &dof && state == current_state); return (0); }
static int dtrace_enabling_match(dtrace_enabling_t *e, int *count)
{
	assert(e == &enabling && depth == 2);
	if (match_calls++ != 0) {
		assert(count == NULL && current_state->dts_enable_pending &&
		    e->dten_pending);
		if (late_match_count != 0) {
			late_ecb.id = current_state->dts_epid++;
			current_state->dts_ecbs[late_ecb.id - 1] = &late_ecb;
		}
		return (late_match_error);
	}
	for (int i = 0; i < match_count; i++) {
		new_ecbs[i].id = current_state->dts_epid++;
		current_state->dts_ecbs[new_ecbs[i].id - 1] = &new_ecbs[i];
	}
	if (match_count > 0)
		dtrace_ecb_create_cache = &new_ecbs[match_count - 1];
	*count = match_count;
	return (match_error);
}
static dtrace_probedesc_t *dtrace_enabling_list(dtrace_enabling_t *e,
    int *count, size_t *size)
{
	dtrace_probedesc_t *probes;
	assert(e == &enabling && depth == 2);
	if (list_error)
		return (NULL);
	*count = match_count;
	*size = (size_t)match_count * sizeof(*probes);
	probes = malloc(*size);
	assert(probes != NULL);
	for (int i = 0; i < match_count; i++)
		probes[i].id = i + 20;
	return (probes);
}
static int dtrace_enabling_retain(dtrace_enabling_t *e)
{
	assert(e == &enabling && depth == 2);
	if (retain_error)
		return (retain_error);
	e->retained = 1;
	retained++;
	return (0);
}
static void dtrace_enabling_destroy(dtrace_enabling_t *e)
{
	assert(e == &enabling && depth == 2 && !e->destroyed);
	e->destroyed = 1;
	if (e->retained)
		retained--;
}
static void dtrace_ecb_disable(dtrace_ecb_t *ecb)
{ assert(depth == 2 && ecb != NULL && !ecb->disabled); ecb->disabled = 1; disabled++; }
static void dtrace_ecb_destroy(dtrace_ecb_t *ecb)
{
	assert(depth == 2 && ecb->disabled);
	assert(current_state->dts_ecbs[ecb->id - 1] == ecb);
	current_state->dts_ecbs[ecb->id - 1] = NULL;
	destroyed_ecbs++;
}
static int dispatch(void *, dtrace_state_t *, thread_t *);
static int copyout(const void *from, void *to, size_t size)
{
	assert(depth == 0 && current_state->dts_enable_pending &&
	    enabling.dten_pending && retained == 1);
	if (reenter_enable) {
		thread_t td = { 0 };
		dtrace_enable_io_t concurrent = { .dof = &dof };
		assert(dispatch(&concurrent, current_state, &td) == EBUSY &&
		    concurrent.n_matched == 0 && concurrent.n_desc == 0);
	}
	if (interleave_foreign) {
		foreign_ecb.id = current_state->dts_epid++;
		current_state->dts_ecbs[foreign_ecb.id - 1] = &foreign_ecb;
	}
	if (copyout_error != 0)
		return (copyout_error);
	memcpy(to, from, size);
	return (0);
}
static void kmem_free(void *ptr, size_t size)
{ assert(size == (size_t)match_count * sizeof(dtrace_probedesc_t)); free(ptr); }

#include "enable-rollback-impl.inc"
#include "enable-ioctl-impl.inc"

static void
reset(dtrace_state_t *state)
{
	memset(slots, 0, sizeof(slots));
	memset(new_ecbs, 0, sizeof(new_ecbs));
	memset(&late_ecb, 0, sizeof(late_ecb));
	memset(&foreign_ecb, 0, sizeof(foreign_ecb));
	memset(&enabling, 0, sizeof(enabling));
	old_ecb.id = 1;
	old_ecb.disabled = 0;
	slots[0] = &old_ecb;
	state->dts_activity = DTRACE_ACTIVITY_INACTIVE;
	state->dts_enable_pending = 0;
	state->dts_epid = 2;
	state->dts_necbs = 8;
	state->dts_ecbs = slots;
	current_state = state;
	match_error = list_error = retain_error = 0;
	late_match_error = late_match_count = copyout_error = match_calls =
	    interleave_foreign = reenter_enable = 0;
	match_count = 2;
	disabled = destroyed_ecbs = destroyed_dofs = retained = 0;
	dtrace_ecb_create_cache = NULL;
	assert(depth == 0);
}

int
main(void)
{
	dtrace_state_t state = { 0 };
	thread_t td = { 0 };
	dtrace_probedesc_t output[2] = { 0 };
	dtrace_enable_io_t p = { .dof = &dof, .ps = output,
	    .ps_bufsize = sizeof(output) };

	reset(&state);
	p.ps_bufsize = sizeof(output[0]);
	assert(dispatch(&p, &state, &td) == E2BIG);
	assert(disabled == 2 && destroyed_ecbs == 2 && retained == 0);
	assert(enabling.destroyed && slots[0] == &old_ecb && !old_ecb.disabled);
	assert(p.n_matched == 0 && p.n_desc == 0 && destroyed_dofs == 1);
	assert(dtrace_ecb_create_cache == NULL);

	reset(&state);
	p.ps_bufsize = sizeof(output);
	match_error = EINVAL;
	assert(dispatch(&p, &state, &td) == EINVAL);
	assert(disabled == 2 && destroyed_ecbs == 2 && enabling.destroyed);

	reset(&state);
	list_error = 1;
	assert(dispatch(&p, &state, &td) == ENOMEM);
	assert(disabled == 2 && destroyed_ecbs == 2 && enabling.destroyed);

	reset(&state);
	retain_error = ENOSPC;
	assert(dispatch(&p, &state, &td) == ENOSPC);
	assert(disabled == 2 && destroyed_ecbs == 2 && enabling.destroyed);

	reset(&state);
	assert(dispatch(&p, &state, &td) == 0);
	assert(disabled == 0 && destroyed_ecbs == 0 && retained == 1);
	assert(!enabling.destroyed && p.n_matched == 2 && p.n_desc == 2);
	assert(output[0].id == 20 && output[1].id == 21);
	assert(state.dts_enable_pending == 0 && !enabling.dten_pending &&
	    match_calls == 2);

	reset(&state);
	reenter_enable = 1;
	assert(dispatch(&p, &state, &td) == 0 && retained == 1 &&
	    destroyed_dofs == 2 && state.dts_enable_pending == 0);

	reset(&state);
	copyout_error = EFAULT;
	interleave_foreign = 1;
	assert(dispatch(&p, &state, &td) == EFAULT);
	assert(disabled == 2 && destroyed_ecbs == 2 && retained == 0 &&
	    enabling.destroyed && state.dts_enable_pending == 0 &&
	    p.n_matched == 0 && p.n_desc == 0 && slots[0] == &old_ecb &&
	    slots[3] == &foreign_ecb && !foreign_ecb.disabled);

	reset(&state);
	late_match_count = 1;
	late_match_error = ENOMEM;
	interleave_foreign = 1;
	assert(dispatch(&p, &state, &td) == ENOMEM);
	assert(disabled == 3 && destroyed_ecbs == 3 && retained == 0 &&
	    enabling.destroyed && state.dts_enable_pending == 0 &&
	    p.n_matched == 0 && p.n_desc == 0 && slots[0] == &old_ecb &&
	    slots[3] == &foreign_ecb && !foreign_ecb.disabled && slots[4] == NULL);

	reset(&state);
	late_match_count = 1;
	assert(dispatch(&p, &state, &td) == 0 &&
	    slots[3] == &late_ecb && late_ecb.id == 4 && retained == 1 &&
	    state.dts_enable_pending == 0 && !enabling.dten_pending);

	reset(&state);
	match_count = 0;
	assert(dispatch(&p, &state, &td) == 0);
	assert(p.n_matched == 0 && p.n_desc == 0 && retained == 1);
	assert(disabled == 0 && destroyed_ecbs == 0);

	p.dof = NULL;
	assert(dispatch(&p, &state, &td) == 0 && matchall == 1);
	puts("enable ioctl: pass");
	return (0);
}
