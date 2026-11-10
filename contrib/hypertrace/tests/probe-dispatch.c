/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define ASSERT(x) assert(x)
#define HYPERTRACE_MAX_VMS 1024
#define DTRACE_SENSIBLE_PROBELIMIT 100000
typedef int hypertrace_id_t;
typedef struct { int unused; } hypertrace_args_t;
typedef int dtrace_icookie_t;
typedef struct {
	uint64_t htpb_epoch;
	int htpb_enabled;
	int htpb_running;
} hypertrace_probe_t;
typedef struct { int unused; } hypertrace_map_t;
struct fake_thread { const void *t_hypertrace_vmhdl; } thread;
static struct fake_thread *curthread = &thread;
static hypertrace_map_t map;
static hypertrace_map_t *hypertrace_map = &map;
static hypertrace_probe_t probe = { .htpb_epoch = 23,
    .htpb_enabled = 1, .htpb_running = 1 };
static int present = 1, disables, enables, firings;
static uint64_t handle_epoch = 23;

static uint16_t
hypertrace_priv_getns(const void *vmhdl)
{
	assert(vmhdl != NULL);
	return (7);
}

static uint64_t
getepoch(const void *vmhdl)
{
	assert(vmhdl != NULL);
	return (handle_epoch);
}
static uint64_t (*vmm_getepoch)(const void *) = getepoch;

static dtrace_icookie_t
dtrace_interrupt_disable(void)
{
	disables++;
	return (1);
}

static void
dtrace_interrupt_enable(dtrace_icookie_t cookie)
{
	assert(cookie == 1);
	enables++;
}

static hypertrace_probe_t *
map_get(hypertrace_map_t *which, uint16_t vmid, hypertrace_id_t id)
{
	assert(which == hypertrace_map && vmid == 7 && id == 12);
	return (present ? &probe : NULL);
}

static void
dtrace_probe(hypertrace_id_t id, uintptr_t args, uintptr_t a2,
    uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	assert(id == 12 && args != 0 && a2 == 0 && a3 == 0 &&
	    a4 == 0 && a5 == 0);
	assert(curthread->t_hypertrace_vmhdl != NULL);
	firings++;
}

/* FUNCTION */

int
main(void)
{
	hypertrace_args_t args = { 0 };
	int handle = 1;
	int previous = 2;

	thread.t_hypertrace_vmhdl = &previous;
	assert(hypertrace_probe(NULL, 12, &args) == EINVAL);
	assert(hypertrace_probe(&handle, 0, &args) == EINVAL);
	assert(hypertrace_probe(&handle, 12, NULL) == EINVAL);
	assert(disables == 0 && enables == 0);
	present = 0;
	assert(hypertrace_probe(&handle, 12, &args) == ESRCH);
	present = 1;
	vmm_getepoch = NULL;
	assert(hypertrace_probe(&handle, 12, &args) == ESTALE);
	vmm_getepoch = getepoch;
	handle_epoch = 24;
	assert(hypertrace_probe(&handle, 12, &args) == ESTALE);
	handle_epoch = 23;
	probe.htpb_enabled = 0;
	assert(hypertrace_probe(&handle, 12, &args) == EACCES);
	probe.htpb_enabled = 1;
	probe.htpb_running = 0;
	assert(hypertrace_probe(&handle, 12, &args) == EACCES);
	probe.htpb_running = 1;
	assert(hypertrace_probe(&handle, 12, &args) == 0);
	assert(firings == 1 && disables == enables);
	assert(curthread->t_hypertrace_vmhdl == &previous);
	puts("PASS: production virtual-probe dispatch results");
	return (0);
}
