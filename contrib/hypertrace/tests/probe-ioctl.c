/* SPDX-License-Identifier: BSD-2-Clause */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", \
    __FILE__, __LINE__, #x); abort(); } } while (0)
#define ASSERT CHECK
#define KM_SLEEP 0
#define DTRACE_IOCTL_PRINTF(...)
#define DTRACEIOC_VPROBE_CREATE 1
#define HYPERTRACE_MAX_VMS 1024
/* Only memory ownership and dispatch are mocked; the ioctl body is extracted. */
typedef struct { uint32_t id; char names[256]; } dtrace_probedesc_t;
typedef struct {
	uint16_t vmid;
	uint64_t epoch;
	size_t neprobes;
	dtrace_probedesc_t *eprobes;
} dtrace_vprobe_io_t;
static unsigned allocations, frees, copy_fault, lock_depth, calls;
static int callback_error;
static int cpu_lock = 1, dtrace_provider_lock = 2, dtrace_lock = 3;
static void mutex_enter(int *lock) { CHECK(*lock == (int)++lock_depth); }
static void mutex_exit(int *lock) { CHECK(*lock == (int)lock_depth--); }
static void *kmem_zalloc(size_t length, int flags)
{
	CHECK(flags == KM_SLEEP && length <= 64U * 1024U * 1024U);
	allocations++;
	return (calloc(1, length));
}
static void kmem_free(void *data, size_t length)
{
	CHECK(length != 0 && lock_depth == 0);
	frees++;
	free(data);
}
static int copyin(const void *src, void *dst, size_t length)
{
	if (copy_fault) return (EFAULT);
	memcpy(dst, src, length);
	return (0);
}
static int create(uint16_t vmid, uint64_t epoch, void *data, size_t count)
{
	CHECK(vmid == 1 && epoch == 42 && data != NULL && count == 1 && lock_depth == 3);
	calls++;
	return (callback_error);
}
static int (*hypertrace_create_probes)(uint16_t, uint64_t, void *, size_t);
#define DTRACE_SENSIBLE_PROBELIMIT (1U << 20)
struct owner_state { size_t dts_vprobe_registrations; } owner_state;
static struct owner_state *state = &owner_state;
static void dtrace_vprobe_register_owner(struct owner_state *owner, uint16_t vmid,
    const dtrace_probedesc_t *data, size_t count) {
	CHECK(owner == state && vmid == 1 && data != NULL && count == 1 && lock_depth == 3);
}
#include "ioctl.inc"
int main(void)
{
	dtrace_probedesc_t desc = { 0 };
	dtrace_vprobe_io_t request = { .vmid = 1, .epoch = 42, .neprobes = 1, .eprobes = &desc };
	request.vmid = 0;
	CHECK(dispatch(&request) == EINVAL && allocations == 0);
	request.vmid = UINT16_MAX;
	CHECK(dispatch(&request) == EINVAL && allocations == 0);
	request.vmid = 1; request.neprobes = SIZE_MAX;
	CHECK(dispatch(&request) == EINVAL && allocations == 0);
	request.neprobes = 1; copy_fault = 1;
	CHECK(dispatch(&request) == EFAULT && allocations == frees);
	copy_fault = 0;
	CHECK(dispatch(&request) == ENOTSUP && allocations == frees);
	hypertrace_create_probes = create;
	callback_error = EEXIST;
	CHECK(dispatch(&request) == EEXIST && allocations == frees && calls == 1);
	callback_error = 0;
	CHECK(dispatch(&request) == 0 && allocations == frees && calls == 2);
	state->dts_vprobe_registrations = DTRACE_SENSIBLE_PROBELIMIT;
	CHECK(dispatch(&request) == ENOSPC && allocations == frees && calls == 2);
	state->dts_vprobe_registrations = SIZE_MAX;
	CHECK(dispatch(&request) == ENOSPC && allocations == frees && calls == 2);
	state->dts_vprobe_registrations = 0;
	CHECK(lock_depth == 0);
	puts("PASS: virtual-probe ioctl bounds, copy faults, absent hooks, errors, ownership and lock order");
	return (0);
}
