/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define HYPERTRACE_STACK_MAX_FRAMES 64U
#define CPU_DTRACE_BADSTACK 0x20U
#define DTRACEACT_STACK 1
#define DTRACE_ANCHORED(probe) 1
typedef uintptr_t pc_t;
typedef struct {
	uintptr_t *htr_pcstack;
	uint32_t htr_pcstack_count;
	uint32_t htr_pcstack_reserved;
} hypertrace_args_t;
/* PCSTACK_HELPER */
struct probe { unsigned dtpr_vmid; int dtpr_aframes; };
struct machine_state {
	void *dtms_vmhdl;
	hypertrace_args_t *dtms_htrargs;
};
static int allowed = 1, copies, host_unwinds;
static int dtrace_priv_kernel(void *state)
{
	(void)state;
	return allowed;
}
static void dtrace_bcopy(void *handle, const void *source, void *dest,
    size_t length)
{
	assert(handle != NULL);
	copies++;
	memcpy(dest, source, length);
}
static void dtrace_getpcstack(pc_t *dest, int frames, int aframes,
    uint32_t *intrpc)
{
	assert(aframes == 0 && intrpc == NULL);
	host_unwinds++;
	for (int i = 0; i < frames; i++)
		dest[i] = 0xbeef + (uintptr_t)i;
}
static void
run(struct probe *probe, struct machine_state mstate, unsigned *flags,
    pc_t output[4], uint32_t frames)
{
	void *state = NULL;
	char *tomax = (char *)output;
	size_t valoffs = 0, size = frames * sizeof(pc_t);
	uintptr_t arg0 = 0;

	for (int i = 0; i < 1; i++) {
		switch (DTRACEACT_STACK) {
/* PRODUCTION_ARM */
		default: assert(0);
		}
	}
}
int
main(void)
{
	pc_t pcs[4] = {0x111, 0x222, 0x333, 0};
	pc_t output[4] = {0};
	hypertrace_args_t args = {
		.htr_pcstack = pcs,
		.htr_pcstack_count = 3,
	};
	struct probe guest = {.dtpr_vmid = 7}, host = {0};
	struct machine_state guest_state = {.dtms_vmhdl = &guest,
	    .dtms_htrargs = &args};
	struct machine_state host_state = {0};
	unsigned flags = 0;

	run(&guest, guest_state, &flags, output, 3);
	assert(flags == 0 && copies == 1 && host_unwinds == 0 &&
	    memcmp(output, pcs, 3 * sizeof(pc_t)) == 0);
	memset(output, 0, sizeof(output));
	run(&guest, guest_state, &flags, output, 4);
	assert(flags == CPU_DTRACE_BADSTACK && copies == 1 && output[0] == 0);
	flags = 0;
	args.htr_pcstack_reserved = 1;
	run(&guest, guest_state, &flags, output, 3);
	assert(flags == CPU_DTRACE_BADSTACK && copies == 1);
	flags = 0;
	args.htr_pcstack_reserved = 0;
	guest_state.dtms_vmhdl = NULL;
	run(&guest, guest_state, &flags, output, 3);
	assert(flags == CPU_DTRACE_BADSTACK && copies == 1);
	flags = 0;
	guest_state.dtms_vmhdl = &guest;
	allowed = 0;
	run(&guest, guest_state, &flags, output, 3);
	assert(flags == 0 && copies == 1);
	allowed = 1;
	run(&host, host_state, &flags, output, 3);
	assert(flags == 0 && copies == 1 && host_unwinds == 1 &&
	    output[0] == 0xbeef && output[2] == 0xbef1);
	puts("PASS: bounded raw guest kernel stack and independent host unwind");
	return 0;
}
