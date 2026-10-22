/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "kinst_isa.h"

#define INSN_SIZE 4
#define PSR_V 0x10000000UL
#define PSR_C 0x20000000UL
#define PSR_Z 0x40000000UL
#define PSR_N 0x80000000UL

struct trapframe {
	uint64_t tf_sp, tf_lr, tf_elr, tf_spsr, tf_esr, tf_far;
	uint64_t tf_x[30];
};
struct kinst_probe {
	kinst_patchval_t kp_savedval;
	struct kinst_probe_md kp_md;
};

#include "kinst-arm64-functions.inc"

static void
emulate(struct trapframe *frame, uint32_t instruction,
    enum kinst_instr expected)
{
	struct kinst_probe kp = { .kp_savedval = instruction };

	kp.kp_md.kp_type = kinst_instr_type(instruction);
	assert(kp.kp_md.kp_type == expected);
	kinst_emulate(frame, &kp);
}

int
main(void)
{
	struct trapframe frame = { 0 };

	/* ADR X30, #0 writes the saved link register, not tf_x[30]. */
	frame.tf_elr = 0x1000;
	emulate(&frame, 0x1000001e, KINST_INSTR_ADR);
	assert(frame.tf_lr == 0x1000 && frame.tf_elr == 0x1004);

	/* ADR XZR, #0 discards its result, leaving X30 untouched. */
	frame.tf_elr = 0x2000;
	emulate(&frame, 0x1000001f, KINST_INSTR_ADR);
	assert(frame.tf_lr == 0x1000 && frame.tf_elr == 0x2004);

	/* CBNZ X30, +8 reads LR; CBZ XZR, +8 always branches. */
	frame.tf_lr = 1;
	frame.tf_elr = 0x3000;
	emulate(&frame, 0xb500005e, KINST_INSTR_CBZ);
	assert(frame.tf_elr == 0x3008);
	frame.tf_elr = 0x3100;
	emulate(&frame, 0xb400005f, KINST_INSTR_CBZ);
	assert(frame.tf_elr == 0x3108);
	/* W30 compares only the low 32 bits of LR. */
	frame.tf_lr = 1ULL << 40;
	frame.tf_elr = 0x3200;
	emulate(&frame, 0x3400005e, KINST_INSTR_CBZ); /* cbz w30, +8 */
	assert(frame.tf_elr == 0x3208);
	frame.tf_elr = 0x3300;
	emulate(&frame, 0x3500005e, KINST_INSTR_CBZ); /* cbnz w30, +8 */
	assert(frame.tf_elr == 0x3304);

	/* TBZ X30 bit 40, +8 must use a 64-bit mask. */
	frame.tf_lr = 1ULL << 40;
	frame.tf_elr = 0x4000;
	emulate(&frame, 0xb640005e, KINST_INSTR_TBZ);
	assert(frame.tf_elr == 0x4004);
	frame.tf_lr = 0;
	frame.tf_elr = 0x4100;
	emulate(&frame, 0xb640005e, KINST_INSTR_TBZ);
	assert(frame.tf_elr == 0x4108);

	puts("PASS: actual arm64 kinst emulator X30, XZR, W30 and TBZ bit 40");
	return (0);
}
