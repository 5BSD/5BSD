/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#define INSN_SIZE 4
#define INSN_C_SIZE 2
#define MATCH_C_NOP 1
#define RD_SHIFT 7
#define RD_MASK (0x1f << RD_SHIFT)
#define RS1_SHIFT 15
#define RS1_MASK (0x1f << RS1_SHIFT)
#define RS2_SHIFT 20
#define RS2_MASK (0x1f << RS2_SHIFT)
#define IMM_SHIFT 20
#define IMM_MASK (0xfff << IMM_SHIFT)
#define panic(...) abort()

typedef uint32_t kinst_patchval_t;
struct trapframe {
	uint64_t tf_ra, tf_sp, tf_gp, tf_tp;
	uint64_t tf_t[7], tf_s[12], tf_a[8];
	uint64_t tf_sepc, tf_sstatus, tf_stval, tf_scause;
};
struct kinst_probe {
	kinst_patchval_t kp_savedval;
	struct { int instlen; bool emulate; } kp_md;
};

#include "kinst-riscv-functions.inc"

int
main(void)
{
	struct trapframe frame = { 0 };
	struct kinst_probe kp = { .kp_md.instlen = INSN_SIZE };

	/* AUIPC x0, 0 must discard its result, not write before trapframe. */
	frame.tf_sepc = 0x1000;
	kp.kp_savedval = 0x00000017;
	assert(kinst_emulate(&frame, &kp) == MATCH_C_NOP);
	assert(frame.tf_sepc == 0x1004 && frame.tf_ra == 0);

	/* AUIPC ra, 0x1000 still writes the ordinary destination. */
	frame.tf_sepc = 0x2000;
	kp.kp_savedval = 0x00001097;
	assert(kinst_emulate(&frame, &kp) == MATCH_C_NOP);
	assert(frame.tf_sepc == 0x2004 && frame.tf_ra == 0x3000);

	/* Compressed indirect jumps clear bit 0 of the target. */
	kp.kp_md.instlen = INSN_C_SIZE;
	kp.kp_savedval = 0x8082; /* c.jr ra */
	frame.tf_ra = 0x4001;
	frame.tf_sepc = 0x3100;
	assert(kinst_emulate(&frame, &kp) == MATCH_C_NOP);
	assert(frame.tf_sepc == 0x4000 && frame.tf_ra == 0x4001);
	kp.kp_savedval = 0x9082; /* c.jalr ra */
	frame.tf_ra = 0x5001;
	frame.tf_sepc = 0x3200;
	assert(kinst_emulate(&frame, &kp) == MATCH_C_NOP);
	assert(frame.tf_sepc == 0x5000 && frame.tf_ra == 0x3202);

	puts("PASS: actual RISC-V kinst AUIPC x0 and compressed JALR");
	return (0);
}
