/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Hand-assembled functions for pid-placement.py.  Every instruction is
 * spelled out as bytes, so the expected return-probe offsets follow from
 * this layout alone.  None of this code is ever executed.
 */
	.text

/*
 * Every return form libdtrace recognises, then jumps that stay inside the
 * function, then a breakpoint byte whose original instruction must be asked
 * of fasttrap (FASTTRAPIOC_GETINSTR), then a final ret.
 */
	.globl	ht_rets
	.type	ht_rets,@function
ht_rets:
	.byte	0xc3				/*  0: ret */
	.byte	0xf3, 0xc3			/*  1: rep ret */
	.byte	0xc2, 0x08, 0x00		/*  3: ret $8 */
	.byte	0xf3, 0xc2, 0x08, 0x00		/*  6: rep ret $8 */
	.byte	0xe9				/* 10: jmp rel32, outside */
	.long	ht_after - (. + 4)
	.byte	0xeb				/* 15: jmp rel8, outside */
	.byte	ht_after - (. + 1)
	.byte	0x0f, 0x84			/* 17: je rel32, outside */
	.long	ht_after - (. + 4)
	.byte	0x74				/* 23: je rel8, outside */
	.byte	ht_after - (. + 1)
	.byte	0xeb, 0x00			/* 25: jmp rel8, inside */
	.byte	0x0f, 0x84, 0x00, 0x00, 0x00, 0x00	/* 27: je rel32, inside */
	.byte	0xcc				/* 33: int3 (fasttrap byte) */
	.byte	0xc3				/* 34: ret */
	.size	ht_rets, . - ht_rets

	.globl	ht_after
	.type	ht_after,@function
ht_after:
	.byte	0xc3
	.size	ht_after, . - ht_after

/*
 * Contains undecodable bytes, so libdtrace assumes a jump table and accepts
 * only leave/ret and movl %ebp,%esp/popl %ebp/ret epilogues (offset of the
 * ret, including any rep prefix), and no offset probes.
 */
	.globl	ht_jt
	.type	ht_jt,@function
ht_jt:
	.byte	0xc9, 0xc3			/*  0: leave; ret -> 1 */
	.byte	0xc9, 0xf3, 0xc3		/*  2: leave; rep ret -> 3 */
	.byte	0x8b, 0xe5, 0x5d, 0xc3		/*  5: movl; popl; ret -> 8 */
	.byte	0x8b, 0xe5, 0x5d, 0xf3, 0xc3	/*  9: movl; popl; rep ret -> 12 */
	.byte	0x0f, 0x01, 0xee		/* 14: rdpkru (refused) */
	.byte	0xc3				/* 17: ret */
	.size	ht_jt, . - ht_jt

	.section .note.GNU-stack,"",@progbits
