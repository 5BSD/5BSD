/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _RISCV_LINUX_SIGFRAME_H_
#define _RISCV_LINUX_SIGFRAME_H_

/* Linux/RISC-V LP64D signal ABI. */
#define LINUX_RISCV_V_MAGIC 0x53465457U

struct l_riscv_ctx_hdr {
	uint32_t magic;
	uint32_t size;
};

struct l_riscv_fp_state {
	uint64_t f[32];
	uint32_t fcsr;
	uint32_t reserved[3];
} __attribute__((aligned(16)));

struct l_riscv_extdesc {
	uint32_t padding[129];
	uint32_t reserved;
	struct l_riscv_ctx_hdr hdr;
} __attribute__((aligned(16)));

struct l_sigcontext {
	struct linux_pt_regset regs;
	union {
		struct l_riscv_fp_state fp;
		struct l_riscv_extdesc ext;
	};
};

struct l_ucontext {
	l_ulong uc_flags;
	l_ulong uc_link;
	l_stack_t uc_stack;
	l_sigset_t uc_sigmask;
	uint8_t padding[128 - sizeof(l_sigset_t)];
	struct l_sigcontext uc_sc;
};

struct l_rt_sigframe {
	l_siginfo_t info;
	struct l_ucontext uc;
} __attribute__((aligned(16)));

struct l_riscv_vector_state {
	uint64_t vstart, vl, vtype, vcsr, vlenb, datap;
} __attribute__((aligned(16)));

#define LINUX_MINSIGSTKSZ roundup(sizeof(struct l_rt_sigframe), 16)

#endif
