/* SPDX-License-Identifier: BSD-2-Clause */
/* Linux/RISC-V vDSO signal return trampoline. */

#include <machine/asm.h>
#include <riscv/linux/linux_syscall.h>

	.data
	.globl linux_platform
linux_platform:
	.asciz "riscv64"

	.text
EENTRY(__vdso_rt_sigreturn)
	.globl __user_rt_sigreturn
__user_rt_sigreturn:
	li a7, LINUX_SYS_linux_rt_sigreturn
	ecall
EEND(__vdso_rt_sigreturn)

	.section .note.GNU-stack,"",%progbits
