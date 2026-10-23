/* SPDX-License-Identifier: BSD-2-Clause */
/* User-memory atomics for Linux FUTEX_WAKE_OP on RISC-V. */

#include <sys/param.h>
#include <sys/systm.h>

#include <riscv/linux/linux.h>
#include <compat/linux/linux_emul.h>
#include <compat/linux/linux_futex.h>

enum futex_op { FX_XCHG, FX_ADD, FX_OR, FX_AND, FX_XOR };

static int
futex_user_op(enum futex_op op, int arg, uint32_t *uaddr, int *oldval)
{
	uint32_t old, next, observed;
	int rc;

	if (fueword32(uaddr, (int32_t *)&old) == -1)
		return (EFAULT);
	for (;;) {
		switch (op) {
		case FX_XCHG: next = arg; break;
		case FX_ADD: next = old + arg; break;
		case FX_OR: next = old | arg; break;
		case FX_AND: next = old & arg; break;
		case FX_XOR: next = old ^ arg; break;
		}
		rc = casueword32(uaddr, old, &observed, next);
		if (rc == -1)
			return (EFAULT);
		if (rc == 0) {
			*oldval = old;
			return (0);
		}
		old = observed;
	}
}

int
futex_xchgl(int arg, uint32_t *uaddr, int *oldval)
{
	return (futex_user_op(FX_XCHG, arg, uaddr, oldval));
}

int
futex_addl(int arg, uint32_t *uaddr, int *oldval)
{
	return (futex_user_op(FX_ADD, arg, uaddr, oldval));
}

int
futex_orl(int arg, uint32_t *uaddr, int *oldval)
{
	return (futex_user_op(FX_OR, arg, uaddr, oldval));
}

int
futex_andl(int arg, uint32_t *uaddr, int *oldval)
{
	return (futex_user_op(FX_AND, arg, uaddr, oldval));
}

int
futex_xorl(int arg, uint32_t *uaddr, int *oldval)
{
	return (futex_user_op(FX_XOR, arg, uaddr, oldval));
}
