/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Guest-side HyperTrace SBI ABI.  The extension ID is experimental and is
 * advertised only by a 5BSD VMM that implements the matching probe call.
 */
#ifndef _RISCV_BHYVE_HYPERCALL_H_
#define _RISCV_BHYVE_HYPERCALL_H_

#include <sys/types.h>
#include <machine/sbi.h>

#define HYPERCALL_RET_SUCCESS 0

static __inline int
bhyve_hypercalls_enabled(void)
{
	struct sbi_ret ret;

	if (sbi_probe_extension(SBI_EXT_ID_HYPERTRACE) <= 0)
		return (0);
	ret = SBI_CALL0(SBI_EXT_ID_HYPERTRACE, SBI_HYPERTRACE_QUERY);
	return (ret.error == SBI_SUCCESS &&
	    ret.value == SBI_HYPERTRACE_VERSION);
}

static __inline int
hypercall_dtrace_probe(int id, uintptr_t args, lwpid_t tid)
{
	struct sbi_ret ret;

	ret = SBI_CALL3(SBI_EXT_ID_HYPERTRACE, SBI_HYPERTRACE_PROBE,
	    id, args, tid);
	return (ret.error == SBI_SUCCESS ? HYPERCALL_RET_SUCCESS : -1);
}

#endif /* _RISCV_BHYVE_HYPERCALL_H_ */
