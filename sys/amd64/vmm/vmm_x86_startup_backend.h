/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _AMD64_VMM_VMM_X86_STARTUP_BACKEND_H_
#define	_AMD64_VMM_VMM_X86_STARTUP_BACKEND_H_

#include <sys/param.h>
#include <sys/types.h>

#include <machine/vmm.h>

#include "vmm_x86_startup_machine.h"

struct vmm_x86_startup_backend_ops {
	int	(*getreg)(void *, enum vm_reg_name, uint64_t *);
	int	(*setreg)(void *, enum vm_reg_name, uint64_t);
	int	(*getdesc)(void *, enum vm_reg_name, struct seg_desc *);
	int	(*setdesc)(void *, enum vm_reg_name, const struct seg_desc *);
};

struct vmm_x86_startup_backend {
	struct vmm_x86_startup_backend_ops ops;
	void	*arg;
};

int	vmm_x86_startup_backend_init(struct vmm_x86_startup_backend *,
	    const struct vmm_x86_startup_backend_ops *, void *);
int	vmm_x86_startup_backend_getreg(void *,
	    enum vmm_x86_startup_register, uint64_t *);
int	vmm_x86_startup_backend_setreg(void *,
	    enum vmm_x86_startup_register, uint64_t);
int	vmm_x86_startup_backend_getdesc(void *,
	    enum vmm_x86_startup_descriptor, struct vmm_x86_startup_desc *);
int	vmm_x86_startup_backend_setdesc(void *,
	    enum vmm_x86_startup_descriptor,
	    const struct vmm_x86_startup_desc *);

#endif /* _AMD64_VMM_VMM_X86_STARTUP_BACKEND_H_ */
