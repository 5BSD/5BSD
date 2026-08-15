/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#include "../../dev/vmm/vmm_address_range.h"

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#endif

#include "vmm_x86_startup_backend.h"
#include "vmm_x86_startup_vmreg.h"

static bool
startup_backend_ranges_overlap(const void *left, size_t left_length,
    const void *right, size_t right_length)
{

	return (vmm_address_ranges_overlap(left, left_length, right,
	    right_length));
}

static int
startup_backend_validate(const struct vmm_x86_startup_backend *backend)
{

	if (backend == NULL || backend->arg == NULL ||
	    backend->ops.getreg == NULL || backend->ops.setreg == NULL ||
	    backend->ops.getdesc == NULL || backend->ops.setdesc == NULL ||
	    startup_backend_ranges_overlap(backend, sizeof(*backend),
	    backend->arg, 1))
		return (EINVAL);
	return (0);
}

int
vmm_x86_startup_backend_init(struct vmm_x86_startup_backend *backend,
    const struct vmm_x86_startup_backend_ops *ops, void *arg)
{
	struct vmm_x86_startup_backend candidate;

	if (backend == NULL || ops == NULL || arg == NULL ||
	    startup_backend_ranges_overlap(backend, sizeof(*backend), ops,
	    sizeof(*ops)) || startup_backend_ranges_overlap(backend,
	    sizeof(*backend), arg, 1) ||
	    ops->getreg == NULL || ops->setreg == NULL ||
	    ops->getdesc == NULL || ops->setdesc == NULL)
		return (EINVAL);
	candidate.ops = *ops;
	candidate.arg = arg;
	*backend = candidate;
	return (0);
}

int
vmm_x86_startup_backend_getreg(void *arg,
    enum vmm_x86_startup_register source, uint64_t *value)
{
	struct vmm_x86_startup_backend *backend;
	enum vm_reg_name reg;
	uint64_t candidate;
	int error;

	backend = arg;
	if (value == NULL || startup_backend_validate(backend) != 0)
		return (EINVAL);
	error = vmm_x86_startup_register_vmreg(source, &reg);
	if (error == 0)
		error = backend->ops.getreg(backend->arg, reg, &candidate);
	if (error == 0)
		*value = candidate;
	return (error);
}

int
vmm_x86_startup_backend_setreg(void *arg,
    enum vmm_x86_startup_register destination, uint64_t value)
{
	struct vmm_x86_startup_backend *backend;
	enum vm_reg_name reg;
	int error;

	backend = arg;
	if (startup_backend_validate(backend) != 0)
		return (EINVAL);
	error = vmm_x86_startup_register_vmreg(destination, &reg);
	if (error != 0)
		return (error);
	return (backend->ops.setreg(backend->arg, reg, value));
}

int
vmm_x86_startup_backend_getdesc(void *arg,
    enum vmm_x86_startup_descriptor source,
    struct vmm_x86_startup_desc *value)
{
	struct vmm_x86_startup_backend *backend;
	struct vmm_x86_startup_desc candidate;
	struct seg_desc hidden;
	enum vm_reg_name reg;
	uint64_t selector;
	int error;

	backend = arg;
	if (value == NULL || startup_backend_validate(backend) != 0)
		return (EINVAL);
	error = vmm_x86_startup_descriptor_vmreg(source, &reg);
	if (error == 0)
		error = backend->ops.getreg(backend->arg, reg, &selector);
	if (error == 0 && selector > UINT16_MAX)
		error = EPROTO;
	if (error == 0)
		error = backend->ops.getdesc(backend->arg, reg, &hidden);
	if (error != 0)
		return (error);
	candidate.base = hidden.base;
	candidate.limit = hidden.limit;
	candidate.access = hidden.access;
	candidate.selector = (uint16_t)selector;
	*value = candidate;
	return (0);
}

int
vmm_x86_startup_backend_setdesc(void *arg,
    enum vmm_x86_startup_descriptor destination,
    const struct vmm_x86_startup_desc *value)
{
	struct vmm_x86_startup_backend *backend;
	struct seg_desc hidden, old_hidden;
	enum vm_reg_name reg;
	uint64_t old_selector;
	int error, restore_desc_error, restore_reg_error;

	backend = arg;
	if (value == NULL || startup_backend_validate(backend) != 0)
		return (EINVAL);
	error = vmm_x86_startup_descriptor_vmreg(destination, &reg);
	if (error == 0)
		error = backend->ops.getreg(backend->arg, reg, &old_selector);
	if (error == 0 && old_selector > UINT16_MAX)
		error = EPROTO;
	if (error == 0)
		error = backend->ops.getdesc(backend->arg, reg, &old_hidden);
	if (error != 0)
		return (error);

	hidden.base = value->base;
	hidden.limit = value->limit;
	hidden.access = value->access;
	error = backend->ops.setreg(backend->arg, reg, value->selector);
	if (error != 0)
		return (error);
	error = backend->ops.setdesc(backend->arg, reg, &hidden);
	if (error == 0)
		return (0);

	/* Restore both halves even if the failed hidden-cache write mutated. */
	restore_desc_error = backend->ops.setdesc(backend->arg, reg,
	    &old_hidden);
	restore_reg_error = backend->ops.setreg(backend->arg, reg,
	    old_selector);
	if (restore_desc_error != 0 || restore_reg_error != 0)
		return (EIO);
	return (error);
}
