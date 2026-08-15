/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/errno.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

#include "vmx_nested_vmcs_launch.h"

void
vmx_nested_vmcs_launch_init(struct vmx_nested_vmcs_launch *launch)
{

	if (launch != NULL)
		memset(launch, 0, sizeof(*launch));
}

int
vmx_nested_vmcs_launch_select(struct vmx_nested_vmcs_launch *launch)
{

	if (launch == NULL || launch->current || launch->launched)
		return (EINVAL);
	launch->current = true;
	return (0);
}

int
vmx_nested_vmcs_launch_instruction(
    const struct vmx_nested_vmcs_launch *launch, int *launched)
{

	if (launch == NULL || launched == NULL || !launch->current)
		return (EINVAL);
	*launched = launch->launched ? 1 : 0;
	return (0);
}

int
vmx_nested_vmcs_launch_commit_entered(
    struct vmx_nested_vmcs_launch *launch)
{

	if (launch == NULL || !launch->current)
		return (EINVAL);
	launch->launched = true;
	return (0);
}

int
vmx_nested_vmcs_launch_clear(struct vmx_nested_vmcs_launch *launch)
{

	if (launch == NULL || !launch->current)
		return (EINVAL);
	vmx_nested_vmcs_launch_init(launch);
	return (0);
}

int
vmx_nested_vmcs_launch_validate(
    const struct vmx_nested_vmcs_launch *launch)
{

	if (launch == NULL || (!launch->current && launch->launched))
		return (EINVAL);
	return (0);
}
