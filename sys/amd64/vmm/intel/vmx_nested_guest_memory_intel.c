/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/systm.h>

#include <vm/vm.h>

#include <machine/vmm.h>

#include <dev/vmm/vmm_vm.h>

#include "vmx_nested_guest_memory_intel.h"

#define	NVMX_GUEST_MEMORY_MAX_LENGTH	PAGE_SIZE
#define	NVMX_GUEST_MEMORY_MAX_SEGMENTS	2

struct nvmx_guest_memory_segment {
	void	*mapping;
	void	*cookie;
	size_t	 length;
};

static void
nvmx_guest_memory_release(struct nvmx_guest_memory_segment *segments,
    u_int count)
{

	while (count != 0) {
		count--;
		vm_gpa_release(segments[count].cookie);
	}
}

static int
nvmx_guest_memory_access(struct vmx_nested_guest_memory_intel *runtime,
    uint64_t address, void *buffer, size_t length, bool write)
{
	struct nvmx_guest_memory_segment
	    segments[NVMX_GUEST_MEMORY_MAX_SEGMENTS];
	uint64_t current;
	size_t offset, remaining, segment_length;
	u_int count;
	int protection;

	if (runtime == NULL || runtime->vcpu == NULL || buffer == NULL ||
	    length == 0 || length > NVMX_GUEST_MEMORY_MAX_LENGTH ||
	    address > UINT64_MAX - (length - 1))
		return (EINVAL);
	if (vcpu_get_state(runtime->vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);

	memset(segments, 0, sizeof(segments));
	current = address;
	remaining = length;
	count = 0;
	protection = write ? VM_PROT_READ | VM_PROT_WRITE : VM_PROT_READ;
	while (remaining != 0) {
		if (count == nitems(segments)) {
			nvmx_guest_memory_release(segments, count);
			return (E2BIG);
		}
		segment_length = MIN(remaining,
		    PAGE_SIZE - (current & PAGE_MASK));
		segments[count].mapping = vm_gpa_hold(runtime->vcpu, current,
		    segment_length, protection, &segments[count].cookie);
		if (segments[count].mapping == NULL) {
			nvmx_guest_memory_release(segments, count);
			return (EFAULT);
		}
		segments[count].length = segment_length;
		count++;
		current += segment_length;
		remaining -= segment_length;
	}

	offset = 0;
	for (u_int i = 0; i < count; i++) {
		if (write) {
			memcpy(segments[i].mapping,
			    (const uint8_t *)buffer + offset,
			    segments[i].length);
		} else {
			memcpy((uint8_t *)buffer + offset,
			    segments[i].mapping, segments[i].length);
		}
		offset += segments[i].length;
	}
	nvmx_guest_memory_release(segments, count);
	return (0);
}

static int
nvmx_guest_memory_read(void *arg, uint64_t address, void *buffer,
    size_t length)
{

	return (nvmx_guest_memory_access(arg, address, buffer, length, false));
}

static int
nvmx_guest_memory_write(void *arg, uint64_t address, const void *buffer,
    size_t length)
{

	return (nvmx_guest_memory_access(arg, address,
	    __DECONST(void *, buffer), length, true));
}

int
vmx_nested_guest_memory_intel_init(
    struct vmx_nested_guest_memory_intel *runtime, struct vcpu *vcpu)
{

	if (runtime == NULL || vcpu == NULL)
		return (EINVAL);
	if (vcpu_get_state(vcpu, NULL) != VCPU_FROZEN)
		return (EBUSY);
	memset(runtime, 0, sizeof(*runtime));
	runtime->vcpu = vcpu;
	runtime->memory.read = nvmx_guest_memory_read;
	runtime->memory.write = nvmx_guest_memory_write;
	runtime->memory.arg = runtime;
	return (0);
}

const struct vmx_nested_memory *
vmx_nested_guest_memory_intel_memory(
    const struct vmx_nested_guest_memory_intel *runtime)
{

	if (runtime == NULL || runtime->vcpu == NULL ||
	    runtime->memory.read != nvmx_guest_memory_read ||
	    runtime->memory.write != nvmx_guest_memory_write ||
	    runtime->memory.arg != runtime)
		return (NULL);
	return (&runtime->memory);
}
