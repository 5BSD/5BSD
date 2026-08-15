/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/types.h>

#ifndef _KERNEL
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#else
#include <sys/systm.h>
#endif

struct seg_desc;

#include "vmcs.h"
#include "vmx_nested_caps.h"
#include "vmx_nested_reflect.h"
#include "vmx_nested_state.h"
#include "vmx_nested_state_range.h"
#include "vmx_nested_timer.h"
#include "vmx_nested_vmcs.h"
#include "vmx_nested_vmcs_fields.h"
#include "vmx_nested_vmcs_store.h"
#include "vmx_nested_vmexit.h"
#include "vmx_nested_vmentry.h"

#define	NVMCS_MAGIC		UINT32_C(0x3153564e)	/* "NVS1" */
#define	NVMCS_VERSION		1U
#define	NVMCS_HEADER_SIZE	40U
#define	NVMCS_FIELD_SIZE	16U
#define	NVMCS_F_LAUNCHED	0x00000001U

/* "Save VMX-preemption timer value" VM-exit control (Intel SDM 25.7.1). */
#define	NVMCS_EXIT_SAVE_PREEMPT_TIMER		(UINT32_C(1) << 22)
/* Basic exit reason 52: VMX-preemption timer expired. */
#define	NVMCS_EXIT_REASON_PREEMPT_TIMER		52U
#define	NVMCS_EXIT_REASON_BASIC_MASK		UINT32_C(0xffff)

static uint32_t
nvmcs_capacity(size_t length)
{

	return ((uint32_t)((length - NVMCS_HEADER_SIZE) / NVMCS_FIELD_SIZE));
}

static bool
nvmcs_output_aliases(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, const void *output,
    size_t output_length)
{

	return (vmx_nested_state_ranges_overlap(output, output_length, region,
	    length) || vmx_nested_state_ranges_overlap(output, output_length,
	    capabilities, sizeof(*capabilities)));
}

static int
nvmcs_header(const uint8_t *bytes, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t *count)
{
	struct vmx_nested_vmcs_field_info info;
	uint64_t previous_value;
	uint32_t encoding, flags, nfields;
	uint8_t width;

	if (bytes == NULL || count == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    vmx_nested_state_ranges_overlap(bytes, length, capabilities,
	    sizeof(*capabilities)) ||
	    length != capabilities->vmcs_region_size ||
	    !vmx_nested_revision_valid(capabilities, le32dec(bytes), shadow) ||
	    le32dec(bytes + 8) != NVMCS_MAGIC ||
	    le16dec(bytes + 12) != NVMCS_VERSION ||
	    le16dec(bytes + 14) != NVMCS_HEADER_SIZE ||
	    le32dec(bytes + 4) > 6 ||
	    le64dec(bytes + 24) != vmx_nested_vmcs_schema_signature())
		return (EINVAL);
	flags = le32dec(bytes + 16);
	nfields = le32dec(bytes + 20);
	if ((flags & ~NVMCS_F_LAUNCHED) != 0 ||
	    (((flags & NVMCS_F_LAUNCHED) == 0) !=
	    (le64dec(bytes + 32) == 0)) ||
	    nfields > nvmcs_capacity(length))
		return (EINVAL);
	previous_value = 0;
	for (uint32_t i = 0; i < nfields; i++) {
		const uint8_t *field = bytes + NVMCS_HEADER_SIZE +
		    (size_t)i * NVMCS_FIELD_SIZE;

		encoding = le32dec(field);
		width = field[4];
		if (field[5] != 0 || le16dec(field + 6) != 0 ||
		    vmx_nested_vmcs_field_info(encoding, &info) != 0 ||
		    info.high_half || info.width != width ||
		    !vmx_nested_vmcs_field_available(capabilities, encoding) ||
		    (i != 0 && encoding <= previous_value) ||
		    (width == 2 && le64dec(field + 8) > UINT16_MAX) ||
		    (width == 4 && le64dec(field + 8) > UINT32_MAX))
			return (EINVAL);
		previous_value = encoding;
	}
	*count = nfields;
	return (0);
}

static int
nvmcs_initialize(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, uint32_t revision)
{
	uint8_t *bytes;

	if (region == NULL || capabilities == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    vmx_nested_state_ranges_overlap(region, length, capabilities,
	    sizeof(*capabilities)) ||
	    length != capabilities->vmcs_region_size)
		return (EINVAL);
	bytes = region;
	memset(bytes, 0, length);
	le32enc(bytes, revision);
	le32enc(bytes + 8, NVMCS_MAGIC);
	le16enc(bytes + 12, NVMCS_VERSION);
	le16enc(bytes + 14, NVMCS_HEADER_SIZE);
	le64enc(bytes + 24, vmx_nested_vmcs_schema_signature());
	return (0);
}

int
vmx_nested_vmcs_region_init(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow)
{

	return (nvmcs_initialize(region, length, capabilities,
	    capabilities == NULL ? 0 : capabilities->revision_id |
	    (shadow ? UINT32_C(1) << 31 : 0)));
}

int
vmx_nested_vmcs_region_prepare(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow)
{
	uint32_t count, revision;

	if (region == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    length != capabilities->vmcs_region_size)
		return (EINVAL);
	revision = le32dec(region);
	if (!vmx_nested_revision_valid(capabilities, revision, shadow))
		return (EINVAL);
	if (nvmcs_header(region, length, capabilities, shadow, &count) == 0)
		return (0);
	/*
	 * VMPTRLD architecturally validates only the revision identifier and
	 * shadow indicator.  Initialize the virtual processor's remaining
	 * implementation-defined representation without changing those bits.
	 */
	return (nvmcs_initialize(region, length, capabilities, revision));
}

int
vmx_nested_vmcs_region_validate(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow)
{
	uint32_t count;

	return (nvmcs_header(region, length, capabilities, shadow, &count));
}

static int
nvmcs_find(const uint8_t *bytes, uint32_t count, uint32_t encoding,
    uint32_t *index, bool *found)
{
	uint32_t current, high, low, middle;

	low = 0;
	high = count;
	while (low < high) {
		middle = low + (high - low) / 2;
		current = le32dec(bytes + NVMCS_HEADER_SIZE +
		    (size_t)middle * NVMCS_FIELD_SIZE);
		if (current < encoding)
			low = middle + 1;
		else
			high = middle;
	}
	*index = low;
	*found = low < count && le32dec(bytes + NVMCS_HEADER_SIZE +
	    (size_t)low * NVMCS_FIELD_SIZE) == encoding;
	return (0);
}

int
vmx_nested_vmcs_region_read(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t encoding, uint64_t *value)
{
	struct vmx_nested_vmcs_field_info info;
	const uint8_t *bytes, *field;
	uint32_t count, index;
	uint64_t complete;
	bool found;
	int error;

	if (value == NULL ||
	    nvmcs_output_aliases(region, length, capabilities, value,
	    sizeof(*value)) ||
	    vmx_nested_vmcs_field_info(encoding, &info) != 0 ||
	    !vmx_nested_vmcs_field_available(capabilities, encoding))
		return (EINVAL);
	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	nvmcs_find(bytes, count, info.encoding, &index, &found);
	if (!found)
		complete = 0;
	else {
		field = bytes + NVMCS_HEADER_SIZE +
		    (size_t)index * NVMCS_FIELD_SIZE;
		complete = le64dec(field + 8);
	}
	*value = info.high_half ? complete >> 32 : complete;
	return (0);
}

static int
nvmcs_write(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t encoding, uint64_t value, bool allow_readonly)
{
	struct vmx_nested_vmcs_field_info info;
	uint8_t *bytes, *field;
	uint32_t count, index;
	uint64_t complete, mask;
	bool found;
	int error;

	if (vmx_nested_vmcs_field_info(encoding, &info) != 0 ||
	    (info.readonly && !allow_readonly) ||
	    !vmx_nested_vmcs_field_available(capabilities, encoding))
		return (EINVAL);
	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	if ((!info.high_half && info.width == 2 && value > UINT16_MAX) ||
	    (!info.high_half && info.width == 4 && value > UINT32_MAX) ||
	    (info.high_half && value > UINT32_MAX))
		return (ERANGE);
	nvmcs_find(bytes, count, info.encoding, &index, &found);
	if (!found && count == nvmcs_capacity(length))
		return (ENOSPC);
	if (!found) {
		field = bytes + NVMCS_HEADER_SIZE +
		    (size_t)index * NVMCS_FIELD_SIZE;
		memmove(field + NVMCS_FIELD_SIZE, field,
		    (size_t)(count - index) * NVMCS_FIELD_SIZE);
		memset(field, 0, NVMCS_FIELD_SIZE);
		le32enc(field, info.encoding);
		field[4] = info.width;
		le32enc(bytes + 20, ++count);
		complete = 0;
	} else {
		field = bytes + NVMCS_HEADER_SIZE +
		    (size_t)index * NVMCS_FIELD_SIZE;
		complete = le64dec(field + 8);
	}
	if (info.high_half)
		complete = (complete & UINT32_MAX) | (value << 32);
	else {
		mask = info.width == 2 ? UINT16_MAX :
		    info.width == 4 ? UINT32_MAX : UINT64_MAX;
		complete = value & mask;
	}
	le64enc(field + 8, complete);
	return (0);
}

int
vmx_nested_vmcs_region_write(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t encoding, uint64_t value)
{

	return (nvmcs_write(region, length, capabilities, shadow, encoding,
	    value, false));
}

int
vmx_nested_vmcs_region_set_instruction_error(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t error)
{

	if (error == 0)
		return (EINVAL);
	return (nvmcs_write(region, length, capabilities, shadow, 0x4400,
	    error, true));
}

int
vmx_nested_vmcs_region_clear(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow)
{
	uint8_t *bytes;
	uint32_t count;
	int error;

	if (region == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    length != capabilities->vmcs_region_size)
		return (EINVAL);
	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0) {
		/*
		 * VMCLEAR initializes implementation-specific VMCS data and
		 * does not validate or overwrite the guest-provided revision.
		 */
		return (nvmcs_initialize(region, length, capabilities,
		    le32dec(bytes)));
	}
	le32enc(bytes + 16, le32dec(bytes + 16) & ~NVMCS_F_LAUNCHED);
	le32enc(bytes + 4, 0);
	le64enc(bytes + 32, 0);
	return (0);
}

int
vmx_nested_vmcs_region_set_launched(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    bool launched, uint64_t epoch)
{
	uint8_t *bytes;
	uint32_t count;
	int error;

	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	if (launched == (epoch == 0))
		return (EINVAL);
	le32enc(bytes + 16, launched ? NVMCS_F_LAUNCHED : 0);
	le64enc(bytes + 32, launched ? epoch : 0);
	return (0);
}

int
vmx_nested_vmcs_region_launched(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    bool *launched, uint64_t *epoch)
{
	const uint8_t *bytes;
	uint32_t count;
	int error;

	if (launched == NULL || epoch == NULL ||
	    nvmcs_output_aliases(region, length, capabilities, launched,
	    sizeof(*launched)) ||
	    nvmcs_output_aliases(region, length, capabilities, epoch,
	    sizeof(*epoch)) ||
	    vmx_nested_state_ranges_overlap(launched, sizeof(*launched), epoch,
	    sizeof(*epoch)))
		return (EINVAL);
	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	*launched = (le32dec(bytes + 16) & NVMCS_F_LAUNCHED) != 0;
	*epoch = le64dec(bytes + 32);
	return (0);
}

int
vmx_nested_vmcs_region_set_abort_indicator(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t indicator)
{
	uint32_t count;
	int error;

	if (indicator > 6)
		return (EINVAL);
	error = nvmcs_header(region, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	le32enc((uint8_t *)region + 4, indicator);
	return (0);
}

int
vmx_nested_vmcs_region_abort_indicator(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t *indicator)
{
	uint32_t count, value;
	int error;

	if (indicator == NULL ||
	    nvmcs_output_aliases(region, length, capabilities, indicator,
	    sizeof(*indicator)))
		return (EINVAL);
	error = nvmcs_header(region, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	value = le32dec((const uint8_t *)region + 4);
	if (value > 6)
		return (EINVAL);
	*indicator = value;
	return (0);
}

int
vmx_nested_vmcs_region_field_count(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t *count)
{

	if (count == NULL ||
	    nvmcs_output_aliases(region, length, capabilities, count,
	    sizeof(*count)))
		return (EINVAL);
	return (nvmcs_header(region, length, capabilities, shadow, count));
}

int
vmx_nested_vmcs_region_field(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    uint32_t index, struct vmx_nested_field *result)
{
	const uint8_t *bytes, *field;
	uint32_t count;
	int error;

	if (result == NULL ||
	    nvmcs_output_aliases(region, length, capabilities, result,
	    sizeof(*result)))
		return (EINVAL);
	bytes = region;
	error = nvmcs_header(bytes, length, capabilities, shadow, &count);
	if (error != 0)
		return (error);
	if (index >= count)
		return (ENOENT);
	field = bytes + NVMCS_HEADER_SIZE +
	    (size_t)index * NVMCS_FIELD_SIZE;
	memset(result, 0, sizeof(*result));
	result->encoding = le32dec(field);
	result->width = field[4];
	result->value = le64dec(field + 8);
	return (0);
}

int
vmx_nested_vmcs_region_import(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_field *fields, uint32_t count, bool launched,
    uint64_t epoch)
{
	struct vmx_nested_vmcs_field_info info;
	uint8_t *bytes, *field;
	uint32_t previous;

	if (region == NULL ||
	    vmx_nested_capabilities_validate(capabilities) != 0 ||
	    length != capabilities->vmcs_region_size ||
	    count > nvmcs_capacity(length) ||
	    (count != 0 && fields == NULL) ||
	    launched == (epoch == 0) ||
	    vmx_nested_state_ranges_overlap(region, length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(region, length, fields,
	    (size_t)count * sizeof(*fields)))
		return (EINVAL);

	/*
	 * Validate the entire image before changing the destination.  Restore
	 * may import read-only exit-information fields; unlike VMWRITE, this
	 * path intentionally does not reject info.readonly.
	 */
	previous = 0;
	for (uint32_t i = 0; i < count; i++) {
		if ((fields[i].encoding & UINT32_C(0xffff8001)) != 0 ||
		    vmx_nested_vmcs_field_info(fields[i].encoding, &info) != 0 ||
		    info.high_half || info.width != fields[i].width ||
		    !vmx_nested_vmcs_field_available(capabilities,
		    fields[i].encoding) ||
		    (i != 0 && fields[i].encoding <= previous) ||
		    (fields[i].width == 2 && fields[i].value > UINT16_MAX) ||
		    (fields[i].width == 4 && fields[i].value > UINT32_MAX))
			return (EINVAL);
		previous = fields[i].encoding;
	}

	bytes = region;
	memset(bytes, 0, length);
	le32enc(bytes, capabilities->revision_id |
	    (shadow ? UINT32_C(1) << 31 : 0));
	le32enc(bytes + 8, NVMCS_MAGIC);
	le16enc(bytes + 12, NVMCS_VERSION);
	le16enc(bytes + 14, NVMCS_HEADER_SIZE);
	le32enc(bytes + 16, launched ? NVMCS_F_LAUNCHED : 0);
	le32enc(bytes + 20, count);
	le64enc(bytes + 24, vmx_nested_vmcs_schema_signature());
	le64enc(bytes + 32, launched ? epoch : 0);
	for (uint32_t i = 0; i < count; i++) {
		field = bytes + NVMCS_HEADER_SIZE +
		    (size_t)i * NVMCS_FIELD_SIZE;
		le32enc(field, fields[i].encoding);
		field[4] = fields[i].width;
		le64enc(field + 8, fields[i].value);
	}
	return (0);
}

static int
nvmcs_exit_information_read(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    struct vmx_nested_exit_information *information)
{
	static const uint32_t encodings[] = {
		0x6400,	/* exit qualification */
		0x640a,	/* guest linear address */
		0x2400,	/* guest physical address */
		0x4402,	/* exit reason */
		0x4404,	/* exit interruption information */
		0x4406,	/* exit interruption error code */
		0x4408,	/* IDT-vectoring information */
		0x440a,	/* IDT-vectoring error code */
		0x440c,	/* VM-exit instruction length */
		0x440e,	/* VM-exit instruction information */
		0x4016,	/* VM-entry interruption information */
	};
	uint64_t values[nitems(encodings)];
	uint64_t launch_epoch;
	bool launched;
	int error;

	for (size_t i = 0; i < nitems(encodings); i++) {
		error = vmx_nested_vmcs_region_read(region, length,
		    capabilities, shadow, encodings[i], &values[i]);
		if (error != 0)
			return (error);
	}
	error = vmx_nested_vmcs_region_launched(region, length, capabilities,
	    shadow, &launched, &launch_epoch);
	if (error != 0)
		return (error);
	memset(information, 0, sizeof(*information));
	information->exit_qualification = values[0];
	information->guest_linear_address = values[1];
	information->guest_physical_address = values[2];
	information->exit_reason = values[3];
	information->exit_interruption_info = values[4];
	information->exit_interruption_error = values[5];
	information->idt_vectoring_info = values[6];
	information->idt_vectoring_error = values[7];
	information->exit_instruction_length = values[8];
	information->exit_instruction_info = values[9];
	information->entry_interruption_info = values[10];
	information->launched = launched;
	return (0);
}

static int
nvmcs_exit_information_write(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_exit_information *information, uint64_t epoch)
{
	static const uint32_t encodings[] = {
		0x6400, 0x640a, 0x2400, 0x4402, 0x4404, 0x4406,
		0x4408, 0x440a, 0x440c, 0x440e,
	};
	const uint64_t values[] = {
		information->exit_qualification,
		information->guest_linear_address,
		information->guest_physical_address,
		information->exit_reason,
		information->exit_interruption_info,
		information->exit_interruption_error,
		information->idt_vectoring_info,
		information->idt_vectoring_error,
		information->exit_instruction_length,
		information->exit_instruction_info,
	};
	int error;

	for (size_t i = 0; i < nitems(encodings); i++) {
		error = nvmcs_write(region, length, capabilities, shadow,
		    encodings[i], values[i], true);
		if (error != 0)
			return (error);
	}
	error = nvmcs_write(region, length, capabilities, shadow, 0x4016,
	    information->entry_interruption_info, false);
	if (error != 0)
		return (error);
	return (vmx_nested_vmcs_region_set_launched(region, length,
	    capabilities, shadow, true, epoch));
}

int
vmx_nested_vmcs_region_commit_ept_exit_information(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch,
    void *scratch, size_t scratch_length)
{
	struct vmx_nested_exit_information current, next, source;
	int error;

	if (region == NULL || hardware == NULL || scratch == NULL ||
	    epoch == 0 || scratch_length != length ||
	    (hardware->exit_reason != 48 && hardware->exit_reason != 49) ||
	    (hardware->exit_reason == 49 &&
	    hardware->exit_qualification != 0) ||
	    !vmx_nested_vmcs_field_available(capabilities, 0x2400) ||
	    vmx_nested_state_ranges_overlap(region, length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(region, length, hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(region, length, scratch, scratch_length) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	error = nvmcs_exit_information_read(region, length, capabilities,
	    shadow, &current);
	if (error != 0)
		return (error);
	source = *hardware;
	/*
	 * This field belongs to the exiting VMCS12, not VMCS01.  Preserve
	 * its value and let the architectural preparation clear VALID.
	 */
	source.entry_interruption_info = current.entry_interruption_info;
	error = vmx_nested_exit_information_prepare(&current, &source, &next);
	if (error != 0)
		return (error);
	memcpy(scratch, region, length);
	error = nvmcs_exit_information_write(scratch, length, capabilities,
	    shadow, &next, epoch);
	if (error != 0)
		return (error);
	memcpy(region, scratch, length);
	return (0);
}

static int
nvmcs_vmexit_state_write(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_vmexit_state_plan *plan)
{
	const struct vmx_nested_guest_control_state *control;
	const struct vmx_nested_guest_arch_state *arch;
	static const uint32_t control_encodings[] = {
		VMCS_GUEST_CR0,
		VMCS_GUEST_CR3,
		VMCS_GUEST_CR4,
		VMCS_GUEST_DR7,
		VMCS_GUEST_IA32_SYSENTER_CS,
		VMCS_GUEST_IA32_SYSENTER_ESP,
		VMCS_GUEST_IA32_SYSENTER_EIP,
	};
	uint64_t control_values[nitems(control_encodings)];
	int error;

	control = &plan->saved_l2_control;
	arch = &plan->saved_l2_arch;
	control_values[0] = control->cr0;
	control_values[1] = control->cr3;
	control_values[2] = control->cr4;
	control_values[3] = control->dr7;
	control_values[4] = control->sysenter_cs;
	control_values[5] = control->sysenter_esp;
	control_values[6] = control->sysenter_eip;
	for (size_t i = 0; i < nitems(control_encodings); i++) {
		error = nvmcs_write(region, length, capabilities, shadow,
		    control_encodings[i], control_values[i], true);
		if (error != 0)
			return (error);
	}
	if (vmx_nested_vmcs_field_available(capabilities,
	    VMCS_GUEST_IA32_PAT)) {
		error = nvmcs_write(region, length, capabilities, shadow,
		    VMCS_GUEST_IA32_PAT, control->pat, true);
		if (error != 0)
			return (error);
	}
	if (vmx_nested_vmcs_field_available(capabilities,
	    VMCS_GUEST_IA32_EFER)) {
		error = nvmcs_write(region, length, capabilities, shadow,
		    VMCS_GUEST_IA32_EFER, control->efer, true);
		if (error != 0)
			return (error);
	}
	for (u_int i = 0; i < VMX_NESTED_GUEST_SEGMENT_COUNT; i++) {
		uint32_t encoding;

		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_SELECTOR, &encoding);
		if (error != 0)
			return (error);
		error = nvmcs_write(region, length, capabilities, shadow,
		    encoding, arch->segment[i].selector, true);
		if (error != 0)
			return (error);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_LIMIT, &encoding);
		if (error != 0)
			return (error);
		error = nvmcs_write(region, length, capabilities, shadow,
		    encoding, arch->segment[i].limit, true);
		if (error != 0)
			return (error);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_ACCESS, &encoding);
		if (error != 0)
			return (error);
		error = nvmcs_write(region, length, capabilities, shadow,
		    encoding, arch->segment[i].access, true);
		if (error != 0)
			return (error);
		error = vmx_nested_vmcs_segment_encoding(i,
		    VMX_NESTED_SEGMENT_BASE, &encoding);
		if (error != 0)
			return (error);
		error = nvmcs_write(region, length, capabilities, shadow,
		    encoding, arch->segment[i].base, true);
		if (error != 0)
			return (error);
	}
#define	NVMCS_VMEXIT_WRITE(encoding, value) do {			\
	error = nvmcs_write(region, length, capabilities, shadow,	\
	    (encoding), (value), true);					\
	if (error != 0)							\
		return (error);						\
} while (0)
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_GDTR_LIMIT, arch->gdtr_limit);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_IDTR_LIMIT, arch->idtr_limit);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_GDTR_BASE, arch->gdtr_base);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_IDTR_BASE, arch->idtr_base);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_RSP, arch->rsp);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_RIP, arch->rip);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_RFLAGS, arch->rflags);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
	    arch->pending_debug);
	if (vmx_nested_vmcs_field_available(capabilities,
	    VMCS_GUEST_IA32_DEBUGCTL))
		NVMCS_VMEXIT_WRITE(VMCS_GUEST_IA32_DEBUGCTL, arch->debugctl);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_ACTIVITY, arch->activity);
	NVMCS_VMEXIT_WRITE(VMCS_GUEST_INTERRUPTIBILITY,
	    arch->interruptibility);
	NVMCS_VMEXIT_WRITE(VMCS_ENTRY_CTLS, plan->saved_vmcs12_vmentry);
	NVMCS_VMEXIT_WRITE(VMCS_ENTRY_INTR_INFO,
	    plan->saved_vmcs12_entry_intr_info);
#undef NVMCS_VMEXIT_WRITE
	return (0);
}

int
vmx_nested_vmcs_region_prepare_vmexit(const void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_vmexit_state_input *state_input,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch,
    void *scratch, size_t scratch_length)
{
	struct vmx_nested_exit_information current, information, source;
	struct vmx_nested_timer_exit_input timer_input;
	struct vmx_nested_timer_exit_plan timer_plan;
	struct vmx_nested_vmexit_state_plan state;
	int error;

	if (region == NULL || capabilities == NULL || state_input == NULL ||
	    state_input->l1_host == NULL || state_input->l2_runtime == NULL ||
	    state_input->vmcs12_control == NULL ||
	    state_input->vmcs12_arch == NULL || hardware == NULL ||
	    scratch == NULL || epoch == 0 || scratch_length != length ||
	    (hardware->exit_reason & (UINT32_C(1) << 31)) != 0 ||
	    vmx_nested_state_ranges_overlap(region, length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(region, length, state_input,
	    sizeof(*state_input)) ||
	    vmx_nested_state_ranges_overlap(region, length, state_input->l1_host,
	    sizeof(*state_input->l1_host)) ||
	    vmx_nested_state_ranges_overlap(region, length, state_input->l2_runtime,
	    sizeof(*state_input->l2_runtime)) ||
	    vmx_nested_state_ranges_overlap(region, length, state_input->vmcs12_control,
	    sizeof(*state_input->vmcs12_control)) ||
	    vmx_nested_state_ranges_overlap(region, length, state_input->vmcs12_arch,
	    sizeof(*state_input->vmcs12_arch)) ||
	    vmx_nested_state_ranges_overlap(region, length, hardware,
	    sizeof(*hardware)) ||
	    vmx_nested_state_ranges_overlap(region, length, scratch, scratch_length) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, state_input,
	    sizeof(*state_input)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length,
	    state_input->l1_host, sizeof(*state_input->l1_host)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length,
	    state_input->l2_runtime, sizeof(*state_input->l2_runtime)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length,
	    state_input->vmcs12_control,
	    sizeof(*state_input->vmcs12_control)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length,
	    state_input->vmcs12_arch,
	    sizeof(*state_input->vmcs12_arch)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, hardware,
	    sizeof(*hardware)))
		return (EINVAL);
	error = nvmcs_exit_information_read(region, length, capabilities,
	    shadow, &current);
	if (error != 0)
		return (error);
	if (current.entry_interruption_info !=
	    state_input->vmcs12_entry_intr_info)
		return (ESTALE);
	error = vmx_nested_vmexit_state_prepare(state_input, &state);
	if (error != 0)
		return (error);
	source = *hardware;
	source.entry_interruption_info = current.entry_interruption_info;
	error = vmx_nested_exit_information_prepare(&current, &source,
	    &information);
	if (error != 0)
		return (error);
	if (information.entry_interruption_info !=
	    state.saved_vmcs12_entry_intr_info)
		return (ESTALE);
	/*
	 * SDM 28.4: when the "save VMX-preemption timer value" exit control
	 * is 1, a VM exit stores the current timer value into VMCS12, and a
	 * timer-expiration exit stores zero.  The residual travels with the
	 * captured L2 runtime image; republish it to the exit planner as a
	 * deadline over a zero exit timestamp so the plan carries exactly
	 * the captured value.  A runtime image without a valid capture can
	 * only describe an L2 that never reached hardware (the composed
	 * VMCS02 always activates the timer when VMCS12 may request the
	 * save), so the unconsumed VMCS12 value is already the current
	 * residual and the save is architecturally a no-op.
	 */
	memset(&timer_input, 0, sizeof(timer_input));
	timer_input.deadline_ticks =
	    state_input->l2_runtime->preemption_timer_value;
	timer_input.save_value =
	    (state_input->vmexit & NVMCS_EXIT_SAVE_PREEMPT_TIMER) != 0 &&
	    state_input->l2_runtime->preemption_timer_valid;
	timer_input.timer_expired_exit =
	    (information.exit_reason & NVMCS_EXIT_REASON_BASIC_MASK) ==
	    NVMCS_EXIT_REASON_PREEMPT_TIMER;
	error = vmx_nested_timer_exit(&timer_input, &timer_plan);
	if (error != 0)
		return (error);

	memcpy(scratch, region, length);
	error = nvmcs_vmexit_state_write(scratch, length, capabilities,
	    shadow, &state);
	if (error == 0)
		error = nvmcs_exit_information_write(scratch, length,
		    capabilities, shadow, &information, epoch);
	if (error == 0 && timer_plan.write_value)
		error = nvmcs_write(scratch, length, capabilities, shadow,
		    VMCS_PREEMPTION_TIMER_VALUE, timer_plan.value, true);
	if (error != 0)
		return (error);
	return (0);
}

int
vmx_nested_vmcs_region_commit_vmexit(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_vmexit_state_input *state_input,
    const struct vmx_nested_exit_information *hardware, uint64_t epoch,
    void *scratch, size_t scratch_length)
{
	int error;

	error = vmx_nested_vmcs_region_prepare_vmexit(region, length,
	    capabilities, shadow, state_input, hardware, epoch, scratch,
	    scratch_length);
	if (error != 0)
		return (error);
	memcpy(region, scratch, length);
	return (0);
}

int
vmx_nested_vmcs_region_commit_vmentry_failure(void *region, size_t length,
    const struct vmx_nested_capabilities *capabilities, bool shadow,
    const struct vmx_nested_vmentry_result *result, void *scratch,
    size_t scratch_length)
{
	int error;

	if (region == NULL || capabilities == NULL || result == NULL ||
	    scratch == NULL || scratch_length != length ||
	    result->disposition != VMX_NESTED_VMENTRY_ENTRY_FAILURE ||
	    vmx_nested_state_ranges_overlap(region, length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(region, length, result, sizeof(*result)) ||
	    vmx_nested_state_ranges_overlap(region, length, scratch, scratch_length) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, capabilities,
	    sizeof(*capabilities)) ||
	    vmx_nested_state_ranges_overlap(scratch, scratch_length, result,
	    sizeof(*result)))
		return (EINVAL);
	error = vmx_nested_vmentry_rejection_validate(result);
	if (error != 0)
		return (error);

	/*
	 * SDM 26.7: a late VM-entry failure populates exit reason and exit
	 * qualification, but it is not a successful launch.  Stage the two
	 * architectural writes in a complete VMCS copy so validation failure
	 * cannot leave a partially updated VMCS12, and deliberately preserve
	 * the launch flag and epoch.
	 */
	memcpy(scratch, region, length);
	error = nvmcs_write(scratch, length, capabilities, shadow, 0x4402,
	    result->exit_reason, true);
	if (error == 0)
		error = nvmcs_write(scratch, length, capabilities, shadow,
		    0x6400, result->exit_qualification, true);
	if (error != 0)
		return (error);
	memcpy(region, scratch, length);
	return (0);
}
