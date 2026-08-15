/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/types.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include "../../../sys/amd64/vmm/vmm_x86_startup_vmreg.c"
#include "../../../sys/amd64/vmm/vmm_x86_startup_backend.c"

struct fake_backend {
	uint64_t reg[VM_REG_LAST];
	struct seg_desc desc[VM_REG_LAST];
	unsigned int set_calls;
	unsigned int fail_set_call;
	unsigned int fail_set_call2;
	unsigned int mutate_fail_call;
};

static int
fake_getreg(void *arg, enum vm_reg_name reg, uint64_t *value)
{
	struct fake_backend *backend = arg;

	ATF_REQUIRE(reg >= 0 && reg < VM_REG_LAST);
	*value = backend->reg[reg];
	return (0);
}

static int
fake_setreg(void *arg, enum vm_reg_name reg, uint64_t value)
{
	struct fake_backend *backend = arg;

	ATF_REQUIRE(reg >= 0 && reg < VM_REG_LAST);
	backend->set_calls++;
	if (backend->set_calls == backend->fail_set_call ||
	    backend->set_calls == backend->fail_set_call2) {
		if (backend->set_calls == backend->mutate_fail_call)
			backend->reg[reg] = value;
		return (EIO);
	}
	backend->reg[reg] = value;
	return (0);
}

static int
fake_getdesc(void *arg, enum vm_reg_name reg, struct seg_desc *value)
{
	struct fake_backend *backend = arg;

	ATF_REQUIRE(reg >= 0 && reg < VM_REG_LAST);
	*value = backend->desc[reg];
	return (0);
}

static int
fake_setdesc(void *arg, enum vm_reg_name reg,
    const struct seg_desc *value)
{
	struct fake_backend *backend = arg;

	ATF_REQUIRE(reg >= 0 && reg < VM_REG_LAST);
	backend->set_calls++;
	if (backend->set_calls == backend->fail_set_call ||
	    backend->set_calls == backend->fail_set_call2) {
		if (backend->set_calls == backend->mutate_fail_call)
			backend->desc[reg] = *value;
		return (EIO);
	}
	backend->desc[reg] = *value;
	return (0);
}

static const struct vmm_x86_startup_backend_ops fake_ops = {
	.getreg = fake_getreg,
	.setreg = fake_setreg,
	.getdesc = fake_getdesc,
	.setdesc = fake_setdesc,
};

static void
fake_init(struct fake_backend *raw, struct vmm_x86_startup_backend *backend)
{

	memset(raw, 0, sizeof(*raw));
	raw->reg[VM_REG_GUEST_CS] = 0x1234;
	raw->desc[VM_REG_GUEST_CS].base = 0x1234000;
	raw->desc[VM_REG_GUEST_CS].limit = 0xffff;
	raw->desc[VM_REG_GUEST_CS].access = 0x9b;
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_init(backend, &fake_ops, raw), 0);
}

static bool
startup_desc_equal(const struct vmm_x86_startup_desc *left,
    const struct vmm_x86_startup_desc *right)
{

	return (left->base == right->base && left->limit == right->limit &&
	    left->access == right->access && left->selector == right->selector);
}

ATF_TC_WITHOUT_HEAD(composite_descriptor_round_trip);
ATF_TC_BODY(composite_descriptor_round_trip, tc)
{
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc input, output;
	struct fake_backend raw;

	(void)tc;
	fake_init(&raw, &backend);
	memset(&input, 0, sizeof(input));
	input.selector = 0x5a00;
	input.base = 0x5a000;
	input.limit = 0xffff;
	input.access = 0x9b;
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &input), 0);
	memset(&output, 0xa5, sizeof(output));
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), 0);
	ATF_CHECK(startup_desc_equal(&input, &output));
}

ATF_TC_WITHOUT_HEAD(hidden_failure_restores_both_halves);
ATF_TC_BODY(hidden_failure_restores_both_halves, tc)
{
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc before, input, output;
	struct fake_backend raw;

	(void)tc;
	fake_init(&raw, &backend);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &before), 0);
	input = before;
	input.selector = 0x5a00;
	input.base = 0x5a000;
	raw.fail_set_call = 2;
	ATF_CHECK_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &input), EIO);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), 0);
	ATF_CHECK(startup_desc_equal(&before, &output));
}

ATF_TC_WITHOUT_HEAD(mutating_hidden_failure_restores_both_halves);
ATF_TC_BODY(mutating_hidden_failure_restores_both_halves, tc)
{
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc before, input, output;
	struct fake_backend raw;

	(void)tc;
	fake_init(&raw, &backend);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &before), 0);
	input = before;
	input.selector = 0x5a00;
	input.base = 0x5a000;
	raw.fail_set_call = 2;
	raw.mutate_fail_call = 2;
	ATF_CHECK_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &input), EIO);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), 0);
	ATF_CHECK(startup_desc_equal(&before, &output));
}

ATF_TC_WITHOUT_HEAD(wide_selector_and_rejection_preserve_output);
ATF_TC_BODY(wide_selector_and_rejection_preserve_output, tc)
{
	struct vmm_x86_startup_backend backend, preserved;
	struct vmm_x86_startup_desc output, expected;
	struct fake_backend raw;

	(void)tc;
	memset(&backend, 0xa5, sizeof(backend));
	preserved = backend;
	ATF_CHECK_EQ(vmm_x86_startup_backend_init(&backend, NULL, &raw), EINVAL);
	ATF_CHECK_EQ(memcmp(&backend, &preserved, sizeof(backend)), 0);
	fake_init(&raw, &backend);
	raw.reg[VM_REG_GUEST_CS] = UINT64_C(0x10000);
	memset(&output, 0xa5, sizeof(output));
	expected = output;
	ATF_CHECK_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), EPROTO);
	ATF_CHECK(startup_desc_equal(&output, &expected));
}

ATF_TC_WITHOUT_HEAD(restore_failure_is_reported_and_not_hidden);
ATF_TC_BODY(restore_failure_is_reported_and_not_hidden, tc)
{
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc before, input, output;
	struct fake_backend raw;

	(void)tc;
	fake_init(&raw, &backend);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &before), 0);
	input = before;
	input.selector = 0x5a00;
	input.base = 0x5a000;
	/* Mutate on the failed apply, then fail the hidden-cache restore. */
	raw.fail_set_call = 2;
	raw.mutate_fail_call = 2;
	raw.fail_set_call2 = 3;
	ATF_CHECK_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &input), EIO);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), 0);
	ATF_CHECK_EQ(output.selector, before.selector);
	ATF_CHECK_EQ(output.base, input.base);
}

ATF_TC_WITHOUT_HEAD(register_mapping_delegates_exact_name);
ATF_TC_BODY(register_mapping_delegates_exact_name, tc)
{
	struct vmm_x86_startup_backend backend;
	struct fake_backend raw;
	uint64_t value;

	(void)tc;
	fake_init(&raw, &backend);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_setreg(&backend,
	    VMM_X86_STARTUP_REG_RDX, UINT64_C(0x806f8)), 0);
	ATF_CHECK_EQ(raw.reg[VM_REG_GUEST_RDX], UINT64_C(0x806f8));
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getreg(&backend,
	    VMM_X86_STARTUP_REG_RDX, &value), 0);
	ATF_CHECK_EQ(value, UINT64_C(0x806f8));
}

ATF_TC_WITHOUT_HEAD(binding_copies_provider_table);
ATF_TC_BODY(binding_copies_provider_table, tc)
{
	struct vmm_x86_startup_backend_ops mutable_ops;
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc input, output;
	struct fake_backend raw;
	uint64_t value;

	(void)tc;
	memset(&raw, 0, sizeof(raw));
	raw.reg[VM_REG_GUEST_CS] = 0x1234;
	raw.desc[VM_REG_GUEST_CS].base = 0x1234000;
	raw.desc[VM_REG_GUEST_CS].limit = 0xffff;
	raw.desc[VM_REG_GUEST_CS].access = 0x9b;
	mutable_ops = fake_ops;
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_init(&backend, &mutable_ops,
	    &raw), 0);

	/* The admitted provider is value-owned by the binding. */
	memset(&mutable_ops, 0, sizeof(mutable_ops));
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_setreg(&backend,
	    VMM_X86_STARTUP_REG_RDX, UINT64_C(0x806f8)), 0);
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getreg(&backend,
	    VMM_X86_STARTUP_REG_RDX, &value), 0);
	ATF_CHECK_EQ(value, UINT64_C(0x806f8));

	memset(&input, 0, sizeof(input));
	input.selector = 0x5a00;
	input.base = 0x5a000;
	input.limit = 0xffff;
	input.access = 0x9b;
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &input), 0);
	memset(&output, 0, sizeof(output));
	ATF_REQUIRE_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &output), 0);
	ATF_CHECK(startup_desc_equal(&input, &output));
}

ATF_TC_WITHOUT_HEAD(corrupt_context_fails_closed);
ATF_TC_BODY(corrupt_context_fails_closed, tc)
{
	struct vmm_x86_startup_backend backend;
	struct vmm_x86_startup_desc desc;
	struct fake_backend raw;
	uint64_t value;

	(void)tc;
	fake_init(&raw, &backend);
	backend.ops.getreg = NULL;
	value = UINT64_C(0xa5a5a5a5a5a5a5a5);
	ATF_CHECK_EQ(vmm_x86_startup_backend_getreg(&backend,
	    VMM_X86_STARTUP_REG_RAX, &value), EINVAL);
	ATF_CHECK_EQ(value, UINT64_C(0xa5a5a5a5a5a5a5a5));
	ATF_CHECK_EQ(vmm_x86_startup_backend_setreg(&backend,
	    VMM_X86_STARTUP_REG_RAX, 0), EINVAL);
	memset(&desc, 0xa5, sizeof(desc));
	ATF_CHECK_EQ(vmm_x86_startup_backend_getdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &desc), EINVAL);
	ATF_CHECK_EQ(vmm_x86_startup_backend_setdesc(&backend,
	    VMM_X86_STARTUP_DESC_CS, &desc), EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, composite_descriptor_round_trip);
	ATF_TP_ADD_TC(tp, hidden_failure_restores_both_halves);
	ATF_TP_ADD_TC(tp, mutating_hidden_failure_restores_both_halves);
	ATF_TP_ADD_TC(tp, wide_selector_and_rejection_preserve_output);
	ATF_TP_ADD_TC(tp, restore_failure_is_reported_and_not_hidden);
	ATF_TP_ADD_TC(tp, register_mapping_delegates_exact_name);
	ATF_TP_ADD_TC(tp, binding_copies_provider_table);
	ATF_TP_ADD_TC(tp, corrupt_context_fails_closed);
	return (atf_no_error());
}
