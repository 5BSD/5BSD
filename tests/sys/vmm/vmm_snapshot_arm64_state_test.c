/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Offline tests for the portable ARM64 checkpoint codec
 * (sys/arm64/vmm/vmm_snapshot_arm64.c): round trips, field validation,
 * structurally malformed envelopes and a deterministic mutation sweep whose
 * oracle is canonical re-encoding.  The codec is host-independent, so these
 * cases run natively on any architecture; they do not exercise the kernel
 * adapter, a vGIC or any guest.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/endian.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <atf-c.h>

#include <dev/vmm/vmm_address_range.h>
#include <dev/vmm/vmm_snapshot_envelope.h>
#include <dev/vmm/vmm_snapshot_state.h>
#include "../../../sys/arm64/vmm/vmm_snapshot_arm64.h"

#include "../../../sys/dev/vmm/vmm_snapshot_envelope.c"
#include "../../../sys/dev/vmm/vmm_snapshot_state.c"
#include "../../../sys/arm64/vmm/vmm_snapshot_arm64.c"

#define	MAXV	8
#define	NV	3

static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;

static uint64_t
rng(void)
{
	/* xorshift64*: deterministic, so every failure is reproducible. */
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (rng_state * 0x2545f4914f6cdd1dULL);
}

static void
vm_fixture(struct vmm_snapshot_arm64_transaction *tx,
    struct vmm_snapshot_arm64_vcpu_stage *stage)
{
	static const uint32_t instances[NV] = { 0, 2, 5 };

	memset(tx, 0, sizeof(*tx));
	memset(stage, 0, sizeof(*stage) * NV);
	tx->vm.max_vcpus = MAXV;
	tx->vm.vcpu_count = NV;
	tx->vcpu_count = NV;
	tx->arm64.cntfrq = 24000000;
	tx->arm64.guest_count = 0x123456789abcdefULL;
	for (int i = 0; i < NV; i++) {
		stage[i].instance = instances[i];
		for (int r = 0; r < VMM_SNAPSHOT_ARM64_REG_COUNT; r++)
			stage[i].vcpu.regs[r] = rng();
		stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_PSTATE] =
		    0x3c0 | VMM_SNAPSHOT_ARM64_PSR_M_EL1h;
		stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_VMPIDR_EL2] =
		    0x80000000ULL | instances[i];
		stage[i].vcpu.flags = i == 1 ?
		    VMM_SNAPSHOT_ARM64_VCPU_F_EXCEPTION : 0;
		stage[i].common.next_pc =
		    stage[i].vcpu.regs[VMM_SNAPSHOT_ARM64_PC];
		for (int v = 0; v < 32; v++)
			for (int b = 0; b < 16; b++)
				stage[i].fp.vregs[v][b] = (uint8_t)rng();
		stage[i].fp.fpcr = (uint32_t)rng();
		stage[i].fp.fpsr = 0x0800001fU;
		stage[i].timer.cntkctl = (uint32_t)rng();
		stage[i].timer.virt_ctl = 1;
		stage[i].timer.virt_cval = rng();
		stage[i].timer.phys_ctl = 3;
		stage[i].timer.phys_cval = rng();
	}
}

static size_t
vm_encode(const struct vmm_snapshot_arm64_transaction *tx,
    const struct vmm_snapshot_arm64_vcpu_stage *stage, uint8_t **wirep)
{
	size_t length, written;

	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vm_size(tx->vcpu_count, &length), 0);
	*wirep = malloc(length);
	ATF_REQUIRE(*wirep != NULL);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vm_encode(tx, stage, tx->vcpu_count,
	    *wirep, length, &written), 0);
	ATF_REQUIRE_EQ(written, length);
	return (written);
}

/* Canonical-encoding oracle: success must re-encode to identical bytes. */
static int
vm_decode_canonical(const uint8_t *wire, size_t length)
{
	struct vmm_snapshot_arm64_vcpu_stage stage[MAXV];
	struct vmm_snapshot_arm64_transaction tx;
	uint8_t *again;
	size_t size, written;
	int error;

	error = vmm_snapshot_arm64_vm_decode(wire, length, stage, MAXV, &tx);
	if (error != 0)
		return (error);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vm_size(tx.vcpu_count, &size), 0);
	again = malloc(size);
	ATF_REQUIRE(again != NULL);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vm_encode(&tx, stage, tx.vcpu_count,
	    again, size, &written), 0);
	/* Unknown non-critical sections are dropped; otherwise identical. */
	if (written == length)
		ATF_REQUIRE_EQ(memcmp(again, wire, length), 0);
	free(again);
	return (0);
}

ATF_TC_WITHOUT_HEAD(vm_round_trip);
ATF_TC_BODY(vm_round_trip, tc)
{
	struct vmm_snapshot_arm64_vcpu_stage stage[NV], out[MAXV];
	struct vmm_snapshot_arm64_transaction tx, decoded;
	uint8_t *wire;
	size_t length;

	vm_fixture(&tx, stage);
	length = vm_encode(&tx, stage, &wire);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vm_decode(wire, length, out, MAXV,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.vcpu_count, NV);
	ATF_CHECK_EQ(decoded.vm.max_vcpus, MAXV);
	ATF_CHECK_EQ(decoded.arm64.cntfrq, tx.arm64.cntfrq);
	ATF_CHECK_EQ(decoded.arm64.guest_count, tx.arm64.guest_count);
	for (int i = 0; i < NV; i++) {
		ATF_CHECK_EQ(out[i].instance, stage[i].instance);
		ATF_CHECK_EQ(memcmp(&out[i].vcpu, &stage[i].vcpu,
		    sizeof(out[i].vcpu)), 0);
		ATF_CHECK_EQ(memcmp(out[i].fp.vregs, stage[i].fp.vregs,
		    sizeof(out[i].fp.vregs)), 0);
		ATF_CHECK_EQ(out[i].fp.fpcr, stage[i].fp.fpcr);
		ATF_CHECK_EQ(out[i].fp.fpsr, stage[i].fp.fpsr);
		ATF_CHECK_EQ(memcmp(&out[i].timer, &stage[i].timer,
		    sizeof(out[i].timer)), 0);
		ATF_CHECK_EQ(out[i].common.next_pc, stage[i].common.next_pc);
	}
	ATF_CHECK_EQ(vm_decode_canonical(wire, length), 0);
	/* Too small a destination capacity is refused. */
	ATF_CHECK_EQ(vmm_snapshot_arm64_vm_decode(wire, length, out, NV - 1,
	    &decoded), EINVAL);
	free(wire);
}

ATF_TC_WITHOUT_HEAD(vm_field_validation);
ATF_TC_BODY(vm_field_validation, tc)
{
	struct vmm_snapshot_arm64_vcpu_stage stage[NV];
	struct vmm_snapshot_arm64_transaction tx;
	uint8_t wire[16384];
	size_t written;
	static const uint64_t bad_pstate[] = {
		0x9,			/* EL2h */
		0x8,			/* EL2t */
		0xd,			/* EL3h */
		0x10,			/* AArch32 */
		0x1,			/* reserved mode */
		UINT64_C(1) << 32 | 5,	/* bits above PSTATE */
	};

#define	EXPECT_ENCODE(err) \
	ATF_CHECK_EQ(vmm_snapshot_arm64_vm_encode(&tx, stage, NV, wire, \
	    sizeof(wire), &written), (err))

	vm_fixture(&tx, stage);
	EXPECT_ENCODE(0);
	for (size_t i = 0; i < nitems(bad_pstate); i++) {
		vm_fixture(&tx, stage);
		stage[1].vcpu.regs[VMM_SNAPSHOT_ARM64_PSTATE] = bad_pstate[i];
		EXPECT_ENCODE(EINVAL);
	}
	vm_fixture(&tx, stage);
	stage[0].vcpu.regs[VMM_SNAPSHOT_ARM64_VMPIDR_EL2] &= ~0x80000000ULL;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[0].vcpu.flags = 4;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[2].timer.virt_ctl = 8;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[2].timer.phys_ctl = UINT64_C(1) << 40;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[0].fp.fpsr = 0x00000100U;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[0].common.next_pc ^= 4;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[0].common.flags = VMM_SNAPSHOT_VCPU_F_STARTUP_WAIT;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[2].instance = MAXV;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	stage[1].instance = 0;		/* not strictly increasing */
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	tx.vm.vcpu_count = NV - 1;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	tx.arm64.cntfrq = 0;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	tx.vm.max_vcpus = VMM_SNAPSHOT_ARM64_MAX_VCPUS + 1;
	EXPECT_ENCODE(EINVAL);
	vm_fixture(&tx, stage);
	ATF_CHECK_EQ(vmm_snapshot_arm64_vm_encode(&tx, stage, NV, wire, 64,
	    &written), E2BIG);
#undef EXPECT_ENCODE
}

/* Emit a VM record with an optional section omitted, duplicated or added. */
enum vm_variant {
	VM_CANONICAL,
	VM_DROP_FP,
	VM_DROP_ARM64_VM,
	VM_NONCRITICAL_UNKNOWN,
	VM_CRITICAL_UNKNOWN,
	VM_UNFLAGGED_VCPU,
	VM_WRONG_INSTANCE,
	VM_SHORT_TIMER,
	VM_BAD_REG_COUNT,
};

static size_t
vm_variant_build(enum vm_variant variant, uint8_t *wire, size_t capacity)
{
	struct vmm_snapshot_arm64_vcpu_stage stage[NV];
	struct vmm_snapshot_arm64_transaction tx;
	struct vmm_snapshot_envelope_builder b;
	uint8_t payload[VMM_SNAPSHOT_ARM64_VCPU_SIZE];
	size_t used, length;
	uint16_t flags;

	vm_fixture(&tx, stage);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_builder_init(&b, wire, capacity),
	    0);
	ATF_REQUIRE_EQ(vmm_snapshot_vm_common_encode(&tx.vm, payload,
	    sizeof(payload), &used), 0);
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b, 1, 1, 0, payload, used), 0);
	for (int i = 0; i < NV; i++) {
		ATF_REQUIRE_EQ(vmm_snapshot_vcpu_common_encode(&stage[i].common,
		    payload, sizeof(payload), &used), 0);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b, 2, 1,
		    stage[i].instance, payload, used), 0);
	}
	if (variant == VM_NONCRITICAL_UNKNOWN || variant == VM_CRITICAL_UNKNOWN)
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b, 0x1fff,
		    variant == VM_CRITICAL_UNKNOWN ? 1 : 0, 0, "x", 1), 0);
	if (variant != VM_DROP_ARM64_VM) {
		arm64_encode_vm(&tx.arm64, payload);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b,
		    VMM_SNAPSHOT_SECTION_ARM64_VM, 1, 0, payload,
		    VMM_SNAPSHOT_ARM64_VM_SIZE), 0);
	}
	for (int i = 0; i < NV; i++) {
		arm64_encode_vcpu(&stage[i].vcpu, payload);
		if (variant == VM_BAD_REG_COUNT && i == 1)
			le32enc(payload + 8, VMM_SNAPSHOT_ARM64_REG_COUNT - 1);
		flags = variant == VM_UNFLAGGED_VCPU && i == 0 ? 0 : 1;
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b,
		    VMM_SNAPSHOT_SECTION_ARM64_VCPU, flags,
		    stage[i].instance + (variant == VM_WRONG_INSTANCE && i == 2),
		    payload, VMM_SNAPSHOT_ARM64_VCPU_SIZE), 0);
	}
	for (int i = 0; variant != VM_DROP_FP && i < NV; i++) {
		arm64_encode_fp(&stage[i].fp, payload);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b,
		    VMM_SNAPSHOT_SECTION_ARM64_FP, 1, stage[i].instance,
		    payload, VMM_SNAPSHOT_ARM64_FP_SIZE), 0);
	}
	for (int i = 0; i < NV; i++) {
		arm64_encode_timer(&stage[i].timer, payload);
		ATF_REQUIRE_EQ(vmm_snapshot_envelope_add(&b,
		    VMM_SNAPSHOT_SECTION_ARM64_TIMER, 1, stage[i].instance,
		    payload, VMM_SNAPSHOT_ARM64_TIMER_SIZE -
		    (variant == VM_SHORT_TIMER ? 8 : 0)), 0);
	}
	ATF_REQUIRE_EQ(vmm_snapshot_envelope_finalize(&b, &length), 0);
	return (length);
}

ATF_TC_WITHOUT_HEAD(vm_malformed_structure);
ATF_TC_BODY(vm_malformed_structure, tc)
{
	struct vmm_snapshot_arm64_vcpu_stage out[MAXV];
	struct vmm_snapshot_arm64_transaction decoded;
	static uint8_t wire[16384];
	size_t length;
	static const struct {
		enum vm_variant variant;
		int error;
	} cases[] = {
		{ VM_CANONICAL, 0 },
		{ VM_DROP_FP, EINVAL },
		{ VM_DROP_ARM64_VM, EINVAL },
		{ VM_NONCRITICAL_UNKNOWN, 0 },
		{ VM_CRITICAL_UNKNOWN, EPROTONOSUPPORT },
		{ VM_UNFLAGGED_VCPU, EINVAL },
		{ VM_WRONG_INSTANCE, EINVAL },
		{ VM_SHORT_TIMER, EINVAL },
		{ VM_BAD_REG_COUNT, EINVAL },
	};

	for (size_t i = 0; i < nitems(cases); i++) {
		length = vm_variant_build(cases[i].variant, wire, sizeof(wire));
		ATF_CHECK_EQ_MSG(vmm_snapshot_arm64_vm_decode(wire, length, out,
		    MAXV, &decoded), cases[i].error, "variant %d",
		    cases[i].variant);
	}
	/* Every proper prefix of a valid record is refused. */
	length = vm_variant_build(VM_CANONICAL, wire, sizeof(wire));
	for (size_t cut = 0; cut < length; cut++)
		ATF_REQUIRE(vmm_snapshot_arm64_vm_decode(wire, cut, out, MAXV,
		    &decoded) != 0);
	ATF_CHECK_EQ(vmm_snapshot_arm64_vm_decode(NULL, length, out, MAXV,
	    &decoded), EINVAL);
}

ATF_TC_WITHOUT_HEAD(vm_mutation_sweep);
ATF_TC_BODY(vm_mutation_sweep, tc)
{
	struct vmm_snapshot_arm64_vcpu_stage stage[NV];
	struct vmm_snapshot_arm64_transaction tx;
	uint8_t *wire, *mutant;
	size_t length, pos;
	unsigned accepted, rejected;

	vm_fixture(&tx, stage);
	length = vm_encode(&tx, stage, &wire);
	mutant = malloc(length);
	ATF_REQUIRE(mutant != NULL);
	accepted = rejected = 0;
	for (unsigned iter = 0; iter < 40000; iter++) {
		memcpy(mutant, wire, length);
		/* Bias half the mutations toward headers and control fields. */
		pos = (iter & 1) ? rng() % 160 : rng() % length;
		mutant[pos] ^= (uint8_t)(1U << (rng() % 8));
		if ((iter % 7) == 0)
			mutant[rng() % length] = (uint8_t)rng();
		if (vm_decode_canonical(mutant, length) == 0)
			accepted++;
		else
			rejected++;
	}
	printf("vm mutations: %u accepted (canonical), %u rejected\n",
	    accepted, rejected);
	ATF_CHECK(rejected > 0);
	ATF_CHECK(accepted > 0);
	free(mutant);
	free(wire);
}

/* vGIC */

static void
vgic_irq_fixture(struct vmm_snapshot_arm64_vgic_irq *irq, uint32_t id,
    int32_t target)
{

	memset(irq, 0, sizeof(*irq));
	irq->priority = (uint8_t)(id * 8);
	irq->target_vcpu = target;
	irq->config = id < 16 ? VMM_SNAPSHOT_ARM64_IRQ_CONFIG_EDGE :
	    VMM_SNAPSHOT_ARM64_IRQ_CONFIG_LEVEL;
	irq->mpidr = target > 0 ? (uint64_t)target : 0;
}

static void
vgic_fixture(struct vmm_snapshot_arm64_vgic_transaction *tx,
    struct vmm_snapshot_arm64_vgic_stage *stage)
{
	static const uint32_t instances[NV] = { 0, 2, 5 };
	struct vmm_snapshot_arm64_vgic_cpu *cpu;

	memset(tx, 0, sizeof(*tx));
	memset(stage, 0, sizeof(*stage) * NV);
	tx->vm.max_vcpus = MAXV;
	tx->vm.vcpu_count = NV;
	tx->vcpu_count = NV;
	tx->dist.dist_start = 0x2f000000;
	tx->dist.dist_size = 0x10000;
	tx->dist.redist_start = 0x2f100000;
	tx->dist.redist_size = MAXV * 0x20000;
	tx->dist.gicd_ctlr = VMM_SNAPSHOT_ARM64_GICD_CTLR_G1A |
	    VMM_SNAPSHOT_ARM64_GICD_CTLR_ARE_NS;
	tx->dist.min_prio = 0xf8;
	tx->dist.lr_num = 4;
	tx->dist.apr_num = 1;
	for (uint32_t i = 0; i < VMM_SNAPSHOT_ARM64_VGIC_SPI_COUNT; i++)
		vgic_irq_fixture(&tx->dist.spis[i], i + 32,
		    (int32_t)(i % 4 == 3 ? -1 : instances[i % NV]));
	/* SPI 33 pending+enabled on CPU 2's list; SPI 40 active on CPU 0. */
	tx->dist.spis[1].flags = VMM_SNAPSHOT_ARM64_IRQ_F_PENDING |
	    VMM_SNAPSHOT_ARM64_IRQ_F_ENABLED | VMM_SNAPSHOT_ARM64_IRQ_F_APLIST;
	tx->dist.spis[8].flags = VMM_SNAPSHOT_ARM64_IRQ_F_ACTIVE |
	    VMM_SNAPSHOT_ARM64_IRQ_F_APLIST;
	for (int c = 0; c < NV; c++) {
		stage[c].instance = instances[c];
		cpu = &stage[c].cpu;
		cpu->ich_hcr = VMM_SNAPSHOT_ARM64_ICH_HCR_EN;
		cpu->ich_vmcr = 0xf8000003ULL;
		cpu->ap1r[0] = 0x80000000U;
		for (uint32_t j = 0; j < 32; j++)
			vgic_irq_fixture(&cpu->private_irqs[j], j,
			    (int32_t)instances[c]);
	}
	/* CPU 0: SGI 1 pending, timer PPI 27 level, then SPI 40. */
	cpu = &stage[0].cpu;
	cpu->private_irqs[1].flags = VMM_SNAPSHOT_ARM64_IRQ_F_PENDING |
	    VMM_SNAPSHOT_ARM64_IRQ_F_ENABLED | VMM_SNAPSHOT_ARM64_IRQ_F_APLIST;
	cpu->private_irqs[27].flags = VMM_SNAPSHOT_ARM64_IRQ_F_LEVEL |
	    VMM_SNAPSHOT_ARM64_IRQ_F_ENABLED | VMM_SNAPSHOT_ARM64_IRQ_F_APLIST;
	cpu->aplist[0] = 40;
	cpu->aplist[1] = 1;
	cpu->aplist[2] = 27;
	cpu->aplist_count = 3;
	stage[1].cpu.aplist[0] = 33;
	stage[1].cpu.aplist_count = 1;
}

static size_t
vgic_encode(const struct vmm_snapshot_arm64_vgic_transaction *tx,
    const struct vmm_snapshot_arm64_vgic_stage *stage, uint8_t **wirep)
{
	size_t bound, written;

	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vgic_size(tx->vcpu_count, &bound), 0);
	*wirep = malloc(bound);
	ATF_REQUIRE(*wirep != NULL);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vgic_encode(tx, stage,
	    tx->vcpu_count, *wirep, bound, &written), 0);
	ATF_REQUIRE(written < bound);
	return (written);
}

static int
vgic_decode_canonical(const uint8_t *wire, size_t length)
{
	static struct vmm_snapshot_arm64_vgic_stage stage[MAXV];
	static struct vmm_snapshot_arm64_vgic_transaction tx;
	uint8_t *again;
	size_t written;
	int error;

	error = vmm_snapshot_arm64_vgic_decode(wire, length, stage, MAXV, &tx);
	if (error != 0)
		return (error);
	written = vgic_encode(&tx, stage, &again);
	if (written == length)
		ATF_REQUIRE_EQ(memcmp(again, wire, length), 0);
	free(again);
	return (0);
}

ATF_TC_WITHOUT_HEAD(vgic_round_trip);
ATF_TC_BODY(vgic_round_trip, tc)
{
	static struct vmm_snapshot_arm64_vgic_stage stage[NV], out[MAXV];
	static struct vmm_snapshot_arm64_vgic_transaction tx, decoded;
	uint8_t *wire;
	size_t length;

	vgic_fixture(&tx, stage);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vgic_validate(&tx, stage, NV), 0);
	length = vgic_encode(&tx, stage, &wire);
	ATF_REQUIRE_EQ(vmm_snapshot_arm64_vgic_decode(wire, length, out, MAXV,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.vcpu_count, NV);
	ATF_CHECK_EQ(memcmp(&decoded.dist, &tx.dist, sizeof(tx.dist)), 0);
	for (int c = 0; c < NV; c++) {
		ATF_CHECK_EQ(out[c].instance, stage[c].instance);
		ATF_CHECK_EQ(out[c].cpu.aplist_count, stage[c].cpu.aplist_count);
		ATF_CHECK_EQ(memcmp(out[c].cpu.aplist, stage[c].cpu.aplist,
		    2 * stage[c].cpu.aplist_count), 0);
		ATF_CHECK_EQ(memcmp(out[c].cpu.private_irqs,
		    stage[c].cpu.private_irqs,
		    sizeof(stage[c].cpu.private_irqs)), 0);
		ATF_CHECK_EQ(out[c].cpu.ich_vmcr, stage[c].cpu.ich_vmcr);
		ATF_CHECK_EQ(out[c].cpu.ap1r[0], stage[c].cpu.ap1r[0]);
	}
	ATF_CHECK_EQ(vgic_decode_canonical(wire, length), 0);
	/* The scratch tail beyond the record is scrubbed. */
	free(wire);
}

ATF_TC_WITHOUT_HEAD(vgic_semantic_validation);
ATF_TC_BODY(vgic_semantic_validation, tc)
{
	static struct vmm_snapshot_arm64_vgic_stage stage[NV];
	static struct vmm_snapshot_arm64_vgic_transaction tx;
	int cases;

#define	EXPECT_INVALID(mutation) do {					\
	vgic_fixture(&tx, stage);					\
	mutation;							\
	ATF_CHECK_EQ_MSG(vmm_snapshot_arm64_vgic_validate(&tx, stage, NV), \
	    EINVAL, "%s", #mutation);					\
	cases++;							\
} while (0)

	cases = 0;
	EXPECT_INVALID(stage[0].cpu.aplist[1] = 40);	/* duplicate */
	EXPECT_INVALID(stage[1].cpu.aplist[0] = 40);	/* on two CPUs */
	EXPECT_INVALID(stage[0].cpu.aplist[0] = 1023);	/* out of range */
	EXPECT_INVALID(stage[1].cpu.aplist[0] = 34);	/* not flagged */
	/* An extra unflagged SPI next to the correctly listed one. */
	EXPECT_INVALID(stage[1].cpu.aplist[1] = 34;
	    stage[1].cpu.aplist_count = 2);
	/* A private interrupt listed twice on its own CPU. */
	EXPECT_INVALID(stage[0].cpu.aplist[3] = 1;
	    stage[0].cpu.aplist_count = 4);
	/* An unflagged private interrupt in the list. */
	EXPECT_INVALID(stage[0].cpu.aplist[3] = 5;
	    stage[0].cpu.aplist_count = 4);
	EXPECT_INVALID(stage[1].cpu.aplist_count = 0);	/* flagged, unlisted */
	EXPECT_INVALID(stage[0].cpu.aplist_count = 2);	/* PPI 27 unlisted */
	EXPECT_INVALID(stage[0].cpu.aplist_count = 1024);
	EXPECT_INVALID(stage[1].cpu.aplist[0] = 27; stage[1].cpu.aplist_count = 1);
	EXPECT_INVALID(stage[0].cpu.private_irqs[3].config = 0);
	EXPECT_INVALID(stage[0].cpu.private_irqs[20].config = 2);
	EXPECT_INVALID(stage[0].cpu.private_irqs[20].target_vcpu = 2);
	EXPECT_INVALID(tx.dist.spis[10].config = 1);
	EXPECT_INVALID(tx.dist.spis[10].config = 3);
	EXPECT_INVALID(tx.dist.spis[10].flags = 0x20);
	EXPECT_INVALID(tx.dist.spis[10].mpidr = UINT64_C(1) << 24);
	EXPECT_INVALID(tx.dist.spis[10].target_vcpu = MAXV);
	EXPECT_INVALID(tx.dist.spis[10].target_vcpu = -2);
	EXPECT_INVALID(stage[2].cpu.ich_hcr = 3);
	EXPECT_INVALID(stage[2].cpu.ich_vmcr = UINT64_C(1) << 32);
	EXPECT_INVALID(stage[2].cpu.ich_vmcr = 0x100);
	EXPECT_INVALID(stage[2].cpu.ap0r[1] = 1);	/* beyond apr_num */
	EXPECT_INVALID(tx.dist.apr_num = 0);
	EXPECT_INVALID(tx.dist.apr_num = 5);
	EXPECT_INVALID(tx.dist.lr_num = 0);
	EXPECT_INVALID(tx.dist.lr_num = 17);
	EXPECT_INVALID(tx.dist.min_prio = 0x100);
	EXPECT_INVALID(tx.dist.gicd_ctlr = 1);
	EXPECT_INVALID(tx.dist.dist_size = 0);
	EXPECT_INVALID(tx.dist.dist_start = UINT64_MAX);
	EXPECT_INVALID(stage[2].instance = 2);		/* not increasing */
	EXPECT_INVALID(tx.vm.vcpu_count = 2);
	printf("%d vGIC semantic rejections checked\n", cases);
#undef EXPECT_INVALID
}

ATF_TC_WITHOUT_HEAD(vgic_malformed_wire);
ATF_TC_BODY(vgic_malformed_wire, tc)
{
	static struct vmm_snapshot_arm64_vgic_stage stage[NV], out[MAXV];
	static struct vmm_snapshot_arm64_vgic_transaction tx, decoded;
	uint8_t *wire;
	size_t length, cpu0, step;

	vgic_fixture(&tx, stage);
	length = vgic_encode(&tx, stage, &wire);
	step = length / 997 + 1;
	for (size_t cut = 0; cut < length; cut += step)
		ATF_REQUIRE(vmm_snapshot_arm64_vgic_decode(wire, cut, out, MAXV,
		    &decoded) != 0);
	ATF_REQUIRE(vmm_snapshot_arm64_vgic_decode(wire, length - 1, out, MAXV,
	    &decoded) != 0);
	/* Locate the first CPU payload and corrupt its alignment padding. */
	cpu0 = VMM_SNAPSHOT_ENVELOPE_HEADER_SIZE +
	    2 * VMM_SNAPSHOT_SECTION_HEADER_SIZE + VMM_SNAPSHOT_VM_COMMON_SIZE +
	    VMM_SNAPSHOT_ARM64_VGIC_DIST_SIZE + VMM_SNAPSHOT_SECTION_HEADER_SIZE;
	ATF_REQUIRE_EQ(le16dec(wire + cpu0 - VMM_SNAPSHOT_SECTION_HEADER_SIZE),
	    VMM_SNAPSHOT_SECTION_ARM64_VGIC_CPU);
	wire[cpu0 + VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE + 6] = 1;
	ATF_CHECK_EQ(vmm_snapshot_arm64_vgic_decode(wire, length, out, MAXV,
	    &decoded), EINVAL);
	wire[cpu0 + VMM_SNAPSHOT_ARM64_VGIC_CPU_FIXED_SIZE + 6] = 0;
	ATF_CHECK_EQ(vmm_snapshot_arm64_vgic_decode(wire, length, out, MAXV,
	    &decoded), 0);
	/* aplist_count that disagrees with the payload length. */
	le32enc(wire + cpu0 + 4, 4);
	ATF_CHECK_EQ(vmm_snapshot_arm64_vgic_decode(wire, length, out, MAXV,
	    &decoded), EINVAL);
	le32enc(wire + cpu0 + 4, 3);
	/* Reserved IRQ entry byte. */
	wire[cpu0 + VMM_SNAPSHOT_ARM64_VGIC_CPU_HEADER_SIZE + 15] = 1;
	ATF_CHECK_EQ(vmm_snapshot_arm64_vgic_decode(wire, length, out, MAXV,
	    &decoded), EINVAL);
	free(wire);
}

ATF_TC_WITHOUT_HEAD(vgic_mutation_sweep);
ATF_TC_BODY(vgic_mutation_sweep, tc)
{
	static struct vmm_snapshot_arm64_vgic_stage stage[NV];
	static struct vmm_snapshot_arm64_vgic_transaction tx;
	uint8_t *wire, *mutant;
	size_t length, pos;
	unsigned accepted, rejected;

	vgic_fixture(&tx, stage);
	length = vgic_encode(&tx, stage, &wire);
	mutant = malloc(length);
	ATF_REQUIRE(mutant != NULL);
	accepted = rejected = 0;
	for (unsigned iter = 0; iter < 20000; iter++) {
		memcpy(mutant, wire, length);
		pos = (iter & 1) ? rng() % 200 : rng() % length;
		mutant[pos] ^= (uint8_t)(1U << (rng() % 8));
		if (vgic_decode_canonical(mutant, length) == 0)
			accepted++;
		else
			rejected++;
	}
	printf("vgic mutations: %u accepted (canonical), %u rejected\n",
	    accepted, rejected);
	ATF_CHECK(rejected > 0);
	ATF_CHECK(accepted > 0);
	free(mutant);
	free(wire);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, vm_round_trip);
	ATF_TP_ADD_TC(tp, vm_field_validation);
	ATF_TP_ADD_TC(tp, vm_malformed_structure);
	ATF_TP_ADD_TC(tp, vm_mutation_sweep);
	ATF_TP_ADD_TC(tp, vgic_round_trip);
	ATF_TP_ADD_TC(tp, vgic_semantic_validation);
	ATF_TP_ADD_TC(tp, vgic_malformed_wire);
	ATF_TP_ADD_TC(tp, vgic_mutation_sweep);
	return (atf_no_error());
}
