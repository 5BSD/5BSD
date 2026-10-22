/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The 5BSD Project
 */

/*
 * Offline tests for the portable RISC-V checkpoint codec
 * (sys/riscv/vmm/vmm_snapshot_riscv.c).  Host-independent; no kernel adapter,
 * APLIC device or guest is exercised.
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
#include "../../../sys/riscv/vmm/vmm_snapshot_riscv.h"

#include "../../../sys/dev/vmm/vmm_snapshot_envelope.c"
#include "../../../sys/dev/vmm/vmm_snapshot_state.c"
#include "../../../sys/riscv/vmm/vmm_snapshot_riscv.c"

#define	MAXV	4
#define	NV	2

static uint64_t rng_state = 0x243f6a8885a308d3ULL;

static uint64_t
rng(void)
{

	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (rng_state * 0x2545f4914f6cdd1dULL);
}

static void
vm_fixture(struct vmm_snapshot_riscv_transaction *tx,
    struct vmm_snapshot_riscv_vcpu_stage *stage)
{
	static const uint32_t instances[NV] = { 1, 3 };

	memset(tx, 0, sizeof(*tx));
	memset(stage, 0, sizeof(*stage) * NV);
	tx->vm.max_vcpus = MAXV;
	tx->vm.vcpu_count = NV;
	tx->vcpu_count = NV;
	tx->riscv.timebase = 10000000;
	tx->riscv.capture_time = 0x1000000000ULL;
	for (int i = 0; i < NV; i++) {
		stage[i].instance = instances[i];
		for (int r = 0; r < VMM_SNAPSHOT_RISCV_REG_COUNT; r++)
			stage[i].vcpu.regs[r] = rng();
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] =
		    VMM_SNAPSHOT_RISCV_HSTATUS_SPV |
		    VMM_SNAPSHOT_RISCV_HSTATUS_VTW |
		    VMM_SNAPSHOT_RISCV_HSTATUS_SPVP |
		    (UINT64_C(2) << VMM_SNAPSHOT_RISCV_HSTATUS_VSXL_SHIFT);
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_SSTATUS] =
		    VMM_SNAPSHOT_RISCV_SSTATUS_SPP |
		    VMM_SNAPSHOT_RISCV_SSTATUS_SPIE |
		    (UINT64_C(1) << 13) |
		    (UINT64_C(2) << VMM_SNAPSHOT_RISCV_SSTATUS_UXL_SHIFT);
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_HVIP] =
		    VMM_SNAPSHOT_RISCV_HVIP_VSTIP;
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_SCOUNTEREN] = 3;
		stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_GUEST_SCOUNTEREN] = 3;
		stage[i].vcpu.flags = VMM_SNAPSHOT_RISCV_VCPU_F_TIMER_ARMED |
		    (i == 1 ? VMM_SNAPSHOT_RISCV_VCPU_F_IPI : 0);
		stage[i].common.next_pc =
		    stage[i].vcpu.regs[VMM_SNAPSHOT_RISCV_SEPC];
		for (int f = 0; f < 32; f++) {
			stage[i].fp.f[f][0] = rng();
			stage[i].fp.f[f][1] = rng();
		}
		stage[i].fp.fcsr = 0xe1;
	}
}

static size_t
vm_encode(const struct vmm_snapshot_riscv_transaction *tx,
    const struct vmm_snapshot_riscv_vcpu_stage *stage, uint8_t **wirep)
{
	size_t length, written;

	ATF_REQUIRE_EQ(vmm_snapshot_riscv_vm_size(tx->vcpu_count, &length), 0);
	*wirep = malloc(length);
	ATF_REQUIRE(*wirep != NULL);
	ATF_REQUIRE_EQ(vmm_snapshot_riscv_vm_encode(tx, stage, tx->vcpu_count,
	    *wirep, length, &written), 0);
	ATF_REQUIRE_EQ(written, length);
	return (written);
}

static int
vm_decode_canonical(const uint8_t *wire, size_t length)
{
	struct vmm_snapshot_riscv_vcpu_stage stage[MAXV];
	struct vmm_snapshot_riscv_transaction tx;
	uint8_t *again;
	size_t written;
	int error;

	error = vmm_snapshot_riscv_vm_decode(wire, length, stage, MAXV, &tx);
	if (error != 0)
		return (error);
	written = vm_encode(&tx, stage, &again);
	if (written == length)
		ATF_REQUIRE_EQ(memcmp(again, wire, length), 0);
	free(again);
	return (0);
}

ATF_TC_WITHOUT_HEAD(vm_round_trip);
ATF_TC_BODY(vm_round_trip, tc)
{
	struct vmm_snapshot_riscv_vcpu_stage stage[NV], out[MAXV];
	struct vmm_snapshot_riscv_transaction tx, decoded;
	uint8_t *wire;
	size_t length;

	vm_fixture(&tx, stage);
	length = vm_encode(&tx, stage, &wire);
	ATF_REQUIRE_EQ(vmm_snapshot_riscv_vm_decode(wire, length, out, MAXV,
	    &decoded), 0);
	ATF_CHECK_EQ(decoded.vcpu_count, NV);
	ATF_CHECK_EQ(decoded.riscv.timebase, tx.riscv.timebase);
	ATF_CHECK_EQ(decoded.riscv.capture_time, tx.riscv.capture_time);
	for (int i = 0; i < NV; i++) {
		ATF_CHECK_EQ(out[i].instance, stage[i].instance);
		ATF_CHECK_EQ(memcmp(&out[i].vcpu, &stage[i].vcpu,
		    sizeof(out[i].vcpu)), 0);
		ATF_CHECK_EQ(memcmp(&out[i].fp, &stage[i].fp,
		    sizeof(out[i].fp)), 0);
	}
	ATF_CHECK_EQ(vm_decode_canonical(wire, length), 0);
	for (size_t cut = 0; cut < length; cut++)
		ATF_REQUIRE(vmm_snapshot_riscv_vm_decode(wire, cut, out, MAXV,
		    &decoded) != 0);
	free(wire);
}

ATF_TC_WITHOUT_HEAD(vm_field_validation);
ATF_TC_BODY(vm_field_validation, tc)
{
	struct vmm_snapshot_riscv_vcpu_stage stage[NV];
	struct vmm_snapshot_riscv_transaction tx;
	uint8_t wire[8192];
	size_t written;
	int cases;

#define	EXPECT_INVALID(mutation) do {					\
	vm_fixture(&tx, stage);						\
	mutation;							\
	ATF_CHECK_EQ_MSG(vmm_snapshot_riscv_vm_encode(&tx, stage, NV, wire, \
	    sizeof(wire), &written), EINVAL, "%s", #mutation);		\
	cases++;							\
} while (0)

	cases = 0;
	vm_fixture(&tx, stage);
	ATF_REQUIRE_EQ(vmm_snapshot_riscv_vm_encode(&tx, stage, NV, wire,
	    sizeof(wire), &written), 0);
	/* hstatus policy: required, forbidden and VSXL encodings. */
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] &=
	    ~VMM_SNAPSHOT_RISCV_HSTATUS_SPV);
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] &=
	    ~VMM_SNAPSHOT_RISCV_HSTATUS_VTW);
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(1) << 9);		/* HU */
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(1) << 22);		/* VTSR */
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(1) << 20);		/* VTVM */
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(5) << 12);		/* VGEIN */
	EXPECT_INVALID(stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(1) << 5);		/* VSBE */
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_HSTATUS] |=
	    UINT64_C(1) << 32);		/* VSXL = 3 */
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_SSTATUS] |=
	    UINT64_C(1) << 3);		/* MIE is not an S-mode bit */
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_SSTATUS] |=
	    UINT64_C(1) << 32);		/* UXL = 3 */
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_HVIP] |= 1);
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_SCOUNTEREN] =
	    UINT64_C(1) << 32);
	EXPECT_INVALID(stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_GUEST_SCOUNTEREN] =
	    UINT64_C(1) << 40);
	EXPECT_INVALID(stage[1].vcpu.flags = 0x10);
	EXPECT_INVALID(stage[1].vcpu.flags = 0;
	    stage[1].vcpu.regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE] = 1);
	EXPECT_INVALID(stage[0].fp.fcsr = 0x100);
	EXPECT_INVALID(stage[0].common.next_pc ^= 2);
	EXPECT_INVALID(stage[0].common.flags = 1);
	EXPECT_INVALID(stage[1].instance = MAXV);
	EXPECT_INVALID(stage[1].instance = 1);
	EXPECT_INVALID(tx.riscv.timebase = 0);
	EXPECT_INVALID(tx.riscv.flags = 2);
	EXPECT_INVALID(tx.vm.vcpu_count = 1);
	printf("%d RISC-V vCPU rejections checked\n", cases);
#undef EXPECT_INVALID
	/* An unarmed timer with a zero deadline is valid. */
	vm_fixture(&tx, stage);
	stage[0].vcpu.flags = 0;
	stage[0].vcpu.regs[VMM_SNAPSHOT_RISCV_TIMER_DEADLINE] = 0;
	ATF_CHECK_EQ(vmm_snapshot_riscv_vm_encode(&tx, stage, NV, wire,
	    sizeof(wire), &written), 0);
}

ATF_TC_WITHOUT_HEAD(vm_mutation_sweep);
ATF_TC_BODY(vm_mutation_sweep, tc)
{
	struct vmm_snapshot_riscv_vcpu_stage stage[NV];
	struct vmm_snapshot_riscv_transaction tx;
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
		pos = (iter & 1) ? rng() % 160 : rng() % length;
		mutant[pos] ^= (uint8_t)(1U << (rng() % 8));
		if ((iter % 5) == 0)
			mutant[rng() % length] = (uint8_t)rng();
		if (vm_decode_canonical(mutant, length) == 0)
			accepted++;
		else
			rejected++;
	}
	printf("riscv vm mutations: %u accepted (canonical), %u rejected\n",
	    accepted, rejected);
	ATF_CHECK(accepted > 0 && rejected > 0);
	free(mutant);
	free(wire);
}

static void
aplic_fixture(struct vmm_snapshot_riscv_aplic *a)
{

	memset(a, 0, sizeof(*a));
	a->vm.max_vcpus = MAXV;
	a->vm.vcpu_count = NV;
	a->mem_start = 0x2f000000;
	a->mem_size = 0x8000;
	a->domaincfg = VMM_SNAPSHOT_RISCV_APLIC_DOMAINCFG_IE;
	a->nirqs = VMM_SNAPSHOT_RISCV_APLIC_NIRQS;
	for (uint32_t i = 1; i < VMM_SNAPSHOT_RISCV_APLIC_SLOTS; i++) {
		a->sources[i].sourcecfg = (i % 3 == 0) ? 6 : 0;
		a->sources[i].state = i % 8;
		a->sources[i].target = (i % MAXV) << 18 | (i & 0xff);
	}
	/* Slot 63 is now addressable (the out-of-bounds slot before). */
	a->sources[63].sourcecfg = 4;
	a->sources[5].sourcecfg = VMM_SNAPSHOT_RISCV_APLIC_SOURCECFG_D | 7;
}

static size_t
aplic_encode(const struct vmm_snapshot_riscv_aplic *a, uint8_t *wire,
    size_t capacity)
{
	size_t written;

	ATF_REQUIRE_EQ(vmm_snapshot_riscv_aplic_encode(a, wire, capacity,
	    &written), 0);
	return (written);
}

ATF_TC_WITHOUT_HEAD(aplic_round_trip_and_validation);
ATF_TC_BODY(aplic_round_trip_and_validation, tc)
{
	struct vmm_snapshot_riscv_aplic a, out;
	uint8_t wire[2048];
	size_t length, bound, written;
	int cases;

	ATF_REQUIRE_EQ(vmm_snapshot_riscv_aplic_size(&bound), 0);
	ATF_REQUIRE(bound <= sizeof(wire));
	aplic_fixture(&a);
	length = aplic_encode(&a, wire, sizeof(wire));
	ATF_CHECK_EQ(length, bound);
	ATF_REQUIRE_EQ(vmm_snapshot_riscv_aplic_decode(wire, length, &out), 0);
	ATF_CHECK_EQ(memcmp(&out, &a, sizeof(a)), 0);
	for (size_t cut = 0; cut < length; cut++)
		ATF_REQUIRE(vmm_snapshot_riscv_aplic_decode(wire, cut, &out) != 0);

#define	EXPECT_INVALID(mutation) do {					\
	aplic_fixture(&a);						\
	mutation;							\
	ATF_CHECK_EQ_MSG(vmm_snapshot_riscv_aplic_encode(&a, wire,	\
	    sizeof(wire), &written), EINVAL, "%s", #mutation);		\
	cases++;							\
} while (0)

	cases = 0;
	EXPECT_INVALID(a.domaincfg |= 4);		/* DM */
	EXPECT_INVALID(a.domaincfg |= 1);		/* BE */
	EXPECT_INVALID(a.sources[0].sourcecfg = 6);
	EXPECT_INVALID(a.sources[0].target = 1);
	EXPECT_INVALID(a.sources[7].sourcecfg = 2);	/* reserved */
	EXPECT_INVALID(a.sources[7].sourcecfg = 3);	/* reserved */
	EXPECT_INVALID(a.sources[7].sourcecfg = 8);
	EXPECT_INVALID(a.sources[5].sourcecfg |= 0x800);
	EXPECT_INVALID(a.sources[9].state = 8);
	EXPECT_INVALID(a.nirqs = 64);
	EXPECT_INVALID(a.mem_size = 0);
	EXPECT_INVALID(a.mem_start = UINT64_MAX);
	EXPECT_INVALID(a.vm.vcpu_count = MAXV + 1);
	printf("%d APLIC rejections checked\n", cases);
#undef EXPECT_INVALID

	/* Wire-level: reserved entry word, critical unknown section. */
	aplic_fixture(&a);
	length = aplic_encode(&a, wire, sizeof(wire));
	wire[length - 1] = 1;
	ATF_CHECK_EQ(vmm_snapshot_riscv_aplic_decode(wire, length, &out),
	    EINVAL);
}

ATF_TC_WITHOUT_HEAD(aplic_mutation_sweep);
ATF_TC_BODY(aplic_mutation_sweep, tc)
{
	struct vmm_snapshot_riscv_aplic a, out;
	uint8_t wire[2048], mutant[2048], again[2048];
	size_t length, written;
	unsigned accepted, rejected;

	aplic_fixture(&a);
	length = aplic_encode(&a, wire, sizeof(wire));
	accepted = rejected = 0;
	for (unsigned iter = 0; iter < 30000; iter++) {
		memcpy(mutant, wire, length);
		mutant[rng() % length] ^= (uint8_t)(1U << (rng() % 8));
		if (vmm_snapshot_riscv_aplic_decode(mutant, length, &out) != 0) {
			rejected++;
			continue;
		}
		accepted++;
		ATF_REQUIRE_EQ(vmm_snapshot_riscv_aplic_encode(&out, again,
		    sizeof(again), &written), 0);
		ATF_REQUIRE_EQ(written, length);
		ATF_REQUIRE_EQ(memcmp(again, mutant, length), 0);
	}
	printf("aplic mutations: %u accepted (canonical), %u rejected\n",
	    accepted, rejected);
	ATF_CHECK(accepted > 0 && rejected > 0);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, vm_round_trip);
	ATF_TP_ADD_TC(tp, vm_field_validation);
	ATF_TP_ADD_TC(tp, vm_mutation_sweep);
	ATF_TP_ADD_TC(tp, aplic_round_trip_and_validation);
	ATF_TP_ADD_TC(tp, aplic_mutation_sweep);
	return (atf_no_error());
}
