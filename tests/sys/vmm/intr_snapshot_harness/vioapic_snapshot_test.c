/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Model tests for the STRUCT_VIOAPIC snapshot codec: the guest-writable
 * 'id' register must round-trip, records predating the 'id' field must be
 * rejected outright (current-only unreleased-format policy), and restore
 * must validate that 'id' only carries architecturally writable bits.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/_cpuset.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <atf-c.h>

#include <machine/vmm.h>
#include <machine/vmm_snapshot.h>
#include <dev/vmm/vmm_vm.h>

/* Stub surface required by vioapic.c. */
static struct vioapic *kmock_vioapic;
static u_int kmock_deliveries;

struct vioapic *
vm_ioapic(struct vm *vm __unused)
{

	return (kmock_vioapic);
}

struct vm *
vcpu_vm(struct vcpu *vcpu __unused)
{

	return (NULL);
}

struct vlapic *
vm_lapic(struct vcpu *vcpu __unused)
{

	return (NULL);
}

void
vlapic_deliver_intr(struct vm *vm __unused, bool level __unused,
    uint32_t dest __unused, bool phys __unused, int delmode __unused,
    int vec __unused)
{

	kmock_deliveries++;
}

void
vlapic_reset_tmr(struct vlapic *vlapic __unused)
{
}

void
vlapic_set_tmr_level(struct vlapic *vlapic __unused, uint32_t dest __unused,
    bool phys __unused, int delmode __unused, int vector __unused)
{
}

cpuset_t
vm_active_cpus(struct vm *vm __unused)
{
	cpuset_t s;

	memset(&s, 0, sizeof(s));
	return (s);
}

int
vm_smp_rendezvous(struct vcpu *vcpu __unused, cpuset_t dest __unused,
    vm_rendezvous_func_t func __unused, void *arg __unused)
{

	return (0);
}

/* Userspace implementation of the snapshot buffer cursor. */
int
vm_snapshot_buf(void *data, size_t data_size, struct vm_snapshot_meta *meta)
{
	struct vm_snapshot_buffer *buffer;

	buffer = &meta->buffer;
	if (buffer->buf_rem < data_size)
		return (E2BIG);
	if (meta->op == VM_SNAPSHOT_SAVE)
		memcpy(buffer->buf, data, data_size);
	else if (meta->op == VM_SNAPSHOT_RESTORE)
		memcpy(data, buffer->buf, data_size);
	else
		return (EINVAL);
	buffer->buf += data_size;
	buffer->buf_rem -= data_size;
	return (0);
}

void
vm_snapshot_buf_err(const char *bufname __unused,
    const enum vm_snapshot_op op __unused)
{
}

#include "../../../../sys/amd64/vmm/io/vioapic.c"

/*
 * Exact wire size: ioregsel(4) + 32 * (reg(8) + acnt(4)) + id(4) = 392.
 * The id field is appended after the historical fields, so a pre-id record
 * is exactly the first 388 bytes.
 */
#define	VIOAPIC_RECORD_SIZE	392
#define	VIOAPIC_ID_OFF		388

static void
ioapic_reg_write(uint32_t regnum, uint32_t val)
{

	ATF_REQUIRE_EQ(0, vioapic_mmio_write(NULL, VIOAPIC_BASE + IOREGSEL,
	    regnum, 4, NULL));
	ATF_REQUIRE_EQ(0, vioapic_mmio_write(NULL, VIOAPIC_BASE + IOWIN,
	    val, 4, NULL));
}

static uint32_t
ioapic_reg_read(uint32_t regnum)
{
	uint64_t rval;

	ATF_REQUIRE_EQ(0, vioapic_mmio_write(NULL, VIOAPIC_BASE + IOREGSEL,
	    regnum, 4, NULL));
	rval = ~(uint64_t)0;
	ATF_REQUIRE_EQ(0, vioapic_mmio_read(NULL, VIOAPIC_BASE + IOWIN,
	    &rval, 4, NULL));
	return ((uint32_t)rval);
}

static int
do_snapshot(struct vioapic *vioapic, enum vm_snapshot_op op, uint8_t *buf,
    size_t len, size_t *consumed)
{
	struct vm_snapshot_meta meta = {
		.dev_name = "vioapic",
		.dev_req = STRUCT_VIOAPIC,
		.buffer = {
			.buf_start = buf,
			.buf_size = len,
			.buf = buf,
			.buf_rem = len,
		},
		.op = op,
	};
	int ret;

	ret = vioapic_snapshot(vioapic, &meta);
	if (consumed != NULL)
		*consumed = len - meta.buffer.buf_rem;
	return (ret);
}

ATF_TC_WITHOUT_HEAD(id_round_trip);
ATF_TC_BODY(id_round_trip, tc)
{
	struct vioapic *src, *dst;
	uint8_t buf[1024];
	size_t consumed;
	uint32_t rtbl_lo;

	src = vioapic_init(NULL);
	kmock_vioapic = src;
	/* The guest writes its APIC id; only bits 27:24 are writable. */
	ioapic_reg_write(IOAPIC_ID, 0x0b000000);
	ATF_REQUIRE_EQ(0x0b000000, ioapic_reg_read(IOAPIC_ID));
	/* Program pin 4: unmasked, edge, vector 0x66. */
	rtbl_lo = 0x66;
	ioapic_reg_write(IOAPIC_REDTBL + 2 * 4, rtbl_lo);
	/* Assert pin 5 (still masked) so acnt is nonzero. */
	ATF_REQUIRE_EQ(0, vioapic_assert_irq(NULL, 5));
	ATF_REQUIRE_EQ(1, src->rtbl[5].acnt);

	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(VIOAPIC_RECORD_SIZE, consumed);

	dst = vioapic_init(NULL);
	kmock_vioapic = dst;
	ATF_REQUIRE_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VIOAPIC_RECORD_SIZE, NULL));

	ATF_CHECK_EQ(0x0b000000, dst->id);
	ATF_CHECK_EQ(0x0b000000, ioapic_reg_read(IOAPIC_ID));
	ATF_CHECK_EQ(rtbl_lo, (uint32_t)dst->rtbl[4].reg);
	ATF_CHECK_EQ(1, dst->rtbl[5].acnt);

	vioapic_cleanup(dst);
	kmock_vioapic = src;
	vioapic_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(pre_id_record_rejected);
ATF_TC_BODY(pre_id_record_rejected, tc)
{
	struct vioapic *src, *dst;
	uint8_t buf[1024];
	size_t consumed;

	src = vioapic_init(NULL);
	kmock_vioapic = src;
	ioapic_reg_write(IOAPIC_ID, 0x0b000000);
	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(VIOAPIC_RECORD_SIZE, consumed);

	/*
	 * A development record written before 'id' was appended is exactly
	 * four bytes shorter.  There is no compatibility reader: it must be
	 * rejected before any destination state is published.
	 */
	dst = vioapic_init(NULL);
	kmock_vioapic = dst;
	ioapic_reg_write(IOAPIC_ID, 0x05000000);
	ATF_CHECK_EQ(E2BIG, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VIOAPIC_RECORD_SIZE - 4, NULL));
	ATF_CHECK_EQ(0x05000000, dst->id);
	/* Redirection entries keep their reset value. */
	ATF_CHECK_EQ(0x0001000000010000UL, dst->rtbl[4].reg);

	vioapic_cleanup(dst);
	kmock_vioapic = src;
	vioapic_cleanup(src);
}

ATF_TC_WITHOUT_HEAD(id_validation);
ATF_TC_BODY(id_validation, tc)
{
	struct vioapic *src, *dst;
	uint8_t buf[1024];
	uint32_t bad_id, max_id;
	size_t consumed;

	src = vioapic_init(NULL);
	kmock_vioapic = src;
	ioapic_reg_write(IOAPIC_ID, 0x01000000);
	ATF_REQUIRE_EQ(0, do_snapshot(src, VM_SNAPSHOT_SAVE, buf, sizeof(buf),
	    &consumed));
	ATF_REQUIRE_EQ(VIOAPIC_RECORD_SIZE, consumed);

	/* Bits outside APIC_ID_MASK can never be latched by the guest. */
	bad_id = 0x00000001;
	memcpy(buf + VIOAPIC_ID_OFF, &bad_id, sizeof(bad_id));
	dst = vioapic_init(NULL);
	kmock_vioapic = dst;
	ATF_CHECK_EQ(EINVAL, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VIOAPIC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(0, dst->id);

	/* Every value inside the mask is acceptable. */
	max_id = 0xff000000;
	memcpy(buf + VIOAPIC_ID_OFF, &max_id, sizeof(max_id));
	ATF_CHECK_EQ(0, do_snapshot(dst, VM_SNAPSHOT_RESTORE, buf,
	    VIOAPIC_RECORD_SIZE, NULL));
	ATF_CHECK_EQ(max_id, dst->id);

	vioapic_cleanup(dst);
	kmock_vioapic = src;
	vioapic_cleanup(src);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, id_round_trip);
	ATF_TP_ADD_TC(tp, pre_id_record_rejected);
	ATF_TP_ADD_TC(tp, id_validation);
	return (atf_no_error());
}
