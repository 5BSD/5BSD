/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ACPI state a bhyve checkpoint restore or live migration presents to the
 * guest, against the real amd64/pm.c and vmgenc.c: the ACPI event registers
 * (with the SIGTERM power button that ACPI enable registers) and the VM
 * generation ID with its GPE notification.  Interrupt and event-loop calls
 * are recorded by the stubs below.
 */

#include <sys/param.h>

#include <atf-c.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

#ifndef BHYVE_SNAPSHOT
#define	BHYVE_SNAPSHOT	1
#endif

#include "amd64/pm.c"
#include "vmgenc.c"

static struct vmctx *const test_ctx = (struct vmctx *)(uintptr_t)0x1000;
static int sci_level, sci_asserts;
static int mevent_adds, mevent_deletes;

struct mevent {
	int	fd;
	enum ev_type type;
	void	(*cb)(int, enum ev_type, void *);
	void	*arg;
};
static struct mevent sigterm_event;

int
vm_isa_assert_irq(struct vmctx *ctx __unused, int atpic_irq,
    int ioapic_irq __unused)
{
	ATF_REQUIRE_EQ(atpic_irq, SCI_INT);
	sci_level = 1;
	sci_asserts++;
	return (0);
}

int
vm_isa_deassert_irq(struct vmctx *ctx __unused, int atpic_irq,
    int ioapic_irq __unused)
{
	ATF_REQUIRE_EQ(atpic_irq, SCI_INT);
	sci_level = 0;
	return (0);
}

int
vm_isa_set_irq_trigger(struct vmctx *ctx __unused, int atpic_irq __unused,
    enum vm_intr_trigger trigger __unused)
{
	return (0);
}

int
vm_suspend(struct vmctx *ctx __unused, enum vm_suspend_how how __unused)
{
	return (0);
}

void
pci_irq_use(int irq __unused)
{
}

struct mevent *
mevent_add(int fd, enum ev_type type,
    void (*cb)(int, enum ev_type, void *), void *arg)
{
	ATF_REQUIRE(sigterm_event.cb == NULL);
	sigterm_event = (struct mevent){ fd, type, cb, arg };
	mevent_adds++;
	return (&sigterm_event);
}

int
mevent_delete(struct mevent *evp)
{
	ATF_REQUIRE(evp == &sigterm_event);
	memset(&sigterm_event, 0, sizeof(sigterm_event));
	mevent_deletes++;
	return (0);
}

static char rom_page[PAGE_SIZE];

int
bootrom_alloc(struct vmctx *ctx __unused, size_t len, int prot __unused,
    int flags __unused, char **region_out, uint64_t *gpa_out)
{
	ATF_REQUIRE(len <= sizeof(rom_page));
	*region_out = rom_page;
	*gpa_out = 0xfffff000;
	return (0);
}

void
dsdt_line(const char *fmt __unused, ...)
{
}

void
dsdt_indent(int levels __unused)
{
}

void
dsdt_unindent(int levels __unused)
{
}

static const struct checkpoint_acpi_pm guest_pm = {
	/* OSPM enabled ACPI, the power button and the generation GPE. */
	.pm1_enable = PM1_PWRBTN_EN | PM1_GBL_EN,
	.pm1_control = PM1_SCI_EN,
	.gpe0_enable = 1u << GPE_VMGENC,
};

/* A fresh destination process: power-on register values, no event. */
static void
destination_reset(void)
{
	static const struct checkpoint_acpi_pm reset;

	acpi_pm_state_set(test_ctx, &reset);
	ATF_REQUIRE(power_button == NULL);
	sci_level = sci_asserts = 0;
	mevent_adds = mevent_deletes = 0;
}

static sig_t
sigterm_disposition(void)
{
	struct sigaction sa;

	ATF_REQUIRE_EQ(sigaction(SIGTERM, NULL, &sa), 0);
	return (sa.sa_handler);
}

ATF_TC_WITHOUT_HEAD(restore_acpi_enabled_keeps_power_button);
ATF_TC_BODY(restore_acpi_enabled_keeps_power_button, tc)
{
	struct checkpoint_acpi_pm pm;

	destination_reset();
	acpi_pm_state_set(test_ctx, &guest_pm);
	/* SIGTERM is the power button, as after the guest's ACPI enable. */
	ATF_REQUIRE_EQ(mevent_adds, 1);
	ATF_CHECK_EQ(sigterm_event.fd, SIGTERM);
	ATF_CHECK_EQ(sigterm_event.type, EVF_SIGNAL);
	ATF_CHECK(sigterm_event.cb == power_button_handler);
	ATF_CHECK(sigterm_disposition() == SIG_IGN);
	ATF_CHECK_EQ(sci_level, 0);

	sigterm_event.cb(SIGTERM, EVF_SIGNAL, sigterm_event.arg);
	acpi_pm_state_get(&pm);
	ATF_CHECK((pm.pm1_status & PM1_PWRBTN_STS) != 0);
	ATF_CHECK(pm.sci_active);
	ATF_CHECK_EQ(sci_level, 1);

	/* Restoring again (e.g. a retried commit) registers it once. */
	acpi_pm_state_set(test_ctx, &pm);
	ATF_CHECK_EQ(mevent_adds, 1);
	ATF_CHECK_EQ(mevent_deletes, 0);

	destination_reset();
	ATF_CHECK(sigterm_disposition() == SIG_DFL);
}

ATF_TC_WITHOUT_HEAD(restore_acpi_disabled_leaves_sigterm);
ATF_TC_BODY(restore_acpi_disabled_leaves_sigterm, tc)
{
	struct checkpoint_acpi_pm pm;

	destination_reset();
	pm = guest_pm;
	pm.pm1_control = 0;
	acpi_pm_state_set(test_ctx, &pm);
	ATF_CHECK_EQ(mevent_adds, 0);
	ATF_CHECK(power_button == NULL);
	ATF_CHECK(sigterm_disposition() == SIG_DFL);

	/* A guest that disables ACPI after a restore gives SIGTERM back. */
	acpi_pm_state_set(test_ctx, &guest_pm);
	smi_cmd_handler(test_ctx, 0, SMI_CMD, 1,
	    &(uint32_t){ BHYVE_ACPI_DISABLE }, NULL);
	ATF_CHECK_EQ(mevent_deletes, 1);
	ATF_CHECK(power_button == NULL);
	ATF_CHECK(sigterm_disposition() == SIG_DFL);
}

ATF_TC_WITHOUT_HEAD(restore_vmgenid_notifies_guest);
ATF_TC_BODY(restore_vmgenid_notifies_guest, tc)
{
	uint8_t boot[VMGENC_ID_SIZE], next[VMGENC_ID_SIZE], seen[VMGENC_ID_SIZE];
	struct checkpoint_acpi_pm pm;

	destination_reset();
	vmgenc_init(test_ctx);
	ATF_REQUIRE_EQ(vmgenc_get_id(boot), 0);
	ATF_CHECK(memcmp(rom_page, boot, sizeof(boot)) == 0);

	/* Live migration: the source's ID, no GPE. */
	memset(next, 0xa5, sizeof(next));
	acpi_pm_state_set(test_ctx, &guest_pm);
	vmgenc_set_id(test_ctx, next, false);
	ATF_REQUIRE_EQ(vmgenc_get_id(seen), 0);
	ATF_CHECK(memcmp(seen, next, sizeof(next)) == 0);
	acpi_pm_state_get(&pm);
	ATF_CHECK_EQ(pm.gpe0_status, 0);
	ATF_CHECK_EQ(sci_asserts, 0);

	/* Checkpoint restore: a new ID and the GPE behind Notify(0x80). */
	memset(next, 0x5a, sizeof(next));
	vmgenc_set_id(test_ctx, next, true);
	ATF_REQUIRE_EQ(vmgenc_get_id(seen), 0);
	ATF_CHECK(memcmp(seen, next, sizeof(next)) == 0);
	acpi_pm_state_get(&pm);
	ATF_CHECK_EQ(pm.gpe0_status, 1u << GPE_VMGENC);
	ATF_CHECK_EQ(sci_asserts, 1);
	ATF_CHECK_EQ(sci_level, 1);

	/* Without the guest's GPE enable the raise asserts no SCI. */
	destination_reset();
	vmgenc_set_id(test_ctx, boot, true);
	ATF_CHECK_EQ(sci_asserts, 0);
	destination_reset();
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, restore_acpi_enabled_keeps_power_button);
	ATF_TP_ADD_TC(tp, restore_acpi_disabled_leaves_sigterm);
	ATF_TP_ADD_TC(tp, restore_vmgenid_notifies_guest);
	return (atf_no_error());
}
