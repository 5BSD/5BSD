#include <sys/types.h>

#include <errno.h>
#include <string.h>

#include <atf-c.h>

#include <bhyve/pci_emul.h>

static int pause_calls;
static int pause_error;
static int resume_calls;
static int resume_error;
static int bar_visits;
static int validate_cleanup_calls;
static int bar_visit_idx[PCI_BARMAX_WITH_ROM + 1];
static bool bar_visit_registration[PCI_BARMAX_WITH_ROM + 1];

struct bar_registration_fixture {
	uint32_t registered;
	int calls;
	int fail_call;
	int rollback_fail_call;
	int indices[2 * (PCI_BARMAX_WITH_ROM + 1)];
	bool registrations[2 * (PCI_BARMAX_WITH_ROM + 1)];
};

static int
bar_registration_op(void *arg, int idx, bool registration)
{
	struct bar_registration_fixture *fixture;
	uint32_t bit;

	fixture = arg;
	ATF_REQUIRE(fixture->calls <
	    (int)(sizeof(fixture->indices) / sizeof(fixture->indices[0])));
	fixture->indices[fixture->calls] = idx;
	fixture->registrations[fixture->calls] = registration;
	fixture->calls++;
	if (fixture->calls == fixture->fail_call)
		return (EIO);
	if (fixture->calls == fixture->rollback_fail_call)
		return (EBUSY);
	bit = UINT32_C(1) << idx;
	if (registration)
		fixture->registered |= bit;
	else
		fixture->registered &= ~bit;
	return (0);
}

static int
test_pause(struct pci_devinst *pi __unused)
{

	pause_calls++;
	return (pause_error);
}

static int
test_resume(struct pci_devinst *pi __unused)
{

	resume_calls++;
	return (resume_error);
}

static void
reset_test_state(struct pci_devinst *pi, struct pci_devemu *pde)
{

	memset(pi, 0, sizeof(*pi));
	memset(pde, 0, sizeof(*pde));
	pi->pi_d = pde;
	pause_calls = 0;
	pause_error = 0;
	resume_calls = 0;
	resume_error = 0;
	bar_visits = 0;
	validate_cleanup_calls = 0;
}

static void
test_validate_cleanup(struct pci_devinst *pi __unused)
{

	validate_cleanup_calls++;
}

static void
visit_bar(struct pci_devinst *pi __unused, int idx, bool registration,
    void *arg __unused)
{

	ATF_REQUIRE(bar_visits <
	    (int)(sizeof(bar_visit_idx) / sizeof(bar_visit_idx[0])));
	bar_visit_idx[bar_visits] = idx;
	bar_visit_registration[bar_visits] = registration;
	bar_visits++;
}

ATF_TC_WITHOUT_HEAD(checkpoint_pause_ownership);
ATF_TC_BODY(checkpoint_pause_ownership, tc)
{
	struct pci_devinst pi;
	struct pci_devemu pde;

	reset_test_state(&pi, &pde);
	ATF_CHECK_EQ(pci_checkpoint_pause(&pi), 0);
	ATF_CHECK_EQ(pci_checkpoint_resume(&pi), 0);
	ATF_CHECK(!pi.pi_checkpoint_paused);

	pde.pe_pause = test_pause;
	ATF_CHECK_EQ(pci_checkpoint_pause(&pi), ENOTSUP);
	ATF_CHECK_EQ(pause_calls, 0);
	pde.pe_resume = test_resume;

	ATF_CHECK_EQ(pci_checkpoint_pause(&pi), 0);
	ATF_CHECK(pi.pi_checkpoint_paused);
	ATF_CHECK_EQ(pause_calls, 1);
	ATF_CHECK_EQ(pci_checkpoint_pause(&pi), 0);
	ATF_CHECK_EQ(pause_calls, 1);

	resume_error = EIO;
	ATF_CHECK_EQ(pci_checkpoint_resume(&pi), EIO);
	ATF_CHECK(pi.pi_checkpoint_paused);
	ATF_CHECK_EQ(resume_calls, 1);
	resume_error = 0;
	ATF_CHECK_EQ(pci_checkpoint_resume(&pi), 0);
	ATF_CHECK(!pi.pi_checkpoint_paused);
	ATF_CHECK_EQ(resume_calls, 2);
	ATF_CHECK_EQ(pci_checkpoint_resume(&pi), 0);
	ATF_CHECK_EQ(resume_calls, 2);

	pause_error = EBUSY;
	ATF_CHECK_EQ(pci_checkpoint_pause(&pi), EBUSY);
	ATF_CHECK(!pi.pi_checkpoint_paused);
	ATF_CHECK_EQ(pause_calls, 2);
	ATF_CHECK_EQ(pci_checkpoint_resume(&pi), 0);
	ATF_CHECK_EQ(resume_calls, 2);
}

ATF_TC_WITHOUT_HEAD(msi_control_normalization);
ATF_TC_BODY(msi_control_normalization, tc)
{
	uint16_t advertised, requested, normalized;

	/* Four vectors are capable; a request for 128 must clamp to four. */
	advertised = PCIM_MSICTRL_64BIT | (2U << 1);
	requested = UINT16_MAX;
	normalized = pci_msi_normalize_msgctrl(advertised, requested);
	ATF_CHECK_EQ(normalized & PCIM_MSICTRL_MMC_MASK,
	    advertised & PCIM_MSICTRL_MMC_MASK);
	ATF_CHECK_EQ((normalized & PCIM_MSICTRL_MME_MASK) >> 4, 2U);
	ATF_CHECK((normalized & PCIM_MSICTRL_MSI_ENABLE) != 0);
	ATF_CHECK_EQ(normalized & ~(PCIM_MSICTRL_MME_MASK |
	    PCIM_MSICTRL_MSI_ENABLE), advertised &
	    ~(PCIM_MSICTRL_MME_MASK | PCIM_MSICTRL_MSI_ENABLE));

	/* A legal narrower request remains unchanged. */
	requested = PCIM_MSICTRL_MSI_ENABLE | (1U << 4);
	normalized = pci_msi_normalize_msgctrl(advertised, requested);
	ATF_CHECK_EQ((normalized & PCIM_MSICTRL_MME_MASK) >> 4, 1U);
}

ATF_TC_WITHOUT_HEAD(checkpoint_restores_decoded_bars);
ATF_TC_BODY(checkpoint_restores_decoded_bars, tc)
{
	struct pci_devinst pi;
	struct pci_devemu pde;

	reset_test_state(&pi, &pde);
	pi.pi_bar[0].type = PCIBAR_IO;
	pi.pi_bar[1].type = PCIBAR_MEM32;
	pi.pi_bar[2].type = PCIBAR_MEM64;
	pi.pi_bar[3].type = PCIBAR_MEMHI64;
	pi.pi_bar[PCI_ROM_IDX].type = PCIBAR_ROM;
	pi.pi_bar[PCI_ROM_IDX].lobits = PCIM_BIOS_ENABLE;

	/* Disabled command decoding must not publish any intercept. */
	pci_snapshot_visit_decoded_bars(&pi, true, visit_bar, NULL);
	ATF_CHECK_EQ(bar_visits, 0);

	pi.pi_cfgdata[PCIR_COMMAND] =
	    PCIM_CMD_PORTEN | PCIM_CMD_MEMEN;
	pci_snapshot_visit_decoded_bars(&pi, true, visit_bar, NULL);
	ATF_REQUIRE_EQ(bar_visits, 4);
	ATF_CHECK_EQ(bar_visit_idx[0], 0);
	ATF_CHECK_EQ(bar_visit_idx[1], 1);
	ATF_CHECK_EQ(bar_visit_idx[2], 2);
	ATF_CHECK_EQ(bar_visit_idx[3], PCI_ROM_IDX);
	for (int i = 0; i < bar_visits; i++)
		ATF_CHECK(bar_visit_registration[i]);

	bar_visits = 0;
	pci_snapshot_visit_decoded_bars(&pi, false, visit_bar, NULL);
	ATF_REQUIRE_EQ(bar_visits, 4);
	for (int i = 0; i < bar_visits; i++)
		ATF_CHECK(!bar_visit_registration[i]);

	/* The high half of a 64-bit BAR is never independently registered. */
	ATF_CHECK(!pci_snapshot_bar_decoded(&pi, 3));
	pi.pi_bar[PCI_ROM_IDX].lobits = 0;
	ATF_CHECK(!pci_snapshot_bar_decoded(&pi, PCI_ROM_IDX));
}

ATF_TC_WITHOUT_HEAD(bar_registration_transaction);
ATF_TC_BODY(bar_registration_transaction, tc)
{
	struct bar_registration_fixture fixture;
	struct pci_bar_registration_result result;
	const uint32_t initial = (UINT32_C(1) << 1) | (UINT32_C(1) << 3);
	const uint32_t register_mask =
	    (UINT32_C(1) << 0) | (UINT32_C(1) << 2);
	const uint32_t unregister_mask = initial;

	(void)tc;
	memset(&fixture, 0, sizeof(fixture));
	fixture.registered = initial;
	result = pci_bar_registration_transaction(&fixture, register_mask,
	    unregister_mask, bar_registration_op);
	ATF_CHECK_EQ(result.error, 0);
	ATF_CHECK_EQ(result.rollback_error, 0);
	ATF_CHECK_EQ(result.completed, register_mask | unregister_mask);
	ATF_CHECK_EQ(fixture.registered, register_mask);

	/* The third operation fails; the first two must unwind in reverse. */
	memset(&fixture, 0, sizeof(fixture));
	fixture.registered = initial;
	fixture.fail_call = 3;
	result = pci_bar_registration_transaction(&fixture, register_mask,
	    unregister_mask, bar_registration_op);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_CHECK_EQ(result.rollback_error, 0);
	ATF_CHECK_EQ(result.completed,
	    (UINT32_C(1) << 0) | (UINT32_C(1) << 1));
	ATF_CHECK_EQ(fixture.registered, initial);
	ATF_REQUIRE_EQ(fixture.calls, 5);
	ATF_CHECK_EQ(fixture.indices[3], 1);
	ATF_CHECK(fixture.registrations[3]);
	ATF_CHECK_EQ(fixture.indices[4], 0);
	ATF_CHECK(!fixture.registrations[4]);

	/* A rollback failure is reported separately from the apply failure. */
	memset(&fixture, 0, sizeof(fixture));
	fixture.registered = initial;
	fixture.fail_call = 3;
	fixture.rollback_fail_call = 4;
	result = pci_bar_registration_transaction(&fixture, register_mask,
	    unregister_mask, bar_registration_op);
	ATF_CHECK_EQ(result.error, EIO);
	ATF_CHECK_EQ(result.rollback_error, EBUSY);

	result = pci_bar_registration_transaction(&fixture,
	    UINT32_C(1), UINT32_C(1), bar_registration_op);
	ATF_CHECK_EQ(result.error, EINVAL);
}

ATF_TC_WITHOUT_HEAD(checkpoint_accepts_negotiated_msi_count);
ATF_TC_BODY(checkpoint_accepts_negotiated_msi_count, tc)
{

	ATF_CHECK(pci_snapshot_msi_state_valid(0, 0));
	for (int count = 1; count <= 32; count <<= 1)
		ATF_CHECK(pci_snapshot_msi_state_valid(1, count));

	ATF_CHECK(!pci_snapshot_msi_state_valid(0, 1));
	ATF_CHECK(!pci_snapshot_msi_state_valid(1, 0));
	ATF_CHECK(!pci_snapshot_msi_state_valid(1, 3));
	ATF_CHECK(!pci_snapshot_msi_state_valid(1, 64));
	ATF_CHECK(!pci_snapshot_msi_state_valid(2, 1));
}

ATF_TC_WITHOUT_HEAD(checkpoint_restore_phases);
ATF_TC_BODY(checkpoint_restore_phases, tc)
{
	struct pci_devinst endpoint, fabric;
	struct pci_devemu endpoint_de, fabric_de;

	reset_test_state(&endpoint, &endpoint_de);
	reset_test_state(&fabric, &fabric_de);
	fabric_de.pe_restore_phase = PCI_RESTORE_FABRIC;

	ATF_CHECK(pci_snapshot_restore_in_phase(&fabric,
	    PCI_RESTORE_FABRIC));
	ATF_CHECK(!pci_snapshot_restore_in_phase(&endpoint,
	    PCI_RESTORE_FABRIC));
	ATF_CHECK(pci_snapshot_restore_in_phase(&endpoint,
	    PCI_RESTORE_NORMAL));
	ATF_CHECK(!pci_snapshot_restore_in_phase(&fabric,
	    PCI_RESTORE_NORMAL));
}

static int
test_snapshot(struct vm_snapshot_meta *meta __unused)
{

	return (0);
}

static int
test_compat(struct pci_devinst *pi __unused,
    struct pci_snapshot_compat *compat __unused)
{

	return (0);
}

ATF_TC_WITHOUT_HEAD(migration_requires_complete_explicit_contract);
ATF_TC_BODY(migration_requires_complete_explicit_contract, tc)
{
	struct pci_devinst pi;
	struct pci_devemu pde;

	(void)tc;
	reset_test_state(&pi, &pde);
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), ENOTSUP);

	pde.pe_snapshot = test_snapshot;
	pde.pe_snapshot_validate = test_snapshot;
	pde.pe_snapshot_compat = test_compat;
	pde.pe_pause = test_pause;
	pde.pe_resume = test_resume;
	pde.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS;
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), 0);

	/* Every policy axis is exclusive and independently required. */
	pde.pe_migration_flags |= PCI_MIGRATION_F_DMA_NONE;
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), EINVAL);
	pde.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS &
	    ~PCI_MIGRATION_F_QUIESCE_CALLBACK;
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), EINVAL);
	pde.pe_migration_flags = PCI_MIGRATION_VIRTIO_FLAGS;
	pde.pe_resume = NULL;
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), EINVAL);

	/* Passthrough's default-zero contract is rejected fail-closed. */
	reset_test_state(&pi, &pde);
	ATF_CHECK_EQ(pci_migration_device_validate(&pi), ENOTSUP);
}

ATF_TC_WITHOUT_HEAD(checkpoint_restore_requires_validator_pair);
ATF_TC_BODY(checkpoint_restore_requires_validator_pair, tc)
{
	struct pci_devinst pi;
	struct pci_devemu pde;

	ATF_CHECK(!pci_snapshot_restore_supported(NULL));
	memset(&pi, 0, sizeof(pi));
	ATF_CHECK(!pci_snapshot_restore_supported(&pi));

	reset_test_state(&pi, &pde);
	ATF_CHECK(!pci_snapshot_restore_supported(&pi));
	pde.pe_snapshot = test_snapshot;
	ATF_CHECK(!pci_snapshot_restore_supported(&pi));
	pde.pe_snapshot = NULL;
	pde.pe_snapshot_validate = test_snapshot;
	ATF_CHECK(!pci_snapshot_restore_supported(&pi));
	pde.pe_snapshot = test_snapshot;
	ATF_CHECK(pci_snapshot_restore_supported(&pi));
}

ATF_TC_WITHOUT_HEAD(checkpoint_lifecycle_dependency_order);
ATF_TC_BODY(checkpoint_lifecycle_dependency_order, tc)
{

	ATF_CHECK_EQ(pci_checkpoint_lifecycle_phase(0, false),
	    PCI_RESTORE_NORMAL);
	ATF_CHECK_EQ(pci_checkpoint_lifecycle_phase(1, false),
	    PCI_RESTORE_FABRIC);
	ATF_CHECK_EQ(pci_checkpoint_lifecycle_phase(0, true),
	    PCI_RESTORE_FABRIC);
	ATF_CHECK_EQ(pci_checkpoint_lifecycle_phase(1, true),
	    PCI_RESTORE_NORMAL);
}

ATF_TC_WITHOUT_HEAD(checkpoint_validation_cleanup);
ATF_TC_BODY(checkpoint_validation_cleanup, tc)
{
	struct pci_devinst pi;
	struct pci_devemu pde;

	reset_test_state(&pi, &pde);
	pci_snapshot_validate_cleanup(NULL);
	pci_snapshot_validate_cleanup(&pi);
	ATF_CHECK_EQ(validate_cleanup_calls, 0);

	pde.pe_snapshot_validate_cleanup = test_validate_cleanup;
	pci_snapshot_validate_cleanup(&pi);
	ATF_CHECK_EQ(validate_cleanup_calls, 1);
}

ATF_TC_WITHOUT_HEAD(checkpoint_compatibility_preflight);
ATF_TC_BODY(checkpoint_compatibility_preflight, tc)
{
	struct pci_snapshot_compat destination, source;

	memset(&source, 0, sizeof(source));
	source.schema = PCI_SNAPSHOT_COMPAT_SCHEMA;
	source.transport = 1;
	source.queue_count = 3;
	source.msix_table_count = 4;
	source.config_size = 64;
	source.offered_features = 0x55;
	source.negotiated_features = 0x11;
	strlcpy(source.queue_sizes, "256,256,32",
	    sizeof(source.queue_sizes));
	strlcpy(source.shared_memory, "1:4:4096:8192",
	    sizeof(source.shared_memory));
	destination = source;
	destination.offered_features = 0xff;

	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination), 0);

	destination.transport++;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	destination.queue_count++;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	destination.msix_table_count++;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	destination.config_size++;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	strlcpy(destination.queue_sizes, "256,128,32",
	    sizeof(destination.queue_sizes));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	memset(destination.shared_memory, 0,
	    sizeof(destination.shared_memory));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	destination.offered_features &= ~UINT64_C(0x40);
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	destination = source;
	source.negotiated_features |= UINT64_C(0x02);
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);
	source.negotiated_features &= ~UINT64_C(0x02);
	destination = source;
	source.offered_features |= UINT64_C(0x80);
	source.negotiated_features |= UINT64_C(0x80);
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    ENOTSUP);
	source.offered_features &= ~UINT64_C(0x80);
	source.negotiated_features &= ~UINT64_C(0x80);
	destination = source;
	destination.schema++;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);
	destination = source;
	memset(destination.queue_sizes, 'x',
	    sizeof(destination.queue_sizes));
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);
	destination = source;
	destination.shared_memory[strlen(destination.shared_memory) + 1] = 1;
	ATF_CHECK_EQ(pci_snapshot_compat_validate(&source, &destination),
	    EINVAL);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, checkpoint_pause_ownership);
	ATF_TP_ADD_TC(tp, msi_control_normalization);
	ATF_TP_ADD_TC(tp, checkpoint_restores_decoded_bars);
	ATF_TP_ADD_TC(tp, bar_registration_transaction);
	ATF_TP_ADD_TC(tp, checkpoint_accepts_negotiated_msi_count);
	ATF_TP_ADD_TC(tp, checkpoint_restore_phases);
	ATF_TP_ADD_TC(tp, checkpoint_restore_requires_validator_pair);
	ATF_TP_ADD_TC(tp, migration_requires_complete_explicit_contract);
	ATF_TP_ADD_TC(tp, checkpoint_lifecycle_dependency_order);
	ATF_TP_ADD_TC(tp, checkpoint_validation_cleanup);
	ATF_TP_ADD_TC(tp, checkpoint_compatibility_preflight);
	return (atf_no_error());
}
