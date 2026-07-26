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
static int bar_visit_idx[PCI_BARMAX_WITH_ROM + 1];
static bool bar_visit_registration[PCI_BARMAX_WITH_ROM + 1];

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

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, checkpoint_pause_ownership);
	ATF_TP_ADD_TC(tp, checkpoint_restores_decoded_bars);
	ATF_TP_ADD_TC(tp, checkpoint_accepts_negotiated_msi_count);
	return (atf_no_error());
}
