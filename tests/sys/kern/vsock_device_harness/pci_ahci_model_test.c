/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>

#include <atf-c.h>

#include "pci_ahci_model.h"

ATF_TC_WITHOUT_HEAD(mmio_access_validation);
ATF_TC_BODY(mmio_access_validation, tc)
{

	ATF_CHECK(pci_ahci_mmio_access_valid(5, 0, 1, false));
	ATF_CHECK(pci_ahci_mmio_access_valid(5, 2, 2, false));
	ATF_CHECK(pci_ahci_mmio_access_valid(5, 4, 4, false));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 1, 2, false));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 2, 4, false));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 0, 8, false));
	ATF_CHECK(!pci_ahci_mmio_access_valid(4, 0, 4, false));

	ATF_CHECK(pci_ahci_mmio_access_valid(5, 0, 4, true));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 0, 1, true));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 0, 2, true));
	ATF_CHECK(!pci_ahci_mmio_access_valid(5, 2, 4, true));
}

ATF_TC_WITHOUT_HEAD(command_abort_is_taskfile_error);
ATF_TC_BODY(command_abort_is_taskfile_error, tc)
{
	/* (ATA_E_ABORT << 8) | ATA_S_READY | ATA_S_ERROR, as ahci_abort_command
	 * builds it. */
	const uint32_t abort_tfd = (0x04U << 8) | 0x40U | 0x01U;

	/* The error register carries ATA_E_ABORT; the status carries the
	 * masked ready|error bits the SDB FIS is allowed to publish. */
	ATF_CHECK_EQ(0x04, pci_ahci_fis_error(abort_tfd));
	ATF_CHECK_EQ(0x41, pci_ahci_sdb_status(abort_tfd));

	/*
	 * Regression: an aborted command must be a task-file error (so only
	 * that command fails), never escalated to a host-bus data error that
	 * COMRESETs the whole port.  ATA_S_ERROR must be set.
	 */
	ATF_CHECK(pci_ahci_tfd_is_taskfile_error(abort_tfd));
	/* A plain ready status (no ERR bit) is not a task-file error. */
	ATF_CHECK(!pci_ahci_tfd_is_taskfile_error(0x40U));
	ATF_CHECK(!pci_ahci_tfd_is_taskfile_error(0));

	/* Only the masked status bits survive into the SDB FIS. */
	ATF_CHECK_EQ(0x00, pci_ahci_sdb_status(0x88U));
	ATF_CHECK_EQ(0x77, pci_ahci_sdb_status(0xffU));
}

ATF_TC_WITHOUT_HEAD(prdt_dba_overflow);
ATF_TC_BODY(prdt_dba_overflow, tc)
{

	ATF_CHECK(pci_ahci_prdt_dba_valid(0, 0));
	ATF_CHECK(pci_ahci_prdt_dba_valid(UINT64_C(0x1000), 0x200));
	ATF_CHECK(pci_ahci_prdt_dba_valid(UINT64_MAX, 0));
	/* base + skip exactly reaches the top of the address space. */
	ATF_CHECK(pci_ahci_prdt_dba_valid(UINT64_MAX - 0x200, 0x200));

	/* Regression: a base that would wrap when the consumed-byte offset is
	 * added must be refused before it is used to map DMA. */
	ATF_CHECK(!pci_ahci_prdt_dba_valid(UINT64_MAX, 1));
	ATF_CHECK(!pci_ahci_prdt_dba_valid(UINT64_MAX - 0x100, 0x200));
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, mmio_access_validation);
	ATF_TP_ADD_TC(tp, command_abort_is_taskfile_error);
	ATF_TP_ADD_TC(tp, prdt_dba_overflow);
	return (atf_no_error());
}
