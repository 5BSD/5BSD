/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _PCI_AHCI_MODEL_H_
#define _PCI_AHCI_MODEL_H_

#include <stdbool.h>
#include <stdint.h>

/*
 * AHCI registers are 32-bit.  Reads may select a naturally aligned byte or
 * word from a register, but register writes are defined as aligned dword
 * transactions.  An untrusted guest can issue any MMIO instruction, so the
 * device model must reject an unsupported access instead of asserting in the
 * bhyve process.
 */
static inline bool
pci_ahci_mmio_access_valid(int baridx, uint64_t offset, int size, bool write)
{

	if (baridx != 5 || (size != 1 && size != 2 && size != 4) ||
	    (offset & (uint64_t)(size - 1)) != 0)
		return (false);
	return (!write || size == 4);
}

/*
 * Task-file descriptor decomposition, shared with ahci_write_fis_d2h() and
 * ahci_write_fis_sdb().  The high byte is the ATA error register; the low byte
 * is the status, of which only the bits in AHCI_MODEL_SDB_STATUS_MASK are
 * carried in the Set Device Bits FIS.
 */
#define	AHCI_MODEL_ATA_S_ERROR		0x01U	/* ATA_S_ERROR: status ERR */
#define	AHCI_MODEL_SDB_STATUS_MASK	0x77U

static inline uint8_t
pci_ahci_fis_error(uint32_t tfd)
{

	return ((uint8_t)((tfd >> 8) & 0xffU));
}

static inline uint8_t
pci_ahci_sdb_status(uint32_t tfd)
{

	return ((uint8_t)(tfd & AHCI_MODEL_SDB_STATUS_MASK));
}

/*
 * A per-command abort posts a task-file error: the status byte carries
 * ATA_S_ERROR, which makes ahci_write_fis() raise PxIS.TFES for that one
 * command.  It must NOT be modelled as a host-bus data error (PxIS.HBDS): that
 * class is fatal and drives the guest driver to a full port COMRESET, tearing
 * down every other outstanding command on the port.  This predicate is the
 * task-file-error test; a true host-bus error is signalled out of band via the
 * PxIS bit and never appears in the task file, so it is always false here.
 */
static inline bool
pci_ahci_tfd_is_taskfile_error(uint32_t tfd)
{

	return ((tfd & AHCI_MODEL_ATA_S_ERROR) != 0);
}

/*
 * Guard a PRDT descriptor's DMA base against 64-bit wrap before adding the
 * count of already-consumed bytes ('skip') for a split/continued transfer.  A
 * guest can place any 64-bit base in the descriptor; letting base + skip wrap
 * would map a bogus, aliased region.  A wrapping descriptor is refused, which
 * the caller turns into a command abort rather than a bhyve fault.
 */
static inline bool
pci_ahci_prdt_dba_valid(uint64_t dba, uint64_t skip)
{

	return (dba <= UINT64_MAX - skip);
}

#endif /* _PCI_AHCI_MODEL_H_ */
