/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_COMPAT_H_
#define _BHYVE_CHECKPOINT_COMPAT_H_

#include <stddef.h>

#include "pci_emul.h"

#ifdef BHYVE_SNAPSHOT
#define	CHECKPOINT_COMPAT_MAGIC	0x42564331U	/* "BVC1" */
#define	CHECKPOINT_COMPAT_SCALARS_SIZE	48
#define	CHECKPOINT_COMPAT_ENVELOPE_SIZE	\
    (CHECKPOINT_COMPAT_SCALARS_SIZE + 2 * PCI_SNAPSHOT_COMPAT_SHAPE_MAX)

int	checkpoint_compat_encode(const struct pci_snapshot_compat *, void *,
	    size_t);
int	checkpoint_compat_decode(const void *, size_t,
	    struct pci_snapshot_compat *);
uint32_t checkpoint_compat_payload_crc32(const void *, size_t);
bool	checkpoint_compat_equal(const struct pci_snapshot_compat *,
	    const struct pci_snapshot_compat *);
#endif

#endif
