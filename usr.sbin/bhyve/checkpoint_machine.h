/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_MACHINE_H_
#define _BHYVE_CHECKPOINT_MACHINE_H_

#include <stddef.h>

#include "pci_emul.h"

#define	CHECKPOINT_MACHINE_TOPOLOGY_VERSION	1U
#define	CHECKPOINT_MACHINE_DIGEST_LENGTH		65U
#define	CHECKPOINT_MACHINE_DEVICE_NAME_MAX	1024U

struct checkpoint_machine_device {
	const char *name;
	const struct pci_snapshot_compat *compat;
};

int	checkpoint_machine_topology_digest(
	    const struct checkpoint_machine_device *, size_t, char *, size_t);
bool	checkpoint_machine_digest_canonical(const char *);

#endif
