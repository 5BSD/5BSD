/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _BHYVE_MIGRATION_ELIGIBILITY_H_
#define _BHYVE_MIGRATION_ELIGIBILITY_H_

/*
 * Validate the complete, configured PCI topology before dirty logging starts.
 * An unqualified device must reject migration before either the CPU or device
 * dirty-generation owner is acquired.
 */
int	pci_migration_precopy_validate(void);

#endif /* _BHYVE_MIGRATION_ELIGIBILITY_H_ */
