/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_TOPOLOGY_H_
#define	_BHYVE_CHECKPOINT_TOPOLOGY_H_

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#define	CHECKPOINT_NUMA_MAX_DOMAINS	8

struct checkpoint_record_range {
	uint64_t offset;
	uint64_t length;
};

struct checkpoint_memory_geometry {
	uint64_t page_size;
	uint64_t lowmem_size;
	uint64_t highmem_base;
	uint64_t highmem_size;
};

/*
 * ACPI PM1/GPE0 event registers (amd64/pm.c) and the bits the PM block can
 * hold; a restored process must present the guest's enables or no later
 * ACPI event, such as the power button, reaches the guest.
 */
#define	CHECKPOINT_ACPI_PM_VERSION	1
#define	CHECKPOINT_ACPI_PM1_EN_MASK	0x0520
#define	CHECKPOINT_ACPI_PM1_STS_MASK	0x8731
#define	CHECKPOINT_ACPI_PM1_CNT_MASK	0x1ffd
#define	CHECKPOINT_ACPI_GPE0_MASK	0x01

struct checkpoint_acpi_pm {
	uint16_t pm1_enable;
	uint16_t pm1_status;
	uint16_t pm1_control;
	uint8_t gpe0_enable;
	uint8_t gpe0_status;
	bool sci_active;
};

/*
 * Compare the source checkpoint's named device-state sections with the
 * destination machine.  Ordering is deliberately irrelevant, but names must
 * be nonempty and unique on both sides and the sets must match exactly.
 * On failure the optional reason buffer names the first unmatched device.
 */
int	checkpoint_topology_validate(const char * const *, size_t,
	    const char * const *, size_t, char *, size_t);
int	checkpoint_cpu_topology_validate(uint64_t, uint64_t, uint64_t,
	    uint64_t);
int	checkpoint_numa_mapping_validate(const uint64_t *, size_t,
	    const uint16_t *, size_t, uint64_t);
int	checkpoint_memory_geometry_validate(
	    const struct checkpoint_memory_geometry *, uint64_t);
int	checkpoint_memory_geometry_match(
	    const struct checkpoint_memory_geometry *,
	    const struct checkpoint_memory_geometry *, uint64_t);
int	checkpoint_record_layout_validate(
	    const struct checkpoint_record_range *, size_t, uint64_t);
int	checkpoint_record_consumption_validate(size_t, size_t);

#endif /* _BHYVE_CHECKPOINT_TOPOLOGY_H_ */
