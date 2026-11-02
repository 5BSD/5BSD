/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_VMGENID_H_
#define	_BHYVE_CHECKPOINT_VMGENID_H_

#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>

/*
 * Optional checkpoint/migration record carrying the ACPI VM Generation ID and
 * the ACPI PM1/GPE0 event registers that deliver its notification.
 *
 * Wire form (basic metadata key "vmgenid_state"), fixed length, lowercase hex:
 *   "1:<id 32>:<pm1_en 4>:<pm1_sts 4>:<pm1_cnt 4>:<gpe0_en 2>:<gpe0_sts 2>:<sci 1>"
 * A peer that does not know the key ignores it; a destination that finds no
 * key keeps its historical behaviour.
 */
#define	CHECKPOINT_VMGENID_VERSION	1
#define	CHECKPOINT_VMGENID_ID_SIZE	16
#define	CHECKPOINT_VMGENID_TEXT_SIZE	58	/* including the NUL */

/* Register bits the bhyve ACPI PM block can hold (amd64/pm.c). */
#define	CHECKPOINT_ACPI_PM1_EN_MASK	0x0520
#define	CHECKPOINT_ACPI_PM1_STS_MASK	0x8731
#define	CHECKPOINT_ACPI_PM1_CNT_MASK	0x1ffd
#define	CHECKPOINT_ACPI_GPE0_MASK	0x01

struct checkpoint_acpi_pm {
	uint16_t	pm1_enable;
	uint16_t	pm1_status;
	uint16_t	pm1_control;
	uint8_t		gpe0_enable;
	uint8_t		gpe0_status;
	bool		sci_active;
};

struct checkpoint_vmgenid {
	uint8_t			id[CHECKPOINT_VMGENID_ID_SIZE];
	struct checkpoint_acpi_pm pm;
};

enum checkpoint_vmgenid_restore {
	/* Restore of a checkpoint: a new ID and an ACPI notification. */
	CHECKPOINT_VMGENID_RESTORE,
	/* Live migration: the source's ID, unchanged, no notification. */
	CHECKPOINT_VMGENID_MIGRATE,
};

int	checkpoint_vmgenid_encode(const struct checkpoint_vmgenid *, char *,
	    size_t);
int	checkpoint_vmgenid_decode(const char *, struct checkpoint_vmgenid *);
int	checkpoint_vmgenid_plan(enum checkpoint_vmgenid_restore,
	    const struct checkpoint_vmgenid *,
	    const uint8_t [CHECKPOINT_VMGENID_ID_SIZE],
	    int (*)(void *, size_t), uint8_t [CHECKPOINT_VMGENID_ID_SIZE],
	    bool *);

#endif
