/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ACPI VM Generation ID semantics across checkpoint restore and live
 * migration ("Virtual Machine Generation ID", Microsoft, 2012; consumed by
 * the FreeBSD vmgenc(4) ACPI driver, Linux vmgenid and Windows to reseed
 * their random number generators):
 *
 *  - restoring a checkpoint (each time, also of the same checkpoint) gives
 *    the guest a new ID and raises Notify(0x80) on the generation device;
 *  - live migration presents the source's ID unchanged, without a notify;
 *  - checkpointing a VM that keeps running changes nothing.
 */

#include <sys/types.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "checkpoint_vmgenid.h"

/* Restore draws until the ID differs from every one it must not repeat. */
#define	CHECKPOINT_VMGENID_DRAWS	8

int
checkpoint_vmgenid_encode(const struct checkpoint_vmgenid *record, char *text,
    size_t size)
{
	const struct checkpoint_acpi_pm *pm;
	char *p;

	if (record == NULL || text == NULL ||
	    size < CHECKPOINT_VMGENID_TEXT_SIZE)
		return (EINVAL);
	pm = &record->pm;
	if ((pm->pm1_enable & ~CHECKPOINT_ACPI_PM1_EN_MASK) != 0 ||
	    (pm->pm1_status & ~CHECKPOINT_ACPI_PM1_STS_MASK) != 0 ||
	    (pm->pm1_control & ~CHECKPOINT_ACPI_PM1_CNT_MASK) != 0 ||
	    (pm->gpe0_enable & ~CHECKPOINT_ACPI_GPE0_MASK) != 0 ||
	    (pm->gpe0_status & ~CHECKPOINT_ACPI_GPE0_MASK) != 0)
		return (EINVAL);
	p = text;
	p += sprintf(p, "%u:", CHECKPOINT_VMGENID_VERSION);
	for (size_t i = 0; i < CHECKPOINT_VMGENID_ID_SIZE; i++)
		p += sprintf(p, "%02x", record->id[i]);
	(void)sprintf(p, ":%04x:%04x:%04x:%02x:%02x:%u", pm->pm1_enable,
	    pm->pm1_status, pm->pm1_control, pm->gpe0_enable, pm->gpe0_status,
	    pm->sci_active ? 1U : 0U);
	return (0);
}

static int
hexval(char c)
{
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (c - 'a' + 10);
	return (-1);
}

/* Parse exactly 'digits' lowercase hex digits followed by 'term'. */
static int
hexfield(const char **pp, size_t digits, char term, uint32_t *value)
{
	const char *p;
	uint32_t v;
	int d;

	p = *pp;
	v = 0;
	for (size_t i = 0; i < digits; i++) {
		if ((d = hexval(p[i])) < 0)
			return (EINVAL);
		v = (v << 4) | (uint32_t)d;
	}
	if (p[digits] != term)
		return (EINVAL);
	*pp = p + digits + (term != '\0' ? 1 : 0);
	*value = v;
	return (0);
}

int
checkpoint_vmgenid_decode(const char *text, struct checkpoint_vmgenid *record)
{
	struct checkpoint_vmgenid out;
	const char *p;
	uint32_t v[6];
	static const size_t width[6] = { 4, 4, 4, 2, 2, 1 };
	int error;

	if (text == NULL || record == NULL)
		return (EINVAL);
	if (strlen(text) != CHECKPOINT_VMGENID_TEXT_SIZE - 1 ||
	    text[0] != '0' + CHECKPOINT_VMGENID_VERSION || text[1] != ':')
		return (EINVAL);
	memset(&out, 0, sizeof(out));
	p = text + 2;
	for (size_t i = 0; i < CHECKPOINT_VMGENID_ID_SIZE; i++, p += 2) {
		int hi = hexval(p[0]), lo = hexval(p[1]);

		if (hi < 0 || lo < 0)
			return (EINVAL);
		out.id[i] = (uint8_t)(hi << 4 | lo);
	}
	if (*p++ != ':')
		return (EINVAL);
	for (size_t i = 0; i < 6; i++) {
		error = hexfield(&p, width[i], i == 5 ? '\0' : ':', &v[i]);
		if (error != 0)
			return (error);
	}
	if (v[5] > 1)
		return (EINVAL);
	out.pm.pm1_enable = (uint16_t)v[0];
	out.pm.pm1_status = (uint16_t)v[1];
	out.pm.pm1_control = (uint16_t)v[2];
	out.pm.gpe0_enable = (uint8_t)v[3];
	out.pm.gpe0_status = (uint8_t)v[4];
	out.pm.sci_active = v[5] != 0;
	if ((out.pm.pm1_enable & ~CHECKPOINT_ACPI_PM1_EN_MASK) != 0 ||
	    (out.pm.pm1_status & ~CHECKPOINT_ACPI_PM1_STS_MASK) != 0 ||
	    (out.pm.pm1_control & ~CHECKPOINT_ACPI_PM1_CNT_MASK) != 0 ||
	    (out.pm.gpe0_enable & ~CHECKPOINT_ACPI_GPE0_MASK) != 0 ||
	    (out.pm.gpe0_status & ~CHECKPOINT_ACPI_GPE0_MASK) != 0)
		return (EINVAL);
	*record = out;
	return (0);
}

/*
 * Decide the destination's generation ID.  'current' is the ID in the
 * destination's page after guest memory and fixed ROMs were restored (for a
 * checkpoint restore that is the checkpoint's ID); 'saved' is the decoded
 * record or NULL when the image carries none (an older peer).
 */
int
checkpoint_vmgenid_plan(enum checkpoint_vmgenid_restore kind,
    const struct checkpoint_vmgenid *saved,
    const uint8_t current[CHECKPOINT_VMGENID_ID_SIZE],
    int (*entropy)(void *, size_t), uint8_t next[CHECKPOINT_VMGENID_ID_SIZE],
    bool *notify)
{
	static const uint8_t zero[CHECKPOINT_VMGENID_ID_SIZE];
	int error;

	if (current == NULL || next == NULL || notify == NULL)
		return (EINVAL);
	*notify = false;
	switch (kind) {
	case CHECKPOINT_VMGENID_MIGRATE:
		memcpy(next, saved != NULL ? saved->id : current,
		    CHECKPOINT_VMGENID_ID_SIZE);
		return (0);
	case CHECKPOINT_VMGENID_RESTORE:
		if (entropy == NULL)
			return (EINVAL);
		for (int i = 0; i < CHECKPOINT_VMGENID_DRAWS; i++) {
			/* 'entropy' returns 0 or an error number. */
			if ((error = entropy(next, CHECKPOINT_VMGENID_ID_SIZE)) != 0)
				return (error);
			if (memcmp(next, current, CHECKPOINT_VMGENID_ID_SIZE) == 0 ||
			    memcmp(next, zero, CHECKPOINT_VMGENID_ID_SIZE) == 0 ||
			    (saved != NULL && memcmp(next, saved->id,
			    CHECKPOINT_VMGENID_ID_SIZE) == 0))
				continue;
			*notify = true;
			return (0);
		}
		return (EAGAIN);
	}
	return (EINVAL);
}
