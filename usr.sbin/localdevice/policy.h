/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALDEVICE_POLICY_H_
#define _LOCALDEVICE_POLICY_H_

#include <sys/types.h>

#include <stdbool.h>

#include <devicecmp_protocol.h>

/*
 * Per-label device policy (default-deny).  Each entry grants one client label
 * one /dev leaf with a DEVICECMP_RIGHT_* mask and, optionally, a bounded ioctl
 * command whitelist applied to the delivered descriptor.  A label/device pair
 * with no matching entry is denied.
 */
#define	DEVICECMP_MAX_POLICY		256
#define	DEVICECMP_MAX_IOCTLS		16
#define	DEVICECMP_LABEL_MAX		128

struct devicecmp_device_policy {
	char		label[DEVICECMP_LABEL_MAX];
	char		device[DEVICECMP_MAX_NAME];
	uint32_t	rights;			/* DEVICECMP_RIGHT_* mask */
	unsigned	nioctls;
	unsigned long	ioctls[DEVICECMP_MAX_IOCTLS];
};

struct devicecmp_config {
	unsigned			nentries;
	struct devicecmp_device_policy	entries[DEVICECMP_MAX_POLICY];
};

/* Compiled-in default: deny everything (no entries). */
void	devicecmp_config_defaults(struct devicecmp_config *);

/*
 * Overlay a UCL policy read from an already-open, trusted descriptor (a bundle
 * Config/ file delivered by serviced).  A closed/empty parse leaves the
 * default-deny config intact.  Returns 0, or -1 with errno on a malformed file.
 * Consumes nothing; the caller owns fd.
 */
int	devicecmp_config_load_fd(struct devicecmp_config *, int fd);

/*
 * Look up the policy for (label, device).  Returns the granted rights mask (0
 * when denied).  On a match, the ioctlsp and nioctlsp out-params receive the
 * entry's ioctl whitelist (nioctls == 0 means no ioctl restriction beyond the
 * rights mask).
 */
uint32_t devicecmp_policy_lookup(const struct devicecmp_config *,
	    const char *label, const char *device,
	    const unsigned long **ioctlsp, unsigned *nioctlsp);

/*
 * Enumerate, into the caller-provided page, the device entries whose policy
 * label equals `label` (label-scoped: no other label's entries are ever
 * visible).  `cursor` is an index into this label's filtered, file-order-stable
 * entry sequence (0 == first page); at most `max` (and at most
 * DEVICECMP_LIST_MAX) entries are filled.  *countp receives the number filled
 * and *nextp the cursor to re-issue for the next page (0 == final page).  A
 * label with no matching entry yields count 0 (default-deny).  Each entry gets
 * the policy-max rights mask and DEVICECMP_LIST_FLAG_IOCTL_WHITELIST when an
 * ioctl whitelist applies.
 */
void	devicecmp_policy_list(const struct devicecmp_config *cfg,
	    const char *label, uint32_t cursor, struct devicecmp_list_entry *out,
	    uint32_t max, uint32_t *countp, uint32_t *nextp);

/* True if name is a single, safe /dev leaf component. */
bool	devicecmp_valid_device_name(const char *name);

#endif /* !_LOCALDEVICE_POLICY_H_ */
