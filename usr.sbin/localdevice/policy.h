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

/* True if name is a single, safe /dev leaf component. */
bool	devicecmp_valid_device_name(const char *name);

#endif /* !_LOCALDEVICE_POLICY_H_ */
