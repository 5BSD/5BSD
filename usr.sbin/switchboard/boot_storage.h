/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_BOOT_STORAGE_H
#define SWITCHBOARD_BOOT_STORAGE_H
#include <sys/types.h>
#include <stdbool.h>
#include <string.h>
#include "switchboard_manifest.h"
/* The label alone is never authority: a personal bundle may reuse it. */
static inline bool
boot_storage_recipient(const struct svc_manifest *m, const char *bundle_id,
    bool system, uid_t owner)
{
	size_t length;

	if (!system || owner != (uid_t)-1 || m->management != SVC_MGMT_CORE ||
	    bundle_id == NULL || bundle_id[0] == '\0')
		return (false);
	length = strlen(bundle_id);
	if (length >= sizeof(m->label) - 1)
		return (false);
	return (strncmp(m->label, bundle_id, length) == 0 &&
	    m->label[length] == '/' && m->label[length + 1] != '\0' &&
	    strchr(m->label + length + 1, '/') == NULL);
}
#endif
