/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CAPSULE_PROTECTED_STORAGE_H
#define CAPSULE_PROTECTED_STORAGE_H
#include "config.h"
struct nvlist;
/* Internal import admission; uses the kernel host ID, never environment overrides. */
bool protected_storage_import_allowed(struct nvlist *);
/* Internal acquisition primitive; caller supplies already validated policy. */
int protected_storage_open(const struct capsule_storage *);
/* Original PID 1 retains the anchors for the boot, across manager restarts. */
int protected_storage_prepare(const struct capsule_config *);
int protected_storage_derive(const char *recipient);
#endif
