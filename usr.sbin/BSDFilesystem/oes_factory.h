/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BSDFS_OES_FACTORY_H_
#define _BSDFS_OES_FACTORY_H_
/* Privileged factory primitive; caller must enforce system.oes admission.
 * Returns one owned, NOTIFY-only descriptor or -1 without leaking a descriptor.
 * No endpoint is enabled merely by linking this helper. */
int bsdfilesystem_oes_open_notify(int rootfd);
#endif
