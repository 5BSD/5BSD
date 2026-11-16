/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Kory Heard */
#ifndef _BSDFS_OES_FACTORY_H_
#define _BSDFS_OES_FACTORY_H_
/* Privileged factory primitive; caller must enforce system.oes admission.
 * Returns one owned, NOTIFY-only descriptor or -1 without leaking a descriptor.
 * No endpoint is enabled merely by linking this helper. */
int bsdfilesystem_oes_open_notify(int rootfd);
/* Consumes session_fd on success and failure; rootfd remains borrowed. */
int bsdfilesystem_oes_serve(int rootfd, int session_fd);
#endif
