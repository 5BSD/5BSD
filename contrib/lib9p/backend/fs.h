
/*
 * Copyright 2016 Chris Torek <torek@ixsystems.com>
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted providing that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef LIB9P_BACKEND_FS_H
#define LIB9P_BACKEND_FS_H

#include <stdbool.h>
#include <stdint.h>
#include "backend.h"

int l9p_backend_fs_init(struct l9p_backend **backendp, int rootfd, bool ro);

/* Numeric credentials and root-relative path used to rebind a quiescent fid. */
#define L9P_FS_FID_MAX_GROUPS 1024U
struct l9p_fs_fid_state {
	uint32_t flags;
	uint32_t open_flags;
	uint32_t uid;
	uint32_t ngids;
	uint32_t *gids;
	uint64_t dev;
	uint64_t ino;
	uint64_t dir_index;
	uint64_t dir_hash;
	uint64_t dir_bytes;
	uint32_t mode;
	char *path;
};

struct l9p_fid;
int l9p_backend_fs_export_fid(struct l9p_backend *, struct l9p_fid *,
    struct l9p_fs_fid_state *);
int l9p_backend_fs_import_fid(struct l9p_backend *,
    const struct l9p_fs_fid_state *, struct l9p_fid *, bool,
    enum l9p_version);
void l9p_backend_fs_free_fid_state(struct l9p_fs_fid_state *);

#endif  /* LIB9P_BACKEND_FS_H */
