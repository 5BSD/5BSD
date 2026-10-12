/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Test double for lib/libfilesystemcmp/filesystem_transact.h: bsdfilesystem_test
 * compiles ../bsdfilesystem.c against this header, so the library's request
 * building and legacy-shaped reply validation run against scripted replies
 * (bsdfilesystem_test.c defines the functions).  The schema transport itself is
 * covered by the BSDFilesystem provider and evolution tests.
 */
#ifndef _FILESYSTEM_TRANSACT_H_
#define	_FILESYSTEM_TRANSACT_H_

#include <stddef.h>
#include <stdint.h>

#include <bsdfilesystem_proto.h>

struct fs_transport {
	int	fd;
};

static int	fs_transport_adopt(struct fs_transport *, int);
static void	fs_transport_drop(struct fs_transport *);
static int	fs_transact(struct fs_transport *, const void *, size_t, void *,
		    size_t, size_t *, int *, uint32_t);

#endif
