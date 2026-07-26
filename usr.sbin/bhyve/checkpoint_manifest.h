/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_MANIFEST_H_
#define _BHYVE_CHECKPOINT_MANIFEST_H_

#include <stdbool.h>
#include <limits.h>

#define	CHECKPOINT_MANIFEST_MAGIC	"BHYVE-CHECKPOINT-MANIFEST-1\n"
#define	CHECKPOINT_GENERATION_HEX_LEN	32

struct checkpoint_manifest {
	char data[NAME_MAX + 1];
	char kern[NAME_MAX + 1];
	char meta[NAME_MAX + 1];
};

bool	checkpoint_member_valid(const char *member);
bool	checkpoint_manifest_valid_for(const char *base,
	    const struct checkpoint_manifest *manifest);
int	checkpoint_manifest_read(const char *filename,
	    struct checkpoint_manifest *manifest, bool *is_manifest);
int	checkpoint_manifest_read_at(int dirfd, const char *filename,
	    struct checkpoint_manifest *manifest, bool *exists,
	    bool *is_manifest);
char	*checkpoint_member_path(const char *checkpoint, const char *member);
int	checkpoint_generation_names(const char *base,
	    struct checkpoint_manifest *manifest, char **manifest_tmp);
int	checkpoint_publish(int dirfd, const char *checkpoint_file,
	    const char *manifest_tmp, const struct checkpoint_manifest *manifest,
	    bool *published);

#endif
