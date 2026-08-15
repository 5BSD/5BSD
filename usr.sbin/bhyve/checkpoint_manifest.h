/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _BHYVE_CHECKPOINT_MANIFEST_H_
#define _BHYVE_CHECKPOINT_MANIFEST_H_

#include <stdbool.h>
#include <limits.h>

#define	CHECKPOINT_MANIFEST_MAGIC	"BHYVE-CHECKPOINT-MANIFEST-3\n"
#define	CHECKPOINT_GENERATION_HEX_LEN	32
#define	CHECKPOINT_ARCH_MAX		15
#define	CHECKPOINT_MACHINE_MAX		63
/*
 * This identifies the complete bhyve/kernel checkpoint record layout, not
 * merely the portable VirtIO device envelope.  Advance it whenever a
 * non-self-describing record changes (in particular an amd64 VMX record), so
 * restore rejects the image at manifest admission rather than discovering a
 * shifted kernel record after it has begun the restore transaction.
 */
#define	CHECKPOINT_MACHINE_ABI		"bhyve-virtio-v2"
#define	CHECKPOINT_SHA256_HEX_LEN	64

struct checkpoint_manifest {
	unsigned int format_version;
	char architecture[CHECKPOINT_ARCH_MAX + 1];
	char machine[CHECKPOINT_MACHINE_MAX + 1];
	char data[NAME_MAX + 1];
	char kern[NAME_MAX + 1];
	char meta[NAME_MAX + 1];
	char data_sha256[CHECKPOINT_SHA256_HEX_LEN + 1];
	char kern_sha256[CHECKPOINT_SHA256_HEX_LEN + 1];
	char meta_sha256[CHECKPOINT_SHA256_HEX_LEN + 1];
};

bool	checkpoint_member_valid(const char *member);
bool	checkpoint_manifest_valid_for(const char *base,
	    const struct checkpoint_manifest *manifest);
bool	checkpoint_manifest_compatible(
	    const struct checkpoint_manifest *manifest);
const char *checkpoint_host_architecture(void);
int	checkpoint_manifest_read(const char *filename,
	    struct checkpoint_manifest *manifest, bool *is_manifest);
int	checkpoint_manifest_read_at(int dirfd, const char *filename,
	    struct checkpoint_manifest *manifest, bool *exists,
	    bool *is_manifest);
int	checkpoint_generation_names(const char *base,
	    struct checkpoint_manifest *manifest, char **manifest_tmp);
int	checkpoint_manifest_open_verified_at(int dirfd,
	    const struct checkpoint_manifest *manifest, int *data_fd,
	    int *kern_fd, int *meta_fd);
int	checkpoint_publish(int dirfd, const char *checkpoint_file,
	    const char *manifest_tmp, struct checkpoint_manifest *manifest,
	    bool *published);

#endif
