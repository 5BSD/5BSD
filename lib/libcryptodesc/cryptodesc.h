/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTODESC_H_
#define _CRYPTODESC_H_

#include <sys/cryptodesc.h>

__BEGIN_DECLS
int	cryptodesc_mint(int control_fd, const struct session2_op *,
    uint32_t rights, int *descriptor_fd);
int	cryptodesc_mint_generated(int control_fd, const struct session2_op *,
    uint32_t rights, uint32_t ttl, int *descriptor_fd);
int	cryptodesc_mint_key(int control_fd, uint32_t type, uint32_t rights,
    uint32_t ttl, uint8_t public_key[CRYPTODESC_ED25519_PUBLIC_SIZE],
    int *descriptor_fd);
int	cryptodesc_named_create(int control_fd, const char *name,
    const char *owner, const struct session2_op *, uint32_t rights,
    uint64_t *generation);
int	cryptodesc_named_lease(int control_fd, const char *name,
    const char *owner, uint32_t rights, uint32_t ttl, uint64_t *generation,
    int *descriptor_fd);
int	cryptodesc_named_rotate(int control_fd, const char *name,
    const char *owner, uint64_t *generation);
int	cryptodesc_named_delete(int control_fd, const char *name,
    const char *owner, uint64_t *generation);
int	cryptodesc_named_stat(int control_fd, const char *name,
    const char *owner, struct cryptodesc_named_stat *stat);
int	cryptodesc_restrict(int descriptor_fd, uint32_t rights);
int	cryptodesc_revoke(int descriptor_fd);
int	cryptodesc_get_info(int descriptor_fd, struct cryptodesc_info *info);
__END_DECLS
#endif
