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
int	cryptodesc_restrict(int descriptor_fd, uint32_t rights);
int	cryptodesc_revoke(int descriptor_fd);
__END_DECLS
#endif
