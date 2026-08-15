/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTODESC_H_
#define _CRYPTODESC_H_

#include <sys/cryptodesc.h>

__BEGIN_DECLS
int	cryptodesc_mint(int control_fd, const struct session2_op *,
    uint32_t rights, int *descriptor_fd);
__END_DECLS
#endif
