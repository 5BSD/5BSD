/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALCRYPTO_POLICY_H_
#define _LOCALCRYPTO_POLICY_H_

#include <sys/cryptodesc.h>

#include <cryptocmp_protocol.h>

#define	CRYPTOCMP_MAX_CIPHER_KEY_BYTES	64
#define	CRYPTOCMP_MAX_MAC_KEY_BYTES	64

int	cryptocmp_policy_validate(const struct cryptocmp_generate *);
int	cryptocmp_key_policy_validate(const struct cryptocmp_key_generate *);
int	cryptocmp_named_create_policy_validate(const struct cryptocmp_named_create *);
int	cryptocmp_named_lease_policy_validate(const struct cryptocmp_named_lease *);
int	cryptocmp_named_control_policy_validate(const struct cryptocmp_named_control *);
int	cryptocmp_named_stat_policy_validate(const struct cryptocmp_named_stat *);
int	cryptocmp_digest_policy_validate(const struct cryptocmp_digest *);
int	cryptocmp_random_policy_validate(const struct cryptocmp_random *);

#endif /* !_LOCALCRYPTO_POLICY_H_ */
