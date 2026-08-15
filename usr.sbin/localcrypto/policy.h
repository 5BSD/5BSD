/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _LOCALCRYPTO_POLICY_H_
#define _LOCALCRYPTO_POLICY_H_

#include <sys/cryptodesc.h>

#include <cryptocmp_protocol.h>

#define	CRYPTOCMP_MAX_CIPHER_KEY_BYTES	64
#define	CRYPTOCMP_MAX_MAC_KEY_BYTES	64

int	cryptocmp_policy_validate(const struct cryptocmp_generate *);
int	cryptocmp_key_policy_validate(const struct cryptocmp_key_generate *);

#endif /* !_LOCALCRYPTO_POLICY_H_ */
