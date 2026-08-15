/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _OPENCRYPTO_CRYPTODESC_ED25519_H_
#define _OPENCRYPTO_CRYPTODESC_ED25519_H_

#include <sys/types.h>

#define	CRYPTODESC_ED25519_SECRET_SIZE	64

void	cryptodesc_ed25519_keypair(uint8_t public_key[32],
	    uint8_t secret_key[CRYPTODESC_ED25519_SECRET_SIZE]);
int	cryptodesc_ed25519_sign(uint8_t signature[64], const uint8_t *data,
	    size_t data_len, const uint8_t secret_key[CRYPTODESC_ED25519_SECRET_SIZE]);
int	cryptodesc_ed25519_verify(const uint8_t signature[64],
	    const uint8_t *data, size_t data_len, const uint8_t public_key[32]);

#endif /* !_OPENCRYPTO_CRYPTODESC_ED25519_H_ */
