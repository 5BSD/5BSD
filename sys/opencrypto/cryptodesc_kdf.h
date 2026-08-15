/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _OPENCRYPTO_CRYPTODESC_KDF_H_
#define _OPENCRYPTO_CRYPTODESC_KDF_H_

#include <sys/types.h>

int	cryptodesc_hkdf(uint32_t hash, uint8_t *output, size_t output_len,
	    const uint8_t *salt, size_t salt_len, const uint8_t *ikm,
	    size_t ikm_len, const uint8_t *info, size_t info_len);

#endif /* !_OPENCRYPTO_CRYPTODESC_KDF_H_ */
