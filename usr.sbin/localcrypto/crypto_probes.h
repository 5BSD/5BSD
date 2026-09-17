/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LOCALCRYPTO_PROBES_H_
#define _LOCALCRYPTO_PROBES_H_
#ifdef WITH_DTRACE
#include "crypto_provider.h"
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	CRYPTO_NAMED_LIST(__DECONST(char *, owner), count, result)
#else
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	do { (void)(owner); (void)(count); (void)(result); } while (0)
#endif
#endif /* !_LOCALCRYPTO_PROBES_H_ */
