/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LOCALCRYPTO_PROBES_H_
#define _LOCALCRYPTO_PROBES_H_
#ifdef WITH_DTRACE
#include "crypto_provider.h"
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	CRYPTO_NAMED_LIST(__DECONST(char *, owner), count, result)
#define	CRYPTO_PROBE_RECLAIM(owner, reclaimed) \
	CRYPTO_RECLAIM(__DECONST(char *, owner), reclaimed)
#else
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	do { (void)(owner); (void)(count); (void)(result); } while (0)
#define	CRYPTO_PROBE_RECLAIM(owner, reclaimed) \
	do { (void)(owner); (void)(reclaimed); } while (0)
#endif
#endif /* !_LOCALCRYPTO_PROBES_H_ */
