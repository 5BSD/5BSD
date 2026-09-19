/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LOCALCRYPTO_PROBES_H_
#define _LOCALCRYPTO_PROBES_H_
#ifdef WITH_DTRACE
#include "crypto_provider.h"
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	CRYPTO_NAMED_LIST(__DECONST(char *, owner), count, result)
#define	CRYPTO_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	CRYPTO_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed)
#define	CRYPTO_PROBE_RECLAIM_DROP(bundle, nkeys, error) \
	CRYPTO_RECLAIM_DROP(__DECONST(char *, bundle), nkeys, error)
#else
#define	CRYPTO_PROBE_NAMED_LIST(owner, count, result) \
	do { (void)(owner); (void)(count); (void)(result); } while (0)
#define	CRYPTO_PROBE_RECLAIM_PASS(when, live, owned, orphans, destroyed, failed) \
	do { (void)(when); (void)(live); (void)(owned); (void)(orphans); \
	    (void)(destroyed); (void)(failed); } while (0)
#define	CRYPTO_PROBE_RECLAIM_DROP(bundle, nkeys, error) \
	do { (void)(bundle); (void)(nkeys); (void)(error); } while (0)
#endif
#endif /* !_LOCALCRYPTO_PROBES_H_ */
