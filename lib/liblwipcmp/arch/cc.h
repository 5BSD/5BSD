/*-
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _LWIPCMP_ARCH_CC_H_
#define	_LWIPCMP_ARCH_CC_H_

#include <sys/endian.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define	BYTE_ORDER	LITTLE_ENDIAN
#else
#define	BYTE_ORDER	BIG_ENDIAN
#endif

#define	LWIP_RAND()	arc4random()
#define	LWIP_PLATFORM_DIAG(x)	do { fprintf(stderr, x); } while (0)
#define	LWIP_PLATFORM_ASSERT(x)	do {				\
	fprintf(stderr, "lwIP assertion: %s (%s:%d)\n", (x),	\
	    __FILE__, __LINE__);					\
	abort();							\
} while (0)

#endif /* !_LWIPCMP_ARCH_CC_H_ */
