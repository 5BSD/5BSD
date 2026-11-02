/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Userland build configuration for sys/contrib/libb2/blake2b-ref.c in
 * bsdextension(8) (pkg file checksums for root loads).  The kernel uses
 * sys/crypto/blake2/config.h, which also shims libc headers; this one only
 * sets what blake2-impl.h reads.  Compiled with an empty SUFFIX, so the
 * functions keep the names blake2.h declares.
 */
#ifndef _BSDEXTENSION_LIBB2_CONFIG_H_
#define	_BSDEXTENSION_LIBB2_CONFIG_H_

#include <sys/endian.h>

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define	NATIVE_LITTLE_ENDIAN	1
#endif
#if !defined(__i386__) && !defined(__x86_64__) && \
    !defined(__ARM_FEATURE_UNALIGNED)
#define	HAVE_ALIGNED_ACCESS_REQUIRED	1
#endif
#define	HAVE_EXPLICIT_BZERO	1

#endif
