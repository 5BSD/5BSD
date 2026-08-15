/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Kory Heard
 */

/*
 * CRYPTO descriptor ABI.
 *
 * A CRYPTO descriptor is a passable capability around one OpenCrypto session.
 * The descriptor fixes the session's algorithms and key material at mint
 * time.  Consumers can only submit operations permitted by cd_rights; they
 * cannot create further sessions or recover the key material.
 */

#ifndef _SYS_CRYPTODESC_H_
#define _SYS_CRYPTODESC_H_

#include <sys/ioccom.h>
#include <sys/types.h>

#include <opencrypto/cryptodev.h>

#define	CRYPTODESC_RIGHT_ENCRYPT	0x00000001U
#define	CRYPTODESC_RIGHT_DECRYPT	0x00000002U
#define	CRYPTODESC_RIGHT_AUTH		0x00000004U
#define	CRYPTODESC_RIGHT_VERIFY		0x00000008U
#define	CRYPTODESC_RIGHT_ALL		(CRYPTODESC_RIGHT_ENCRYPT | \
					 CRYPTODESC_RIGHT_DECRYPT | \
					 CRYPTODESC_RIGHT_AUTH | \
					 CRYPTODESC_RIGHT_VERIFY)

/*
 * Issued only by the /dev/crypto control descriptor.  The key pointers in
 * session are copied into kernel/OpenCrypto storage during the call; the
 * returned fd is a DTYPE_CRYPTO descriptor and owns the resulting session.
 */
struct cryptodesc_create {
	struct session2_op	session;
	uint32_t		cd_rights;
	int32_t			cd_fd;		/* out */
};

/*
 * Attenuate an issued descriptor.  cd_rights must be a subset of the current
 * rights and may be zero.  Rights can never be restored through this ABI.
 */
struct cryptodesc_restrict {
	uint32_t		cd_rights;
};

/* Permanently disable an issued descriptor before its final close. */
struct cryptodesc_revoke {
	uint32_t		cd_flags;	/* must be zero */
};

#define	CIOCGCRYPTODESC	_IOWR('c', 110, struct cryptodesc_create)
#define	CIOCSCRYPTODESCRIGHTS	_IOW('c', 111, struct cryptodesc_restrict)
#define	CIOCCRYPTODESCREVOKE	_IOW('c', 112, struct cryptodesc_revoke)

#endif /* !_SYS_CRYPTODESC_H_ */
