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

#ifdef _KERNEL
#include <opencrypto/cryptodev.h>
#else
#include <crypto/cryptodev.h>
#endif

#define	CRYPTODESC_RIGHT_ENCRYPT	0x00000001U
#define	CRYPTODESC_RIGHT_DECRYPT	0x00000002U
#define	CRYPTODESC_RIGHT_AUTH		0x00000004U
#define	CRYPTODESC_RIGHT_VERIFY		0x00000008U
#define	CRYPTODESC_RIGHT_SIGN		0x00000010U
#define	CRYPTODESC_RIGHT_EXCHANGE	0x00000020U
#define	CRYPTODESC_RIGHT_DERIVE		0x00000040U
#define	CRYPTODESC_RIGHT_SESSION	(CRYPTODESC_RIGHT_ENCRYPT | \
					 CRYPTODESC_RIGHT_DECRYPT | \
					 CRYPTODESC_RIGHT_AUTH | \
					 CRYPTODESC_RIGHT_VERIFY | \
					 CRYPTODESC_RIGHT_DERIVE)
#define	CRYPTODESC_RIGHT_ALL		(CRYPTODESC_RIGHT_SESSION | \
					 CRYPTODESC_RIGHT_SIGN | \
					 CRYPTODESC_RIGHT_EXCHANGE)

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
 * Mint a descriptor with a kernel-generated key.  The session's key and
 * mackey pointers must be NULL; their lengths select the generated material.
 * cd_ttl is in seconds (zero means no expiry).  The key never enters the
 * component or consumer address space.
 */
struct cryptodesc_generate {
	struct session2_op	session;
	uint32_t		cd_rights;
	uint32_t		cd_ttl;
	int32_t			cd_fd;
};

#define	CRYPTODESC_HKDF_SHA256	1
#define	CRYPTODESC_HKDF_SHA512	2
#define	CRYPTODESC_MAX_DERIVE_SALT	1024
#define	CRYPTODESC_MAX_DERIVE_INFO	1024

/*
 * Derive a kernel-generated child session from a descriptor's secret.  The
 * child session key pointers must be NULL.  The output key is retained only
 * by the resulting DTYPE_CRYPTO descriptor.
 */
struct cryptodesc_derive {
	struct session2_op	session;
	const void		*cd_salt;
	size_t			cd_salt_len;
	const void		*cd_info;
	size_t			cd_info_len;
	uint32_t		cd_hash;
	uint32_t		cd_rights;
	uint32_t		cd_ttl;
	int32_t			cd_fd;
};

#define	CRYPTODESC_KEY_X25519	1
#define	CRYPTODESC_KEY_ED25519	2
#define	CRYPTODESC_X25519_SIZE	32
#define	CRYPTODESC_ED25519_PUBLIC_SIZE	32
#define	CRYPTODESC_ED25519_SIGNATURE_SIZE	64
#define	CRYPTODESC_KEY_NAME_MAX	64
#define	CRYPTODESC_KEY_OWNER_MAX	64

/*
 * Named key objects are kernel-resident symmetric-key templates.  Names are
 * scoped to cd_owner, which [CRYPTO] fills from the serviced client label.
 * They are intentionally volatile: module unload destroys every object.
 */
struct cryptodesc_named_create {
	char			cd_name[CRYPTODESC_KEY_NAME_MAX];
	char			cd_owner[CRYPTODESC_KEY_OWNER_MAX];
	struct session2_op	cd_session;
	uint32_t		cd_rights;
	uint32_t		cd_flags;	/* must be zero */
	uint64_t		cd_generation;	/* out */
};

struct cryptodesc_named_lease {
	char			cd_name[CRYPTODESC_KEY_NAME_MAX];
	char			cd_owner[CRYPTODESC_KEY_OWNER_MAX];
	uint32_t		cd_rights;
	uint32_t		cd_ttl;
	uint32_t		cd_flags;	/* must be zero */
	uint32_t		cd_pad;
	uint64_t		cd_generation;	/* out */
	int32_t			cd_fd;		/* out */
};

struct cryptodesc_named_control {
	char			cd_name[CRYPTODESC_KEY_NAME_MAX];
	char			cd_owner[CRYPTODESC_KEY_OWNER_MAX];
	uint32_t		cd_flags;	/* must be zero */
	uint32_t		cd_pad;
	uint64_t		cd_generation;	/* out */
};

/*
 * Read-only introspection of a named key resolved by (cd_name, cd_owner).
 * Returns the object's current metadata without minting a descriptor or
 * mutating the key; a miss (or a key deleted under the owner) is ENOENT.
 */
struct cryptodesc_named_stat {
	char			cd_name[CRYPTODESC_KEY_NAME_MAX];
	char			cd_owner[CRYPTODESC_KEY_OWNER_MAX];
	uint32_t		cd_flags;	/* must be zero */
	uint32_t		cd_rights;	/* out: granted rights */
	uint64_t		cd_generation;	/* out */
	uint32_t		cd_cipher;	/* out */
	uint32_t		cd_mac;		/* out */
	uint32_t		cd_keylen;	/* out */
	uint32_t		cd_mackeylen;	/* out */
};

/* Mint a kernel-generated X25519 or Ed25519 key descriptor. */
struct cryptodesc_key_create {
	uint32_t		cd_type;
	uint32_t		cd_rights;
	uint32_t		cd_ttl;
	uint32_t		cd_flags;	/* must be zero */
	uint8_t			cd_public[CRYPTODESC_ED25519_PUBLIC_SIZE];
	int32_t			cd_fd;
};

struct cryptodesc_x25519 {
	const void		*cd_peer_public;
	size_t			cd_peer_public_len;
	void			*cd_shared_secret;
	size_t			cd_shared_secret_len;
};

struct cryptodesc_sign {
	const void		*cd_data;
	size_t			cd_data_len;
	void			*cd_signature;
	size_t			cd_signature_len;
};

struct cryptodesc_verify {
	const void		*cd_data;
	size_t			cd_data_len;
	const void		*cd_signature;
	size_t			cd_signature_len;
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

#define	CRYPTODESC_STATE_REVOKED	0x00000001U
#define	CRYPTODESC_STATE_EXPIRED	0x00000002U
#define	CRYPTODESC_STATE_KEY_INVALID	0x00000004U

/* Fixed-layout metadata suitable for native and compatibility ABIs. */
struct cryptodesc_info {
	uint32_t		cd_size;
	uint32_t		cd_type;
	uint32_t		cd_rights;
	uint32_t		cd_state;
	int32_t			cd_crid;	/* selected OpenCrypto provider, or -1 */
	uint32_t		cd_provider_flags; /* CRYPTO_FLAG_* classification */
	int64_t			cd_expires;	/* absolute epoch seconds; zero if none */
	uint64_t		cd_generation;	/* generation held by this lease */
	uint64_t		cd_key_generation; /* latest observed named-key generation */
	uint64_t		cd_spare[3];
};

#define	CIOCGCRYPTODESC	_IOWR('c', 110, struct cryptodesc_create)
#define	CIOCSCRYPTODESCRIGHTS	_IOW('c', 111, struct cryptodesc_restrict)
#define	CIOCCRYPTODESCREVOKE	_IOW('c', 112, struct cryptodesc_revoke)
#define	CIOCGCRYPTODESCGENERATE	_IOWR('c', 113, struct cryptodesc_generate)
#define	CIOCCRYPTODESCDERIVE	_IOWR('c', 114, struct cryptodesc_derive)
#define	CIOCGCRYPTOKEYDESC	_IOWR('c', 115, struct cryptodesc_key_create)
#define	CIOCCRYPTX25519	_IOWR('c', 116, struct cryptodesc_x25519)
#define	CIOCCRYPTOSIGN	_IOWR('c', 117, struct cryptodesc_sign)
#define	CIOCCRYPTOVERIFY	_IOW('c', 118, struct cryptodesc_verify)
#define	CIOCGCRYPTONAMEDKEY	_IOWR('c', 119, struct cryptodesc_named_create)
#define	CIOCGCRYPTONAMEDLEASE	_IOWR('c', 120, struct cryptodesc_named_lease)
#define	CIOCCRYPTONAMEDROTATE	_IOWR('c', 121, struct cryptodesc_named_control)
#define	CIOCCRYPTONAMEDDELETE	_IOWR('c', 122, struct cryptodesc_named_control)
#define	CIOCGCRYPTODESCINFO	_IOWR('c', 123, struct cryptodesc_info)
#define	CIOCGCRYPTONAMEDSTAT	_IOWR('c', 124, struct cryptodesc_named_stat)

#endif /* !_SYS_CRYPTODESC_H_ */
