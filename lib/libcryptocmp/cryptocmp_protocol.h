/*- SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CRYPTOCMP_PROTOCOL_H_
#define _CRYPTOCMP_PROTOCOL_H_
#include <stdint.h>
#define CRYPTOCMP_MAGIC 0x43434d50U
#define CRYPTOCMP_VERSION 3
#define CRYPTOCMP_INTERFACE "system.Crypto"
#define CRYPTOCMP_INTERFACE_VERSION "3.2.0"
#define CRYPTOCMP_OP_GENERATE 1
#define CRYPTOCMP_OP_GENERATE_KEY 2
#define CRYPTOCMP_OP_NAMED_CREATE 3
#define CRYPTOCMP_OP_NAMED_LEASE 4
#define CRYPTOCMP_OP_NAMED_ROTATE 5
#define CRYPTOCMP_OP_NAMED_DELETE 6
#define CRYPTOCMP_OP_DIGEST 7
#define CRYPTOCMP_OP_RANDOM 8
#define CRYPTOCMP_OP_NAMED_STAT 9
#define CRYPTOCMP_GENERATE_F_NIST_APPROVED_ONLY 0x00000001U
/* Upper bound on a single CRYPTOCMP_OP_RANDOM request/reply payload. */
#define CRYPTOCMP_MAX_RANDOM_BYTES 1024U
struct cryptocmp_msg { uint32_t magic; uint16_t version, opcode; int32_t status; } __attribute__((aligned(8)));
/* This selects an algorithm profile; it is not a FIPS validation claim. */
struct cryptocmp_generate { uint32_t cipher, mac, keylen, mackeylen, rights, ttl, flags; int32_t crid, ivlen, maclen; };
struct cryptocmp_key_generate { uint32_t type, rights, ttl, flags; };
struct cryptocmp_key_reply { struct cryptocmp_msg msg; uint8_t public_key[32]; };
struct cryptocmp_named_create { char name[64]; struct cryptocmp_generate generate; };
struct cryptocmp_named_lease { char name[64]; uint32_t rights, ttl, flags; };
struct cryptocmp_named_control { char name[64]; uint32_t flags; };
struct cryptocmp_named_reply { struct cryptocmp_msg msg; uint64_t generation; };
/* Unkeyed hash: mints an ephemeral CSP_MODE_DIGEST session descriptor. alg is
 * an OpenCrypto plain-hash selector (CRYPTO_SHA2_256/384/512). No key material,
 * so no owner scoping; the descriptor carries CRYPTODESC_RIGHT_AUTH. */
struct cryptocmp_digest { uint32_t alg, ttl, flags; };
/* CSPRNG: nbytes of output, bounded by CRYPTOCMP_MAX_RANDOM_BYTES. */
struct cryptocmp_random { uint32_t nbytes; };
struct cryptocmp_random_reply { struct cryptocmp_msg msg; uint32_t nbytes; uint8_t data[CRYPTOCMP_MAX_RANDOM_BYTES]; };
/*
 * Read-only named-key introspection.  NAMED_STAT resolves a named key by
 * (owner, name) and returns its metadata WITHOUT minting a descriptor or
 * mutating the key: no fd is delivered and the generation is unchanged.  The
 * owner is the session's channel label (never wire-supplied), exactly as the
 * other NAMED_* ops, so a STAT can only observe keys minted under its own
 * label; a miss (or a key deleted under the owner) is reported ENOENT.  flags
 * is reserved and must be zero.  The reply is data-only.
 */
struct cryptocmp_named_stat { char name[64]; uint32_t flags; };
struct cryptocmp_named_info {
	uint64_t generation;	/* current named-key generation */
	uint32_t rights;	/* granted CRYPTODESC_RIGHT_* mask */
	uint32_t cipher;	/* OpenCrypto cipher selector (0 if none) */
	uint32_t mac;		/* OpenCrypto MAC selector (0 if none) */
	uint32_t keylen;	/* cipher key length in bytes */
	uint32_t mackeylen;	/* MAC key length in bytes */
};
struct cryptocmp_named_stat_reply { struct cryptocmp_msg msg; struct cryptocmp_named_info info; };
#endif
