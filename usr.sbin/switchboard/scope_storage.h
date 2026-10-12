/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef SWITCHBOARD_SCOPE_STORAGE_H
#define SWITCHBOARD_SCOPE_STORAGE_H
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sha256.h>

/* Broker-generated names only; no request payload selects this namespace.
 * Global names remain unchanged for durable storage compatibility. */
static inline void
sb_personal_digest(const char *kind, uid_t owner, const char *name,
    unsigned char digest[SHA256_DIGEST_LENGTH])
{
	SHA256_CTX ctx;
	unsigned char encoded[8];
	uint64_t uid = owner;

	for (unsigned i = 0; i < 8; i++)
		encoded[7 - i] = (unsigned char)(uid >> (i * 8));
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, "5bsd.personal.v1", sizeof("5bsd.personal.v1"));
	SHA256_Update(&ctx, kind, strlen(kind) + 1);
	SHA256_Update(&ctx, encoded, sizeof(encoded));
	SHA256_Update(&ctx, name, strlen(name));
	SHA256_Final(digest, &ctx);
}

static inline bool
sb_personal_storage_key(const char *kind, uid_t owner, const char *name,
    char *out, size_t size)
{
	static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";
	unsigned char digest[SHA256_DIGEST_LENGTH];
	char encoded[27];
	unsigned bits = 0, value = 0, n = 0;
	int length;

	/* 128 digest bits in unpadded base32 leave room in the unchanged
	 * 64-byte wire container for a UID and a distinct per-unit suffix. */
	sb_personal_digest(kind, owner, name, digest);
	for (unsigned i = 0; i < 16; i++) {
		value = (value << 8) | digest[i];
		bits += 8;
		while (bits >= 5) {
			bits -= 5;
			encoded[n++] = alphabet[(value >> bits) & 31];
		}
	}
	if (bits != 0)
		encoded[n++] = alphabet[(value << (5 - bits)) & 31];
	encoded[n] = '\0';
	length = snprintf(out, size, "u%ju.%s", (uintmax_t)owner, encoded);
	return (length >= 0 && (size_t)length < size);
}
#endif
