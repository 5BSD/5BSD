/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _CAPIMAGE_H_
#define _CAPIMAGE_H_
#include <sys/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/capimage.h>
#define CAPIMAGE_TRUST_DIR "/etc/capability/keys"
struct capimage_policy {
	unsigned char *data;
	size_t size;
	unsigned char key[CAPIMAGE_KEY_SIZE];
	unsigned char digest[32];
};
__BEGIN_DECLS
/* ENOENT: no policy; ENOATTR: unsigned build policy; EAUTH: untrusted signature. */
int capimage_signatures_required(bool *, char *, size_t);
int capimage_verify(int, const char *, struct capimage_policy *, char *, size_t);
int capimage_sign(int, const char *, char *, size_t);
int capimage_cache_info(int, struct capimage_elf_info *, char *, size_t);
int capimage_cache_size(int, off_t *, char *, size_t);
int capimage_remove(int, char *, size_t);
int capimage_embed(int, const void *, size_t, char *, size_t);
int capimage_note(FILE *, const void *, size_t, char *, size_t);
void capimage_policy_free(struct capimage_policy *);
/* Detached signatures bind arbitrary immutable artifacts (bundle inventories,
 * shared caches). domain must be a stable, distinct protocol string. */
int capimage_seal(int, int, const char *, const char *, char *, size_t);
int capimage_check_seal(int, int, const char *, const char *, char *, size_t);
/* Integrity only: embedded keys authenticate bytes, NOT a trusted publisher or
 * capability grant. Callers must independently confine all policy requests. */
int capimage_verify_integrity(int, struct capimage_policy *, char *, size_t);
int capimage_check_seal_integrity(int, int, const char *, char *, size_t);
/* Explicit pinned integrity only. Success with *handle == -1 means unsigned.
 * Keep the handle until the same original fd has been adopted/pinned by its
 * consumer. No automatic fallback or publisher trust is implied. */
int capimage_prepare_fd(int, uint32_t, int *, struct capimage_info *, char *, size_t);
/* As prepare_fd, plus existing catalogue/explicit-key trust for signed input. */
int capimage_prepare_trusted_fd(int, uint32_t, const char *, int *,
    struct capimage_info *, char *, size_t);
int capimage_handle_policy(int, struct capimage_policy *, char *, size_t);
__END_DECLS
#endif
