/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef CAPSULE_PROTECTED_CRYPTO_H
#define CAPSULE_PROTECTED_CRYPTO_H
struct capsule_config;
int protected_crypto_prepare(const struct capsule_config *);
int protected_crypto_open(const char *);
#endif
