/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef _BHYVE_MIGRATION_CREDENTIALS_H_
#define _BHYVE_MIGRATION_CREDENTIALS_H_
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

struct migration_tls_credentials {
	int certificate_fd;
	int private_key_fd;
	int trust_fd;
	uint8_t peer_certificate_sha256[32];
};

static inline int
migration_credentials_pin(const char *text, uint8_t pin[32])
{
	uint8_t candidate[32] = {0};
	if (text == NULL || strlen(text) != 64 || pin == NULL) return (EINVAL);
	for (size_t i = 0; i < 64; i++) {
		unsigned value;
		if (text[i] >= '0' && text[i] <= '9') value = text[i] - '0';
		else if (text[i] >= 'a' && text[i] <= 'f') value = text[i] - 'a' + 10;
		else if (text[i] >= 'A' && text[i] <= 'F') value = text[i] - 'A' + 10;
		else return (EINVAL);
		candidate[i / 2] = (uint8_t)((candidate[i / 2] << 4) | value);
	}
	if (memcmp(candidate, (const uint8_t[32]){0}, 32) == 0) return (EINVAL);
	memcpy(pin, candidate, 32);
	return (0);
}

/* Any supplied field requests TLS. Partial configuration is always an error,
 * never permission to choose the plaintext transport. No paths are opened. */
static inline int
migration_credentials_config(const char *certificate, const char *key,
    const char *trust, const char *pin, struct migration_tls_credentials *out,
    bool *enabled)
{
	struct migration_tls_credentials candidate = {0};
	const char *values[] = {certificate, key, trust}, *error;
	int *fds[] = {&candidate.certificate_fd, &candidate.private_key_fd,
	    &candidate.trust_fd};
	if (out == NULL || enabled == NULL) return (EINVAL);
	*enabled = certificate != NULL || key != NULL || trust != NULL || pin != NULL;
	if (!*enabled) return (0);
	if (certificate == NULL || key == NULL || trust == NULL || pin == NULL)
		return (EINVAL);
	for (size_t i = 0; i < 3; i++) {
		long fd = strtonum(values[i], 0, INT_MAX, &error);
		if (error != NULL) return (EINVAL);
		*fds[i] = (int)fd;
	}
	if (migration_credentials_pin(pin, candidate.peer_certificate_sha256) != 0)
		return (EINVAL);
	*out = candidate;
	return (0);
}
#endif
