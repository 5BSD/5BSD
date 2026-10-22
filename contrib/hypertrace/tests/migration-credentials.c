/* SPDX-License-Identifier: BSD-2-Clause */
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include "migration_credentials_nv.h"
#include "migration_channel.h"

int main(void)
{
	char pin[65]; memset(pin, '1', 64); pin[64] = 0;
	const char *names[] = {"tls_certificate_fd", "tls_private_key_fd", "tls_trust_fd"};
	int fd = open("/dev/null", O_RDONLY);
	assert(fd >= 0);
	for (unsigned mask = 0; mask < 16; mask++) {
		struct migration_tls_credentials credentials = { .certificate_fd = -7 };
		bool enabled = false;
		int error = migration_credentials_config(mask & 1 ? "0" : NULL,
		    mask & 2 ? "1" : NULL, mask & 4 ? "2" : NULL,
		    mask & 8 ? pin : NULL, &credentials, &enabled);
		assert(enabled == (mask != 0));
		assert(error == (mask == 0 || mask == 15 ? 0 : EINVAL));
		if (mask != 15) assert(credentials.certificate_fd == -7);
		nvlist_t *nvl = nvlist_create(0);
		for (unsigned i = 0; i < 3; i++)
			if (mask & (1u << i)) nvlist_add_descriptor(nvl, names[i], fd);
		if (mask & 8) nvlist_add_string(nvl, "tls_peer_sha256", pin);
		error = migration_credentials_nv(nvl, &credentials, &enabled);
		assert(enabled == (mask != 0));
		assert(error == (mask == 0 || mask == 15 ? 0 : EINVAL));
		nvlist_destroy(nvl);
	}
	struct migration_tls_credentials credentials = {0};
	bool enabled;
	const char *badfds[] = {"", "-1", "2147483648", "xyz"};
	for (unsigned i = 0; i < sizeof(badfds)/sizeof(badfds[0]); i++)
		assert(migration_credentials_config(badfds[i], "1", "2", pin,
		    &credentials, &enabled) == EINVAL && enabled);
	uint8_t digest[32]; memset(digest, 0x5a, sizeof(digest));
	pin[63] = 'g'; assert(migration_credentials_pin(pin, digest) == EINVAL);
	assert(digest[0] == 0x5a);
	memset(pin, '0', 64); assert(migration_credentials_pin(pin, digest) == EINVAL);
	memset(pin, 'A', 64); assert(migration_credentials_pin(pin, digest) == 0);
	assert(digest[0] == 0xaa && digest[31] == 0xaa);
	nvlist_t *wrong = nvlist_create(0);
	nvlist_add_number(wrong, names[0], (uint64_t)fd);
	assert(migration_credentials_nv(wrong, &credentials, &enabled) == EINVAL && enabled);
	nvlist_destroy(wrong);
	struct migration_channel channel;
	struct migration_transport transport;
	assert(migration_channel_init(&channel, &transport, -1, false,
	    &credentials, 10) == EOPNOTSUPP);
	assert(!channel.secure && transport.xp_send == NULL && transport.xp_recv == NULL);
	assert(migration_channel_init(&channel, &transport, -1, false, NULL, 10) == 0);
	assert(!channel.secure && transport.xp_send != NULL && transport.xp_recv != NULL);
	migration_channel_cleanup(&channel);
	close(fd);
	return (0);
}
