/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * cryptoprobe: a throwaway capability unit for the bsdcrypto container-model
 * reclaim test.  It enters capability mode, mints a NAMED key in the kernel
 * keystore through system.Crypto (bsdcrypto keys the store by the unit's
 * bundle, "Test"), and idles.  Removing the bundle must make bsdcrypto's
 * reconcile drop that key on the next boot.
 */
#include <sys/capsicum.h>
#include <sys/cryptodesc.h>

#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <opencrypto/cryptodev.h>

#include <cryptocmp.h>
#include <logcmp.h>

int
main(void)
{
	struct cryptocmp_client *client = NULL;
	struct cryptocmp_generate generate;
	uint64_t generation = 0;

	if (cap_enter() == -1)
		return (1);
	memset(&generate, 0, sizeof(generate));
	generate.cipher = CRYPTO_AES_CBC;
	generate.keylen = 32;
	generate.rights = CRYPTODESC_RIGHT_ENCRYPT | CRYPTODESC_RIGHT_DECRYPT;
	generate.crid = CRYPTO_FLAG_SOFTWARE;
	generate.ivlen = 16;
	if (cryptocmp_open(&client) == -1)
		logcmp_log(LOG_ERR, "cryptoprobe: cryptocmp_open: %m");
	else if (cryptocmp_named_create(client, "probe-key", &generate,
	    &generation) == -1)
		logcmp_log(LOG_ERR, "cryptoprobe: named_create: %m");
	else
		logcmp_log(LOG_NOTICE, "cryptoprobe: minted named key probe-key "
		    "(generation %llu)", (unsigned long long)generation);
	for (;;)
		(void)pause();
	return (0);
}
