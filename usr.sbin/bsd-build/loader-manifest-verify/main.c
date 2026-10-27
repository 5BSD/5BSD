/* SPDX-License-Identifier: BSD-2-Clause */
/* Native generation signature verification using the loader's crypto sources.
 * No firmware trust transport, ambient CA store or runtime anchor addition.
 * Firmware revocation/enrollment and independent build attestation are separate.
 */
#include <sys/types.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <libsecureboot.h>

int
main(int argc, char **argv)
{
	unsigned char *content;

	if (argc != 2)
		errx(2, "usage: loader-manifest-verify manifest.sig");
	if (ve_trust_init() <= 0)
		errx(2, "no compiled generation trust anchors");
	content = verify_sig(argv[1], 0);
	if (content == NULL)
		return (1);
	free(content);
	puts("accepted");
	return (0);
}
