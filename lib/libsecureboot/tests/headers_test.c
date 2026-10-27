/* SPDX-License-Identifier: BSD-2-Clause */
#include <stddef.h>
#include <string.h>
#include "secureboot_config.h"
#include "ta.h"
#include "vse.h"

#ifndef VE_SHA256_SUPPORT
#error missing SHA256 policy
#endif
#ifndef VE_SHA384_SUPPORT
#error missing SHA384 policy
#endif
#ifndef VE_RSA_SUPPORT
#error missing RSA policy
#endif
#ifdef VE_ECDSA_SUPPORT
#error unexpected ECDSA policy
#endif
int
main(void)
{
	/* This fixture deliberately trusts nobody; it is not a boot policy. */
	if (sizeof(ta_PEM) != 1 || ta_PEM[0] != 0 || sizeof(vc_PEM) != 0)
		return 1;
	if (BUILD_UTC != 1546329600 || strcmp(signature_exts[0], "sig") ||
	    signature_exts[1] != NULL)
		return 2;
	if (strcmp(VE_HASH_KAT_STR, "self-tests-are-good") ||
	    VE_HASH_KAT_STRLEN(VE_HASH_KAT_STR) != 19 ||
	    strlen(vh_SHA256) != 64 || strlen(vh_SHA384) != 96)
		return 3;
	return 0;
}
