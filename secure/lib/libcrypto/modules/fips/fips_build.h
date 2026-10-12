#ifndef FIVEBSD_FIPS_BUILD_H
#define FIVEBSD_FIPS_BUILD_H
/* This is a 5BSD integration build, not a validated cryptographic module. */
#include <openssl/opensslconf.h>
#include <openssl/fipskey.h>
#undef OPENSSL_NO_FIPS_POST
#undef OPENSSL_NO_FIPS_SECURITYCHECKS
#ifndef OPENSSL_NO_ASM
#define OPENSSL_NO_ASM
#endif
#undef FIPS_VENDOR
#define FIPS_VENDOR "5BSD FIPS provider (not validated)"
#endif
