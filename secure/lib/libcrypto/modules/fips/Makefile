# SPDX-License-Identifier: BSD-2-Clause
# Self-contained provider: never link this module against libcrypto.
LCRYPTO_SRC= ${SRCTOP}/crypto/openssl
SHLIB_NAME= fips.so
LIBADD= pthread
CFLAGS+= -I${LCRYPTO_SRC}/crypto -DFIPS_MODULE -DOPENSSL_PIC
CFLAGS+= -include ${.CURDIR}/fips_build.h
CFLAGS+= -ffunction-sections -fdata-sections
LDFLAGS+= -Wl,--version-script=${.CURDIR}/fips.map -Wl,-z,defs
LDFLAGS+= -Wl,-Bsymbolic -Wl,--gc-sections
.include <bsd.endian.mk>
.if ${TARGET_ENDIANNESS} == 1234
CFLAGS+= -DL_ENDIAN
.else
CFLAGS+= -DB_ENDIAN
.endif
.include "Makefile.sources"
.include <bsd.lib.mk>
