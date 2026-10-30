# SPDX-License-Identifier: BSD-2-Clause
.include <src.opts.mk>
PROG= loader-manifest-verify
SRCS= main.c
MAN=
# This build-specific tool has exactly the selected generation trust anchors.
.if empty(TRUST_ANCHORS) || ${MK_LOADER_EFI_TRUST_DB:Uyes} != "no"
.error loader-manifest-verify requires explicit compiled-only generation trust
.endif
CFLAGS+= -I${SRCTOP}/lib/libsecureboot -I${SRCTOP}/contrib/bearssl/tools
.include "${SRCTOP}/lib/libbearssl/Makefile.libsa.inc"
.include "${SRCTOP}/lib/libsecureboot/Makefile.inc"
.for directory in ${SRCS:M*/*:H:O:u}
.if ${directory:M/*} != ""
.PATH: ${directory}
.else
.PATH: ${BEARSSL_SRC}/${directory}
.endif
.endfor
SRCS:= ${SRCS:T}
.include <bsd.prog.mk>
XCFLAGS.i31_moddiv+= -Wno-shadow
XCFLAGS.i62_modpow2+= -Wno-cast-align
XCFLAGS.x509_minimal+= -Wno-cast-qual
CFLAGS+= ${XCFLAGS.${.TARGET:T:R}:U}
