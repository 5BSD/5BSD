# SPDX-License-Identifier: BSD-2-Clause
.include <src.opts.mk>
PROG= manifest_trust_probe
SRCS= main.c efi_init.c verify_file.c veopen.c verified_root.c
MAN=
CFLAGS+= -I${SRCTOP}/lib/libsecureboot -I${SRCTOP}/contrib/bearssl/tools -I${.CURDIR} -include ${.CURDIR}/probe_shim.h
# Use the same cryptographic sources as the loader, in a native test process.
.include "${SRCTOP}/lib/libbearssl/Makefile.libsa.inc"
.include "${SRCTOP}/lib/libsecureboot/Makefile.inc"
.PATH: ${SRCTOP}/lib/libsecureboot/efi ${SRCTOP}/stand/common
CFLAGS+= -DLOADER_VERIEXEC -I${SRCTOP}/sys -I${SRCTOP}/stand/common
# bsd.prog.mk uses flat PIE object names; retain the source directories.
.for directory in ${SRCS:M*/*:H:O:u}
.if ${directory:M/*} != ""
.PATH: ${directory}
.else
.PATH: ${BEARSSL_SRC}/${directory}
.endif
.endfor
SRCS:= ${SRCS:T}
.include <bsd.prog.mk>

# Match the per-source warning exceptions in lib/libbearssl/Makefile.
XCFLAGS.i31_moddiv+= -Wno-shadow
XCFLAGS.i62_modpow2+= -Wno-cast-align
XCFLAGS.x509_minimal+= -Wno-cast-qual
CFLAGS+= ${XCFLAGS.${.TARGET:T:R}:U}
