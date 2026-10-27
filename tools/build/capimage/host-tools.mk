# SPDX-License-Identifier: BSD-2-Clause
# Native tools for signing a cross-built stage. Invoke from a new /usr/obj
# directory with -f /usr/src/tools/build/capimage/host-tools.mk.
SRCTOP?= /usr/src
CC?= cc
CFLAGS+= -O2 -Wall -Wextra -Werror
CFLAGS+= -I${.OBJDIR} -I${SRCTOP}/lib/libcapimage
CFLAGS+= -I${SRCTOP}/lib/libcapbundle -I${SRCTOP}/lib/libcapsulert
CFLAGS+= -I${SRCTOP}/contrib/libucl/include
# Host ABI headers take precedence; source-only capability definitions remain
# available for parsing manifests. Never use target syscall/libc headers here.
CFLAGS+= -iquote${SRCTOP}/sys -idirafter ${SRCTOP}/sys
.PATH: ${SRCTOP}/usr.sbin/capsign
.PATH: ${SRCTOP}/lib/libcapimage ${SRCTOP}/lib/libcapbundle ${SRCTOP}/lib/libcapsulert
COMMON= capimage.o
BUNDLE= libcapbundle.o libcapbundle_parse.o libcapbundle_verify.o libcapbundle_sign.o claim_parse.o
all: capsign
sys/capimage.h: ${SRCTOP}/sys/sys/capimage.h
	mkdir -p sys
	cp ${.ALLSRC} ${.TARGET}
capsign.o capsign_tree.o ${COMMON} ${BUNDLE}: sys/capimage.h
.c.o:
	${CC} ${CFLAGS} -c ${.IMPSRC} -o ${.TARGET}
capsign: capsign.o capsign_tree.o ${COMMON} ${BUNDLE}
	${CC} ${LDFLAGS} -o ${.TARGET} ${.ALLSRC} -lprivateucl -lmd -lcrypto
.PHONY: all

sys/capimage_elf.h: ${SRCTOP}/sys/sys/capimage_elf.h
	mkdir -p sys
	cp ${.ALLSRC} ${.TARGET}
capimage.o: sys/capimage_elf.h

# Account-generation tools execute on the builder, never from the target stage.
# Its maintained bootstrap recipe supplies source account-directory policy and
# compatibility headers while retaining the host ABI and native libraries.
pwd_mkdb: .PHONY
	mkdir -p ${.OBJDIR}/pwd_mkdb-build
	env -u MAKEOBJDIRPREFIX MAKEOBJDIR=${.OBJDIR}/pwd_mkdb-build \
	    ${MAKE} -C ${SRCTOP}/usr.sbin/pwd_mkdb BOOTSTRAPPING=0 \
	    WITHOUT_TESTS=yes all
	cp ${.OBJDIR}/pwd_mkdb-build/pwd_mkdb ${.OBJDIR}/pwd_mkdb

# Use the maintained bootstrap build for a host-native, cross-ELF hints tool.
# Keep its objects separate from capsign and from target-world objects.
kldxref: .PHONY
	mkdir -p ${.OBJDIR}/kldxref-build
	env -u MAKEOBJDIRPREFIX MAKEOBJDIR=${.OBJDIR}/kldxref-build \
	    ${MAKE} -C ${SRCTOP}/usr.sbin/kldxref BOOTSTRAPPING=0 all
	cp ${.OBJDIR}/kldxref-build/kldxref ${.OBJDIR}/kldxref

# Native static validator shares Capsule's production parser and report.
# Compiler-generated dependencies keep source and transitive headers in sync.
CAPSULE_VALIDATE_SRCS= ${SRCTOP}/usr.sbin/bsd-build/capsule-policy-validate/capsule-policy-validate.c \
    ${SRCTOP}/usr.sbin/capsule/config.c \
    ${SRCTOP}/usr.sbin/capsule/config_report.c \
    ${SRCTOP}/lib/libcapsulert/claim_parse.c
CAPSULE_VALIDATE_OBJS= ${CAPSULE_VALIDATE_SRCS:T:R:S/$/.validator.o/}
.for src in ${CAPSULE_VALIDATE_SRCS}
${src:T:R}.validator.o: ${src}
	${CC} ${CFLAGS} -I${SRCTOP}/usr.sbin/capsule -MD -MP \
	    -MF ${.TARGET:R}.d -c ${src} -o ${.TARGET}
.endfor
bsd-capsule-validate: ${CAPSULE_VALIDATE_OBJS}
	${CC} ${LDFLAGS} -static -o ${.TARGET} ${.ALLSRC} -lprivateucl -lmd
.for dep in ${CAPSULE_VALIDATE_OBJS:R:S/$/.d/}
.sinclude "${dep}"
.endfor
